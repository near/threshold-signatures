use elliptic_curve::group::Curve;
use frost_secp256k1::{
    Secp256K1ScalarField,
    Field,
    keys::{
        SigningShare,
        VerifyingShare,
    }
};

use super::presign::PresignOutput;
use elliptic_curve::CurveArithmetic;

use crate::{
    crypto::polynomials::eval_interpolation,
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        internal::{make_protocol, Comms, SharedChannel},
        Participant,
        ProtocolError,
        InitializationError,
        Protocol
    },
    // TODO: The following crates need to be done away with
    compat::CSCurve,
    ecdsa::sign::FullSignature,
};

type Scalar = <Secp256K1ScalarField as Field>::Scalar;


/// Transforms a verification key of type Secp256k1SHA256 to CSCurve of cait-sith
fn from_secp256k1sha256_to_cscurve_point<C: CSCurve>(
    vshare: &VerifyingShare,
) -> Result<<C as CurveArithmetic>::AffinePoint, ProtocolError> {
    // serializes into a canonical byte array buf of length 33 bytes using the  affine point representation
    let bytes = vshare
        .serialize()
        .map_err(|_| ProtocolError::PointSerialization)?;

    let bytes: [u8; 33] = bytes.try_into().expect("Slice is not 33 bytes long");
    let point = match C::from_bytes_to_affine(bytes) {
        Some(point) => point,
        _ => return Err(ProtocolError::PointSerialization),
    };
    Ok(point.to_affine())
}

/// Transforms a secret key of type Secp256k1Sha256 to CSCurve of cait-sith
fn from_secp256k1sha256_to_cscurve_scalar<C: CSCurve>(private_share: &SigningShare) -> C::Scalar {
    let bytes = private_share.to_scalar().to_bytes();
    let bytes: [u8; 32] = bytes.try_into().expect("Slice is not 32 bytes long");
    C::from_bytes_to_scalar(bytes).unwrap()
}

async fn do_sign<C: CSCurve>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: C::AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<FullSignature<C>, ProtocolError> {
    let s_me = msg_hash * presignature.alpha_i.to_scalar() + presignature.beta_i.to_scalar();
    let s_me = SigningShare::new(s_me);

    let wait_round = chan.next_waitpoint();
    chan.send_many(wait_round, &s_me);

    let mut seen = ParticipantCounter::new(&participants);
    let mut s_map = ParticipantMap::new(&participants);
    s_map.put(me, s_me);

    seen.put(me);
    while !seen.full() {
        let (from, s_i): (_, SigningShare) = chan.recv(wait_round).await?;
        if !seen.put(from) {
            continue;
        }
        s_map.put(from, s_i);
    }

    let s = eval_interpolation(&s_map, None)?;
    // Only for formatting
    let s = from_secp256k1sha256_to_cscurve_scalar::<C>(&s);
    let big_r = from_secp256k1sha256_to_cscurve_point::<C>(&presignature.big_r)?;
    // TODO:
    // Normalize s
    // s.conditional_assign(&(-s), s.is_high());
    let sig = FullSignature {
        big_r,
        s,
    };

    let msg_hash = from_secp256k1sha256_to_cscurve_scalar::<C>(&SigningShare::new(msg_hash));
    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    };

    Ok(sig)
}


// TODO: try to unify both sign functions in robust ecdsa and in ot_based_ecdsa
pub fn sign<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    public_key: C::AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = FullSignature<C>>, InitializationError> {

    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me){
        return Err(InitializationError::BadParameters("participant list does not contain me".to_string()))
    };

    let ctx = Comms::new();
    let fut = do_sign(
        ctx.shared_channel(),
        participants,
        me,
        public_key,
        presignature,
        msg_hash,
    );
    Ok(make_protocol(ctx, fut))
}
