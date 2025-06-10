use frost_secp256k1::{
    Secp256K1Sha256, Secp256K1ScalarField,
    Field,
    keys::SigningShare,
};

use super::presign::PresignOutput;
use k256::AffinePoint;

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
}

type C = Secp256K1Sha256;
type Scalar = <Secp256K1ScalarField as Field>::Scalar;

/// Represents a signature with extra information, to support different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars. The first scalar is derived from
/// a point on the curve, and because this process is lossy, some other variants
/// of ECDSA also include some extra information in order to recover this point.
///
/// Furthermore, some signature formats may disagree on how precisely to serialize
/// different values as bytes.
///
/// To support these variants, this simply gives you a normal signature, along with the entire
/// first point.
#[derive(Clone)]
pub struct FullSignature {
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}


async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<FullSignature, ProtocolError> {
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

    // // Optionally, normalize s
    // s.conditional_assign(&(-s), s.is_high());
    let sig = FullSignature {
        big_r: presignature.big_r.to_element().to_affine(),
        s: s.to_scalar(),
    };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    }

    Ok(sig)
}