use elliptic_curve::{
    scalar::IsHigh,
    group::Curve,
};

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
    ecdsa::FullSignature,
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

    // Normalize s
    let minus_s = -s;
    let s = if s.is_high().into() {
        minus_s
    }else{
        s
    };

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


#[cfg(test)]
mod test {
    use std::error::Error;

    use ecdsa::Signature;
    use frost_core::keys::{SigningShare, VerifyingShare};
    use k256::{
        ecdsa::signature::Verifier, ecdsa::VerifyingKey, ProjectivePoint, PublicKey, Scalar,
        Secp256k1,
    };
    use rand_core::OsRng;

    use super::*;
    use crate::ecdsa::{
        math::Polynomial,
    };

    use crate::{
        compat::{scalar_hash, x_coordinate},
        protocol::run_protocol
    };

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let threshold = max_malicious + 1;
        let msg = b"hello?";

        // Run 4 times to test randomness
        for _ in 0..4 {
            let fx = Polynomial::<Secp256k1>::random(&mut OsRng, threshold);
            // master secret key
            let x = fx.evaluate_zero();
            // master public key
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();



            let fa = Polynomial::<Secp256k1>::random(&mut OsRng, threshold);
            let fk = Polynomial::<Secp256k1>::random(&mut OsRng, threshold);

            let fd = Polynomial::<Secp256k1>::extend_random(&mut OsRng, 2*max_malicious+1, &Scalar::ZERO);
            let fe = Polynomial::<Secp256k1>::extend_random(&mut OsRng, 2*max_malicious+1, &Scalar::ZERO);

            let k = fk.evaluate_zero();
            let big_r = ProjectivePoint::GENERATOR * k;
            let big_r_x_coordinate = x_coordinate::<Secp256k1>(&big_r.to_affine());

            let big_r = VerifyingShare::new(big_r);

            let w = fa.evaluate_zero()* k;
            let w_invert = w.invert().unwrap();

            let participants = vec![
                                    Participant::from(0u32),
                                    Participant::from(1u32),
                                    Participant::from(2u32),
                                    Participant::from(3u32),
                                    Participant::from(4u32),
                                ];

            #[allow(clippy::type_complexity)]
            let mut protocols: Vec<(
                Participant,
                Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
            )> = Vec::with_capacity(participants.len());
            for p in &participants {
                let p_scalar = p.scalar::<Secp256k1>();
                let h_i = fa.evaluate(&p_scalar) *w_invert;
                let alpha_i = h_i + fd.evaluate(&p_scalar);
                let beta_i = h_i * big_r_x_coordinate * fx.evaluate(&p_scalar) + fe.evaluate(&p_scalar);

                let alpha_i = SigningShare::new(alpha_i);
                let beta_i = SigningShare::new(beta_i);

                let presignature = PresignOutput {
                    big_r,
                    alpha_i,
                    beta_i
                };

                let protocol = sign(
                    &participants,
                    *p,
                    public_key,
                    presignature,
                    scalar_hash(msg),
                )?;
                protocols.push((*p, Box::new(protocol)));
            }

            let result = run_protocol(protocols)?;
            let sig = result[0].1.clone();
            let sig =
                Signature::from_scalars(x_coordinate::<Secp256k1>(&sig.big_r), sig.s)?;
            VerifyingKey::from(&PublicKey::from_affine(public_key).unwrap())
                .verify(&msg[..], &sig)?;
        }
        Ok(())
    }
}
