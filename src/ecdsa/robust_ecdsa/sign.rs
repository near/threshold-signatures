use elliptic_curve::scalar::IsHigh;

use frost_secp256k1::keys::SigningShare;
use subtle::ConditionallySelectable;

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
    ecdsa::{FullSignature, Scalar, AffinePoint},
};
use super::PresignOutput;

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<FullSignature, ProtocolError> {
    let s_me = msg_hash * presignature.alpha_i + presignature.beta_i;
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

    let mut s = eval_interpolation(&s_map, None)?.to_scalar();
    let big_r = presignature.big_r;

    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = FullSignature {
        big_r,
        s,
    };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    };

    Ok(sig)
}

pub fn sign(
    participants: &[Participant],
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<impl Protocol<Output = FullSignature>, InitializationError> {

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
        ecdsa::signature::Verifier, ecdsa::VerifyingKey, PublicKey,
    };
    use rand_core::OsRng;

    use crate::ecdsa::{
        ProjectivePoint,
        Secp256K1Sha256,
        Secp256K1ScalarField,
        Field,
        x_coordinate,
    };
    use super::*;

    use crate::{
        compat::{scalar_hash},
        protocol::run_protocol,
        crypto::polynomials::{
            Polynomial,
            eval_polynomial_on_participant,
            eval_polynomial_on_zero,
        }
    };

    type C = Secp256K1Sha256;
    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let threshold = max_malicious + 1;
        let msg = b"hello?";

        // Run 4 times to test randomness
        for _ in 0..4 {
            let fx = Polynomial::<C>::generate_polynomial(None, threshold-1, &mut OsRng);
            // master secret key
            let x = eval_polynomial_on_zero::<C>(&fx).to_scalar();
            // master public key
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();

            let fa = Polynomial::<C>::generate_polynomial(None, threshold-1, &mut OsRng);
            let fk = Polynomial::<C>::generate_polynomial(None, threshold-1, &mut OsRng);

            let fd = Polynomial::<C>::generate_polynomial(Some(Secp256K1ScalarField::zero()), 2*max_malicious, &mut OsRng);
            let fe = Polynomial::<C>::generate_polynomial(Some(Secp256K1ScalarField::zero()), 2*max_malicious, &mut OsRng);

            let k = eval_polynomial_on_zero::<C>(&fk).to_scalar();
            let big_r = ProjectivePoint::GENERATOR * k.clone();
            let big_r_x_coordinate = x_coordinate(&big_r.to_affine());

            let big_r = VerifyingShare::new(big_r);

            let w = eval_polynomial_on_zero::<C>(&fa).to_scalar() * k;
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
                Box<dyn Protocol<Output = FullSignature>>,
            )> = Vec::with_capacity(participants.len());
            for p in &participants {
                let h_i = w_invert
                        * eval_polynomial_on_participant::<C>(&fa, *p).unwrap().to_scalar();
                let alpha_i = h_i
                        + eval_polynomial_on_participant::<C>(&fd, *p).unwrap().to_scalar();
                let beta_i = h_i * big_r_x_coordinate
                        * eval_polynomial_on_participant::<C>(&fx, *p).unwrap().to_scalar()
                        + eval_polynomial_on_participant::<C>(&fe, *p).unwrap().to_scalar();

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
                Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;
            VerifyingKey::from(&PublicKey::from_affine(public_key).unwrap())
                .verify(&msg[..], &sig)?;
        }
        Ok(())
    }
}
