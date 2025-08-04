use elliptic_curve::scalar::IsHigh;

use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;

use super::PresignOutput;
use crate::{
    ecdsa::{AffinePoint, Signature, Polynomial, Scalar, Secp256K1Sha256},
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        internal::{make_protocol, Comms, SharedChannel},
        InitializationError, Participant, Protocol, ProtocolError,
    },
};
type C = Secp256K1Sha256;

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<Signature, ProtocolError> {
    let s_me = msg_hash * presignature.alpha_i + presignature.beta_i;
    let s_me = SerializableScalar(s_me);

    let wait_round = chan.next_waitpoint();
    chan.send_many(wait_round, &s_me);

    let mut seen = ParticipantCounter::new(&participants);
    let mut s_map = ParticipantMap::new(&participants);
    s_map.put(me, s_me);

    seen.put(me);
    while !seen.full() {
        let (from, s_i): (_, SerializableScalar<C>) = chan.recv(wait_round).await?;
        if !seen.put(from) {
            continue;
        }
        s_map.put(from, s_i);
    }

    let identifiers: Vec<Scalar> = s_map
        .participants()
        .iter()
        .map(|p| p.scalar::<C>())
        .collect();

    let sshares = s_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    let mut s = Polynomial::eval_interpolation(&identifiers, &sshares, None)?.0;
    let big_r = presignature.big_r;

    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let sig = Signature { big_r, s };

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
) -> Result<impl Protocol<Output = Signature>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "participant list does not contain me".to_string(),
        ));
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
    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, PublicKey};
    use rand_core::OsRng;

    use super::*;
    use crate::test::generate_participants;
    use crate::ecdsa::{x_coordinate, Field, ProjectivePoint, Secp256K1ScalarField};

    use crate::{crypto::hash::scalar_hash, protocol::run_protocol};

    #[test]
    fn test_sign() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let threshold = max_malicious + 1;
        let msg = b"hello?";

        for _ in 0..100 {
            let fx = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng).unwrap();
            // master secret key
            let x = fx.eval_on_zero().0;
            // master public key
            let public_key = (ProjectivePoint::GENERATOR * x).to_affine();

            let fa = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng).unwrap();
            let fk = Polynomial::generate_polynomial(None, threshold - 1, &mut OsRng).unwrap();

            let fd = Polynomial::generate_polynomial(
                Some(Secp256K1ScalarField::zero()),
                2 * max_malicious,
                &mut OsRng,
            )
            .unwrap();
            let fe = Polynomial::generate_polynomial(
                Some(Secp256K1ScalarField::zero()),
                2 * max_malicious,
                &mut OsRng,
            )
            .unwrap();

            let k = fk.eval_on_zero().0;
            let big_r = ProjectivePoint::GENERATOR * k;
            let big_r_x_coordinate = x_coordinate(&big_r.to_affine());

            let w = fa.eval_on_zero().0 * k;
            let w_invert = w.invert().unwrap();

            let participants = generate_participants(5);

            #[allow(clippy::type_complexity)]
            let mut protocols: Vec<(
                Participant,
                Box<dyn Protocol<Output = super::Signature>>,
            )> = Vec::with_capacity(participants.len());
            for p in &participants {
                let h_i = w_invert * fa.eval_on_participant(*p).0;
                let alpha_i = h_i + fd.eval_on_participant(*p).0;
                let beta_i = h_i * big_r_x_coordinate * fx.eval_on_participant(*p).0
                    + fe.eval_on_participant(*p).0;

                let presignature = PresignOutput {
                    big_r: big_r.to_affine(),
                    alpha_i,
                    beta_i,
                };

                let protocol = sign(
                    &participants,
                    *p,
                    public_key,
                    presignature,
                    scalar_hash::<C>(msg),
                )?;
                protocols.push((*p, Box::new(protocol)));
            }

            let result = run_protocol(protocols)?;
            let sig = result[0].1.clone();
            let sig = Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;
            VerifyingKey::from(&PublicKey::from_affine(public_key).unwrap())
                .verify(&msg[..], &sig)?;
        }
        Ok(())
    }
}
