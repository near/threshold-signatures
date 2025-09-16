use elliptic_curve::scalar::IsHigh;

use frost_core::serialization::SerializableScalar;
use subtle::ConditionallySelectable;

use crate::{
    ecdsa::{
        robust_ecdsa::RerandomizedPresignOutput, AffinePoint, Polynomial, Scalar, Secp256K1Sha256,
        Signature,
    },
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        errors::{InitializationError, ProtocolError},
        internal::{make_protocol, Comms, SharedChannel},
        Participant, Protocol,
    },
};
type C = Secp256K1Sha256;

pub fn sign(
    participants: &[Participant],
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
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

async fn do_sign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    public_key: AffinePoint,
    presignature: RerandomizedPresignOutput,
    msg_hash: Scalar,
) -> Result<Signature, ProtocolError> {
    let s_me = msg_hash * presignature.alpha + presignature.beta;
    let s_me = SerializableScalar(s_me);

    let wait_round = chan.next_waitpoint();
    chan.send_many(wait_round, &s_me)?;

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

    // interpolate s
    let mut s = Polynomial::eval_interpolation(&identifiers, &sshares, None)?.0;
    // raise error if s is zero
    if s == <<<C as frost_core::Ciphersuite>::Group as frost_core::Group>::Field as frost_core::Field>::zero(){
        return Err(ProtocolError::AssertionFailed(
            "signature part s cannot be zero".to_string(),
        ))
    }
    // Normalize s
    s.conditional_assign(&(-s), s.is_high());

    let big_r = presignature.big_r;
    let sig = Signature { big_r, s };

    if !sig.verify(&public_key, &msg_hash) {
        return Err(ProtocolError::AssertionFailed(
            "signature failed to verify".to_string(),
        ));
    };

    Ok(sig)
}

#[cfg(test)]
mod test {
    use std::error::Error;

    use k256::{ecdsa::signature::Verifier, ecdsa::VerifyingKey, PublicKey};
    use rand_core::OsRng;

    use super::*;
    use crate::ecdsa::{
        robust_ecdsa::test::{run_sign_with_rerandomization, run_sign_without_rerandomization},
        robust_ecdsa::PresignOutput,
        x_coordinate, Field, ProjectivePoint, Secp256K1ScalarField,
    };
    use crate::test::generate_participants;

    type PresigSimulationOutput = (
        Scalar,
        Polynomial,
        Polynomial,
        Polynomial,
        Polynomial,
        ProjectivePoint,
        Scalar,
    );

    fn simulate_presignature(
        max_malicious: usize,
    ) -> Result<PresigSimulationOutput, Box<dyn Error>> {
        // the presignatures scheme requires the generation of 5 different polynomials
        // (fk, fa, fb, fd, fe)
        // here we do not need fb as it is only used to mask some values before sending
        // them to other participants then adding them all together to generate w
        // this sum would annihilate all the fb shares which make them useless in our case
        let fk = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        let fa = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        let fd = Polynomial::generate_polynomial(
            Some(Secp256K1ScalarField::zero()),
            2 * max_malicious,
            &mut OsRng,
        )?;
        let fe = Polynomial::generate_polynomial(
            Some(Secp256K1ScalarField::zero()),
            2 * max_malicious,
            &mut OsRng,
        )?;

        // computing k, R, Rx
        let k = fk.eval_at_zero()?.0;
        let big_r = ProjectivePoint::GENERATOR * k;
        let big_r_x_coordinate = x_coordinate(&big_r.to_affine());

        // compute the master scalar w = a * k
        let w = fa.eval_at_zero()?.0 * k;
        let w_invert = w.invert().unwrap();

        Ok((w_invert, fa, fd, fe, fk, big_r, big_r_x_coordinate))
    }

    #[test]
    fn test_sign_given_presignature() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        // Manually compute presignatures then deliver them to the signing function
        let fx = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        // master secret key
        let x = fx.eval_at_zero()?.0;
        // master public key
        let public_key = ProjectivePoint::GENERATOR * x;

        let (w_invert, fa, fd, fe, fk, big_r, big_r_x_coordinate) =
            simulate_presignature(max_malicious)?;
        let participants = generate_participants(5);

        let mut participants_presign = Vec::new();
        // Simulate the each participant's presignature
        for p in &participants {
            let h_i = w_invert * fa.eval_at_participant(*p)?.0;
            let alpha = h_i + fd.eval_at_participant(*p)?.0;
            let beta = h_i * big_r_x_coordinate * fx.eval_at_participant(*p)?.0
                + fe.eval_at_participant(*p)?.0;
            let k = fk.eval_at_participant(*p)?.0;
            // build the presignature
            let presignature = PresignOutput {
                big_r: big_r.to_affine(),
                alpha,
                beta,
                k,
            };
            participants_presign.push((*p, presignature));
        }

        let result = run_sign_without_rerandomization(participants_presign, public_key, msg)?;
        let sig = result[0].1.clone();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)?;
        Ok(())
    }

    #[test]
    fn test_sign_given_presignature_with_rerandomization() -> Result<(), Box<dyn Error>> {
        let max_malicious = 2;
        let msg = b"Hello? Is it me you're looking for?";

        // Manually compute presignatures then deliver them to the signing function
        let fx = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng)?;
        // master secret key
        let x = fx.eval_at_zero()?.0;
        // master public key
        let public_key = frost_core::VerifyingKey::new(ProjectivePoint::GENERATOR * x);

        let (w_invert, fa, fd, fe, fk, big_r, big_r_x_coordinate) =
            simulate_presignature(max_malicious)?;
        let participants = generate_participants(5);

        let mut participants_presign = Vec::new();
        // Simulate the each participant's presignature
        for p in &participants {
            let h_i = w_invert * fa.eval_at_participant(*p)?.0;
            let alpha = h_i + fd.eval_at_participant(*p)?.0;
            let beta = h_i * big_r_x_coordinate * fx.eval_at_participant(*p)?.0
                + fe.eval_at_participant(*p)?.0;
            let k = fk.eval_at_participant(*p)?.0;
            // build the presignature
            let presignature = PresignOutput {
                big_r: big_r.to_affine(),
                alpha,
                beta,
                k,
            };
            participants_presign.push((*p, presignature));
        }

        let (tweak, result) =
            run_sign_with_rerandomization(participants_presign, public_key.to_element(), msg)?;
        let sig = result[0].1.clone();
        let sig = ecdsa::Signature::from_scalars(x_coordinate(&sig.big_r), sig.s)?;
        // derive the public key
        let public_key = tweak.derive_verifying_key(&public_key).to_element();

        // verify the correctness of the generated signature
        VerifyingKey::from(&PublicKey::from_affine(public_key.to_affine()).unwrap())
            .verify(&msg[..], &sig)?;
        Ok(())
    }
}
