use rand_core::CryptoRngCore;

#[cfg(test)]
use crate::protocol::ProtocolError;
use crate::{
    ecdsa::{
        ProjectivePoint,
        Secp256K1Sha256,
        Secp256K1ScalarField,
        Field,
    },
    protocol::Participant,
    crypto::polynomials::{
        generate_polynomial,
        evaluate_polynomial_on_participant,
    },
};
use super::{TriplePub, TripleShare};
type C = Secp256K1Sha256;

/// Create a new triple from scratch.
///
/// This can be used to generate a triple if you then trust the person running
/// this code to forget about the values they generated.
/// We prevent users from using it in non-testing env and attribute it to #[cfg(test)]
#[cfg(test)]
pub fn deal(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    threshold: usize,
) -> Result<(TriplePub, Vec<TripleShare>), ProtocolError> {
    let a = Secp256K1ScalarField::random(&mut *rng);
    let b = Secp256K1ScalarField::random(&mut *rng);
    let c = a * b;

    let f_a = generate_polynomial::<C>(Some(a), threshold-1, rng);
    let f_b = generate_polynomial::<C>(Some(b), threshold-1, rng);
    let f_c = generate_polynomial::<C>(Some(c), threshold-1, rng);

    let mut shares = Vec::with_capacity(participants.len());
    let mut participants_owned = Vec::with_capacity(participants.len());

    for p in participants {
        participants_owned.push(*p);
        shares.push(TripleShare {
            a: evaluate_polynomial_on_participant::<C>(&f_a, *p)?.to_scalar(),
            b: evaluate_polynomial_on_participant::<C>(&f_b, *p)?.to_scalar(),
            c: evaluate_polynomial_on_participant::<C>(&f_c, *p)?.to_scalar(),
        });
    }

    let triple_pub = TriplePub {
        big_a: (ProjectivePoint::GENERATOR * a).into(),
        big_b: (ProjectivePoint::GENERATOR * b).into(),
        big_c: (ProjectivePoint::GENERATOR * c).into(),
        participants: participants_owned,
        threshold,
    };
    Ok((triple_pub, shares))
}
