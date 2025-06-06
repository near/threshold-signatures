use rand_core::OsRng;
use frost_core::{
    Scalar,
    Group,
    Field,
    keys::SigningShare,
};

use super::ciphersuite::Ciphersuite;
use crate::protocol::{Participant, ProtocolError};

/// Creates a polynomial p of degree threshold - 1
/// and sets p(0) = secret
pub fn generate_secret_polynomial<C: Ciphersuite>(
    secret: Scalar<C>,
    degree: usize,
    rng: &mut OsRng,
) -> Vec<Scalar<C>> {
    let poly_size = degree+1;
    let mut coefficients = Vec::with_capacity(poly_size);
    // insert the secret share
    coefficients.push(secret);
    for _ in 1..poly_size {
        coefficients.push(<C::Group as Group>::Field::random(rng));
    }
    coefficients
}

/// Evaluates a polynomial on the identifier of a participant
/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
/// Implements [`polynomial_evaluate`] from the spec.
/// [`polynomial_evaluate`]: https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera
pub fn evaluate_polynomial<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
    participant: Participant,
) -> Result<SigningShare<C>, ProtocolError> {
    let id = participant.to_identifier::<C>();
    Ok(SigningShare::from_coefficients(coefficients, id))
}


/// Evaluates multiple polynomials of the same type on the same identifier
pub fn evaluate_multi_polynomials<C: Ciphersuite, const N: usize>(
    polynomials: [&[Scalar<C>]; N],
    participant: Participant,
) -> Result<[SigningShare<C>; N], ProtocolError> {
    let mut result_vec = Vec::with_capacity(N);

    for poly in polynomials.iter() {
        let eval = evaluate_polynomial::<C>(poly, participant)?;
        result_vec.push(eval);
    }
    Ok(result_vec
        .try_into()
        .expect("Internal error: Vec did not match expected array size")
    )
}