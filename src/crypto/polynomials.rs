// +++++++++ Polynomial manipulations +++++++++
use frost_core::{Scalar,Group, Field};
use rand_core::OsRng;

use super::ciphersuite::Ciphersuite;

/// Creates a polynomial p of degree threshold - 1
/// and sets p(0) = secret
pub fn generate_secret_polynomial<C: Ciphersuite>(
    secret: Scalar<C>,
    threshold: usize,
    rng: &mut OsRng,
) -> Vec<Scalar<C>> {
    let mut coefficients = Vec::with_capacity(threshold);
    // insert the secret share
    coefficients.push(secret);
    for _ in 1..threshold {
        coefficients.push(<C::Group as Group>::Field::random(rng));
    }
    coefficients
}