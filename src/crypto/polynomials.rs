use rand_core::CryptoRngCore;
use frost_core::{
    Scalar,
    Group, Field,
    keys::{
        SigningShare,
        CoefficientCommitment,
    },
    Identifier,
};

use super::ciphersuite::Ciphersuite;
use crate::{
    protocol::{Participant, ProtocolError},
    participants::ParticipantMap,
};

/// Creates a polynomial p of degree threshold - 1
/// and sets p(0) = secret
/// if the secret is not given then it is picked at random
pub fn generate_polynomial<C: Ciphersuite>(
    secret: Option<Scalar<C>>,
    degree: usize,
    rng: &mut impl CryptoRngCore,
) -> Vec<Scalar<C>> {
    let poly_size = degree+1;
    let mut coefficients = Vec::with_capacity(poly_size);
    // insert the secret share if exists
    let secret = secret.unwrap_or_else(|| <C::Group as Group>::Field::random(rng));

    coefficients.push(secret);
    for _ in 1..poly_size {
        coefficients.push(<C::Group as Group>::Field::random(rng));
    }
    coefficients
}

/// Returns the constant term (constant term is the first coefficient)
pub fn eval_polynomial_on_zero<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
) -> SigningShare<C> {
    SigningShare::new(coefficients[0])
}

/// Evaluates a polynomial on a certain scalar
/// Evaluate the polynomial with the given coefficients (constant term first)
/// at the point x=identifier using Horner's method.
/// Implements [`polynomial_evaluate`] from the spec.
/// [`polynomial_evaluate`]: https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera
pub fn eval_polynomial<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
    point: Scalar<C>,
) -> SigningShare<C> {
    // creating this dummy id is only to be able to call the from_coefficients function
    let point_id = Identifier::new(point);
    if point_id.is_err(){
        eval_polynomial_on_zero::<C>(coefficients)
    } else{
        let point_id = point_id.unwrap();
        SigningShare::from_coefficients(coefficients, point_id)
    }
}


/// Evaluates a polynomial on the identifier of a participant
pub fn eval_polynomial_on_participant<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
    participant: Participant,
) -> Result<SigningShare<C>, ProtocolError> {
    let id = participant.to_identifier::<C>();
    Ok(SigningShare::from_coefficients(coefficients, id))
}


/// Evaluates multiple polynomials of the same type on the same identifier
pub fn eval_multi_polynomials<C: Ciphersuite, const N: usize>(
    polynomials: [&[Scalar<C>]; N],
    participant: Participant,
) -> Result<[SigningShare<C>; N], ProtocolError> {
    let mut result_vec = Vec::with_capacity(N);

    for poly in polynomials.iter() {
        let eval = eval_polynomial_on_participant::<C>(poly, participant)?;
        result_vec.push(eval);
    }
    Ok(result_vec
        .try_into()
        .expect("Internal error: Vec did not match expected array size")
    )
}

/// Computes the lagrange coefficient lamda_i(x) using a set of coefficients
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    points_set: &Vec<Scalar<C>>,
    i: &Scalar<C>,
    x: Option<&Scalar<C>>,
) -> Result<Scalar<C>, ProtocolError> {
    let mut num = <<C::Group as Group>::Field>::one();
    let mut den = <<C::Group as Group>::Field>::one();

    if points_set.len() <= 1  || !points_set.contains(i){
        // returns error if there is not enough points to interpolate
        // or if i is not in the set of points
        return Err(ProtocolError::InvalidInterpolationArguments)
    }
    if let Some(x) = x {
        for j in points_set.iter() {
            if *i == *j {

                continue;
            }
            num = num * (*x - *j);
            den = den * (*i - *j);
        }
    } else {
        for j in points_set.iter() {
            if *i == *j {
                continue;
            }
            // Both signs inverted just to avoid requiring an extra negation
            num = num * *j;
            den = den * (*j - *i);
        }
    }

    // raises error if the denominator is null, i.e., the set contains duplicates
    let den = <<C::Group as Group>::Field>::invert(&den)
            .map_err(|_| ProtocolError::InvalidInterpolationArguments)?;
    Ok(num * den)
}

/// Computes polynomial interpolation on a specific point
/// using a sequence of sorted elements
pub fn eval_interpolation<C: Ciphersuite>(
    signingshares_map: &ParticipantMap<'_, SigningShare<C>>,
    point: Option<&Scalar<C>>,
)-> Result<SigningShare<C>, ProtocolError>{
    let mut interpolation = <<C::Group as Group>::Field>::zero();
    let identifiers: Vec<Scalar<C>> =  signingshares_map
                    .participants()
                    .iter()
                    .map(|p| p.generic_scalar::<C>())
                    .collect();
    let shares = signingshares_map.into_refs_or_none()
            .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    // Compute the Lagrange coefficients
    for (id, share) in identifiers.iter().zip(shares) {
        // would raise error if not enough shares or identifiers
        let lagrange_coefficient =
            compute_lagrange_coefficient::<C>(&identifiers, id, point)?;

        // Compute y = f(point) via polynomial interpolation of these points of f
        interpolation = interpolation + (lagrange_coefficient * share.to_scalar());
    }

    Ok(SigningShare::new(interpolation))
}

/// Computes polynomial interpolation on the exponent on a specific point
/// using a sequence of sorted elements
pub fn eval_exponent_interpolation<C:Ciphersuite>(
    identifiers: &Vec<Scalar<C>>,
    shares: &Vec<&CoefficientCommitment<C>>,
    point: Option<&Scalar<C>>,
) -> Result<CoefficientCommitment<C>, ProtocolError>{
    let mut interpolation = <C::Group as Group>::identity();
    if identifiers.len() != shares.len(){
        return Err(ProtocolError::InvalidInterpolationArguments)
    };

    // Compute the Lagrange coefficients
    for (id, share) in identifiers.iter().zip(shares) {
        // would raise error if not enough shares or identifiers
        let lagrange_coefficient =
            compute_lagrange_coefficient::<C>(&identifiers, id, point)?;

        // Compute y = g^f(point) via polynomial interpolation of these points of f
        interpolation = interpolation + (share.to_element() * lagrange_coefficient);
    }

    Ok(CoefficientCommitment::new(interpolation))
}

/// Commits to a polynomial returning a sequence of group coefficients
/// Creates a commitment vector of coefficients * G
pub fn commit_polynomial<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
) -> Vec<CoefficientCommitment<C>> {
    // Computes the multiplication of every coefficient of p with the generator G
    coefficients.iter().map(
        |c| CoefficientCommitment::new(<C::Group as Group>::generator() * *c)
    ).collect()
}
