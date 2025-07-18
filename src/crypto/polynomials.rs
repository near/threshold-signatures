use rand_core::CryptoRngCore;
use frost_core::{
    Scalar,
    Group, Field,
    keys::CoefficientCommitment,
    serialization::SerializableScalar,
};

use super::ciphersuite::Ciphersuite;
use crate::{
    protocol::{Participant, ProtocolError},
    participants::ParticipantMap,
};

use std::ops::Add;

pub struct Polynomial<C:Ciphersuite>(Vec<Scalar<C>>);

impl <C: Ciphersuite> Polynomial<C>{
    /// Constructs the polynomial out of scalars
    /// The first scalar (coefficients[0]) is the constant term
    pub fn new(coefficients: Vec<Scalar<C>>) -> Self {
        Polynomial(coefficients)
    }

    pub fn get_coefficients(&self) -> Vec<Scalar<C>> {
        self.0.to_vec()
    }

    /// Outputs the degree of the polynomial
    pub fn degree(&self) -> usize{
        let mut degree = self.0.len();
        // loop as long as the higher terms are zero
        while degree > 0 && self.0[degree - 1] == <C::Group as Group>::Field::zero() {
            degree -= 1;
        }
        if degree == 0 {
            0
        } else {
            degree - 1
        }
    }

    /// Creates a polynomial p of degree threshold - 1
    /// and sets p(0) = secret
    /// if the secret is not given then it is picked at random
    pub fn generate_polynomial(
        secret: Option<Scalar<C>>,
        degree: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let poly_size = degree+1;
        let mut coefficients = Vec::with_capacity(poly_size);
        // insert the secret share if exists
        let secret = secret.unwrap_or_else(|| <C::Group as Group>::Field::random(rng));

        coefficients.push(secret);
        for _ in 1..poly_size {
            coefficients.push(<C::Group as Group>::Field::random(rng));
        }
        Self::new(coefficients)
    }

    /// Returns the constant term
    pub fn eval_on_zero(&self) -> SerializableScalar<C> {
        SerializableScalar(self.0[0])
    }

    /// Evaluates a polynomial on a certain scalar
    /// Evaluate the polynomial with the given coefficients
    /// at the point using Horner's method.
    /// Implements [`polynomial_evaluate`] from the spec:
    /// https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera
    pub fn eval_on_point(
        &self,
        point: Scalar<C>,
    ) -> SerializableScalar<C> {
        if point == <C::Group as Group>::Field::zero(){
            self.eval_on_zero()
        } else {
            let mut value = <<C::Group as Group>::Field>::zero();
            for coeff in self.0.iter().skip(1).rev() {
                value = value + *coeff;
                value = value * point;
            }
            value = value
                + *self.0
                    .first()
                    .expect("coefficients must have at least one element");
            SerializableScalar(value)
        }
    }

    /// Evaluates a polynomial on the identifier of a participant
    pub fn eval_on_participant(
        &self,
        participant: Participant,
    ) -> SerializableScalar<C> {
        let id = participant.scalar::<C>();
        self.eval_on_point(id)
    }

    /// Evaluates multiple polynomials of the same type on the same identifier
    pub fn multi_eval_on_participant<const N: usize>(
        polynomials: [&Self; N],
        participant: Participant,
    ) -> [SerializableScalar<C>; N] {
        let mut result_vec = Vec::with_capacity(N);

        for poly in polynomials.iter() {
            let eval = poly.eval_on_participant(participant);
            result_vec.push(eval);
        }
        match result_vec.try_into(){
            Ok(arr) => arr,
            Err(_) => panic!("Internal error: Vec did not match expected array size"),
        }
    }

    /// Computes polynomial interpolation on a specific point
    /// using a sequence of sorted elements
    pub fn eval_interpolation(
        signingshares_map: &ParticipantMap<'_, SerializableScalar<C>>,
        point: Option<&Scalar<C>>,
    )-> Result<SerializableScalar<C>, ProtocolError>{
        let mut interpolation = <<C::Group as Group>::Field>::zero();
        let identifiers: Vec<Scalar<C>> =  signingshares_map
                        .participants()
                        .iter()
                        .map(|p| p.scalar::<C>())
                        .collect();
        let shares = signingshares_map.into_refs_or_none()
                .ok_or(ProtocolError::InvalidInterpolationArguments)?;

        // Compute the Lagrange coefficients
        for (id, share) in identifiers.iter().zip(shares) {
            // would raise error if not enough shares or identifiers
            let lagrange_coefficient =
                compute_lagrange_coefficient::<C>(&identifiers, id, point)?;

            // Compute y = f(point) via polynomial interpolation of these points of f
            interpolation = interpolation + (lagrange_coefficient.0 * share.0);
        }

        Ok(SerializableScalar(interpolation))
    }

    /// Commits to a polynomial returning a sequence of group coefficients
    /// Creates a commitment vector of coefficients * G
    pub fn commit_polynomial(
        &self,
    ) -> PolynomialCommitment<C> {
        // Computes the multiplication of every coefficient of p with the generator G
        let coef_commitment = self.0.iter().map(
            |c| CoefficientCommitment::new(<C::Group as Group>::generator() * *c)
        ).collect();
        PolynomialCommitment::new(coef_commitment)
    }

    /// Set the constant value of this polynomial to a new scalar
    pub fn set_constant(&mut self, v: Scalar<C>) {
        if self.0.is_empty() {
            self.0.push(v)
        } else {
            self.0[0] = v
        }
    }

    /// Extends the Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_zero(&self) -> Self{
        let mut coeffcommitment = vec![<C::Group as Group>::Field::zero()];
        coeffcommitment.extend(self.get_coefficients());
        Polynomial::new(coeffcommitment)
    }

}



/******************* Polynomial Commitment *******************/
/// Contains the commited coefficients of a polynomial i.e. coeff * G
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(bound = "C: Ciphersuite")]
pub struct PolynomialCommitment<C:Ciphersuite>(Vec<CoefficientCommitment<C>>);

impl <C: Ciphersuite> PolynomialCommitment<C>{
    pub fn new(coefcommitments: Vec<CoefficientCommitment<C>>)-> Self{
        PolynomialCommitment(coefcommitments)
    }

    /// Returns the coefficients of the
    pub fn get_coefficients(&self) -> Vec<CoefficientCommitment<C>> {
        self.0.to_vec()
    }

    /// Outputs the degree of the commited polynomial
    pub fn degree(&self) -> usize{
        let mut degree = self.0.len();
        // loop as long as the higher terms are zero
        while degree > 0 && self.0[degree - 1].value() == <C::Group as Group>::identity() {
            degree -= 1;
        }
        if degree == 0 {
            0
        } else {
            degree - 1
        }
    }

    /// Evaluates the commited polynomial on zero
    /// In other words, outputs the constant term
    pub fn eval_on_zero(&self) -> CoefficientCommitment<C>{
        self.0[0]
    }


    /// Evaluates the commited polynomial at a specific value
    pub fn eval_on_point(&self, point: Scalar<C>) -> CoefficientCommitment<C> {
        let mut out = C::Group::identity();
        for c in self.0.iter().rev() {
            out = out * point + c.value();
        }
        CoefficientCommitment::new(out)
    }

    /// Evaluates the commited polynomial on a participant identifier.
    pub fn eval_on_participant(&self, participant: Participant) -> CoefficientCommitment<C> {
        let id = participant.scalar::<C>();
        self.eval_on_point(id)
    }

    /// Computes polynomial interpolation on the exponent on a spcoefcommitmentscoefcommitmentsecific point
    /// using a sequence of sorted elements
    pub fn eval_exponent_interpolation(
        identifiers: &Vec<Scalar<C>>,
        shares: &Vec<CoefficientCommitment<C>>,
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
            interpolation = interpolation + (share.value() * lagrange_coefficient.0);
        }

        Ok(CoefficientCommitment::new(interpolation))
    }

    /// Extends the Commited Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_identity(&self) -> Self{
        let mut coeffcommitment = vec![CoefficientCommitment::<C>::new(C::Group::identity())];
        coeffcommitment.extend(self.get_coefficients());
        PolynomialCommitment::new(coeffcommitment)
    }


    /// Set the constant value of this polynomial to a new scalar
    pub fn set_constant(&mut self, v: CoefficientCommitment<C>) {
        if self.0.is_empty() {
            self.0.push(v)
        } else {
            self.0[0] = v
        }
    }

}

impl<C: Ciphersuite> Add for &PolynomialCommitment<C> {
    type Output = PolynomialCommitment<C>;

    fn add(self, rhs: Self) -> Self::Output {
        let coefficients = self
            .0
            .iter()
            .zip(rhs.0.iter())
            .map(|(a, b)| CoefficientCommitment::new(a.value() + b.value()))
            .collect();
        PolynomialCommitment::new(coefficients)
    }
}

/// Computes the lagrange coefficient using a set of given points
/// lamda_i(x) = \prod_j (x - x_j)/(x_i - x_j)
/// where j != i
/// If x is None then consider it as 0
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    points_set: &Vec<Scalar<C>>,
    i: &Scalar<C>,
    x: Option<&Scalar<C>>,
) -> Result<SerializableScalar<C>, ProtocolError> {
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
    Ok(SerializableScalar(num * den))
}
