use frost_core::{
    keys::CoefficientCommitment, serialization::SerializableScalar, Field, Group, Scalar,
};
use rand_core::CryptoRngCore;

use super::ciphersuite::Ciphersuite;
use crate::protocol::{Participant, ProtocolError};

use std::ops::Add;

use serde::{Deserialize, Deserializer, Serialize};

/// Polynomial structure of non-empty or non-zero coefficiants
/// Represents a polynomial with coefficients in the scalar field of the curve.
pub struct Polynomial<C: Ciphersuite> {
    /// The coefficients of our polynomial,
    /// The 0 term being the constant term of the polynomial
    coefficients: Vec<Scalar<C>>,
}

impl<C: Ciphersuite> Polynomial<C> {
    /// Constructs the polynomial out of scalars
    /// The first scalar (coefficients[0]) is the constant term
    /// The highest degree null coefficients are dropped out
    pub fn new(coefficients: Vec<Scalar<C>>) -> Result<Self, ProtocolError> {
        if coefficients.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // count the number of zero coeffs before spotting the first non-zero
        let count = coefficients
            .iter()
            .rev()
            .take_while(|x| *x == &<C::Group as Group>::Field::zero())
            .count();
        if count == coefficients.len() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // get the degree + 1 of the polynomial
        let last_non_null = coefficients.len() - count;

        Ok(Polynomial {
            coefficients: coefficients[..last_non_null].to_vec(),
        })
    }

    /// Returns the coeficients of the polynomial
    pub fn get_coefficients(&self) -> Vec<Scalar<C>> {
        self.coefficients.to_vec()
    }

    /// Creates a random polynomial p of the given degree
    /// and sets p(0) = secret
    /// if the secret is not given then it is picked at random
    pub fn generate_polynomial(
        secret: Option<Scalar<C>>,
        degree: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Self, ProtocolError> {
        let poly_size = degree + 1;
        let mut coefficients = Vec::with_capacity(poly_size);
        // insert the secret share if exists
        let secret = secret.unwrap_or_else(|| <C::Group as Group>::Field::random(rng));

        coefficients.push(secret);
        for _ in 1..poly_size {
            coefficients.push(<C::Group as Group>::Field::random(rng));
        }
        // fails only if:
        // * polynomial is of degree 0 and the constant term is 0
        // * polynomial degree is the max of usize, and so degree + 1 is 0
        // such cases never happen in a classic (non-malicious) implementations
        Self::new(coefficients)
    }

    /// Returns the constant term
    pub fn eval_at_zero(&self) -> SerializableScalar<C> {
        SerializableScalar(self.coefficients[0])
    }

    /// Evaluates a polynomial at a certain scalar
    /// Evaluate the polynomial with the given coefficients
    /// at the point using Horner's method.
    /// Implements [`polynomial_evaluate`] from the spec:
    /// https://datatracker.ietf.org/doc/html/rfc9591#name-additional-polynomial-opera
    pub fn eval_at_point(&self, point: Scalar<C>) -> SerializableScalar<C> {
        if point == <C::Group as Group>::Field::zero() {
            self.eval_at_zero()
        } else {
            let mut value = <C::Group as Group>::Field::zero();
            for coeff in self.coefficients.iter().skip(1).rev() {
                value = value + *coeff;
                value = value * point;
            }
            value = value + self.coefficients[0];
            SerializableScalar(value)
        }
    }

    /// Evaluates a polynomial at the identifier of a participant
    pub fn eval_at_participant(&self, participant: Participant) -> SerializableScalar<C> {
        let id = participant.scalar::<C>();
        self.eval_at_point(id)
    }

    /// Computes polynomial interpolation at a specific point
    /// using a sequence of sorted elements
    /// Input requirements:
    ///     * identifiers MUST be pairwise distinct and of length greater than 1
    ///     * shares and identifiers must be of same length
    // Returns error if shares' and identifiers' lengths are distinct or less than or equals to 1
    pub fn eval_interpolation(
        identifiers: &[Scalar<C>],
        shares: &[SerializableScalar<C>],
        point: Option<&Scalar<C>>,
    ) -> Result<SerializableScalar<C>, ProtocolError> {
        let mut interpolation = <C::Group as Group>::Field::zero();
        // raise Error if the lengths are not the same
        // or the number of identifiers (<= 1)
        if identifiers.len() != shares.len() || identifiers.len() <= 1 {
            return Err(ProtocolError::InvalidInterpolationArguments);
        }

        // Compute the Lagrange coefficients
        for (id, share) in identifiers.iter().zip(shares) {
            let lagrange_coefficient = compute_lagrange_coefficient::<C>(identifiers, id, point)?;

            // Compute y = f(point) via polynomial interpolation of these points of f
            interpolation = interpolation + (lagrange_coefficient.0 * share.0);
        }

        Ok(SerializableScalar(interpolation))
    }

    /// Commits to a polynomial returning a sequence of group coefficients
    /// Creates a commitment vector of coefficients * G
    pub fn commit_polynomial(&self) -> PolynomialCommitment<C> {
        // Computes the multiplication of every coefficient of p with the generator G
        let coef_commitment = self
            .coefficients
            .iter()
            .map(|c| CoefficientCommitment::new(C::Group::generator() * *c))
            .collect();
        PolynomialCommitment::new(coef_commitment)
            .expect("coefficients must have at least one element set to non-zero")
    }

    /// Set the constant value of this polynomial to a new scalar
    /// Abort if the output polynomial is zero
    pub fn set_nonzero_constant(&mut self, v: Scalar<C>) -> Result<(), ProtocolError> {
        if self.coefficients.len() == 1 && v == <C::Group as Group>::Field::zero() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        self.coefficients[0] = v;
        Ok(())
    }

    /// Extends the Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_zero(&self) -> Self {
        let mut coeffcommitment = vec![<C::Group as Group>::Field::zero()];
        coeffcommitment.extend(self.get_coefficients());
        Polynomial::new(coeffcommitment).expect("coefficients must have at least one element")
    }
}

/******************* Polynomial Commitment *******************/
/// Contains the commited coefficients of a polynomial i.e. coeff * G
#[derive(Clone)]
pub struct PolynomialCommitment<C: Ciphersuite> {
    /// The committed coefficients which are group elements
    /// (elliptic curve points)
    coefficients: Vec<CoefficientCommitment<C>>,
}

impl<C: Ciphersuite> PolynomialCommitment<C> {
    /// Creates a PolynomialCommitment out of a vector of CoefficientCommitment
    /// This function raises Error if the vector is empty or if it is the all identity vector
    pub fn new(coefcommitments: Vec<CoefficientCommitment<C>>) -> Result<Self, ProtocolError> {
        if coefcommitments.is_empty() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // count the number of zero coeffs before spotting the first non-zero
        let count = coefcommitments
            .iter()
            .rev()
            .take_while(|x| x.value() == C::Group::identity())
            .count();
        if count == coefcommitments.len() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        // get the number of non-identity coeffs
        let last_non_id = coefcommitments.len() - count;
        Ok(PolynomialCommitment {
            coefficients: coefcommitments[..last_non_id].to_vec(),
        })
    }

    /// Returns the coefficients of the
    pub fn get_coefficients(&self) -> Vec<CoefficientCommitment<C>> {
        self.coefficients.to_vec()
    }

    /// Outputs the degree of the commited polynomial
    pub fn degree(&self) -> usize {
        self.coefficients.len() - 1
    }

    /// Evaluates the commited polynomial on zero
    /// In other words, outputs the constant term
    pub fn eval_at_zero(&self) -> CoefficientCommitment<C> {
        self.coefficients[0]
    }

    /// Evaluates the commited polynomial at a specific value
    pub fn eval_at_point(&self, point: Scalar<C>) -> CoefficientCommitment<C> {
        let mut out = C::Group::identity();
        for c in self.coefficients.iter().rev() {
            out = out * point + c.value();
        }
        CoefficientCommitment::new(out)
    }

    /// Evaluates the commited polynomial at a participant identifier.
    pub fn eval_at_participant(&self, participant: Participant) -> CoefficientCommitment<C> {
        let id = participant.scalar::<C>();
        self.eval_at_point(id)
    }

    /// Computes polynomial interpolation on the exponent at a specific point
    /// using a sequence of sorted coefficient commitments
    /// Input requirements:
    ///     * identifiers MUST be pairwise distinct and of length greater than 1
    ///     * shares and identifiers must be of same length
    // Returns error if shares' and identifiers' lengths are distinct or less than or equals to 1
    pub fn eval_exponent_interpolation(
        identifiers: &[Scalar<C>],
        shares: &[CoefficientCommitment<C>],
        point: Option<&Scalar<C>>,
    ) -> Result<CoefficientCommitment<C>, ProtocolError> {
        let mut interpolation = C::Group::identity();
        // raise Error if the lengths are not the same
        // or the number of identifiers (<= 1)
        if identifiers.len() != shares.len() || identifiers.len() <= 1 {
            return Err(ProtocolError::InvalidInterpolationArguments);
        };

        // Compute the Lagrange coefficients
        for (id, share) in identifiers.iter().zip(shares) {
            let lagrange_coefficient = compute_lagrange_coefficient::<C>(identifiers, id, point)?;

            // Compute y = g^f(point) via polynomial interpolation of these points of f
            interpolation = interpolation + (share.value() * lagrange_coefficient.0);
        }

        Ok(CoefficientCommitment::new(interpolation))
    }

    /// Extends the Commited Polynomial with an extra value as a constant
    /// Used usually after sending a smaller polynomial to prevent serialization from
    /// failing if the constant term is the identity
    pub fn extend_with_identity(&self) -> Self {
        let mut coeffcommitment = vec![CoefficientCommitment::<C>::new(C::Group::identity())];
        coeffcommitment.extend(self.get_coefficients());
        PolynomialCommitment::new(coeffcommitment)
            .expect("coefficients must have at least one element")
    }

    /// Set the constant value of this polynomial to a new group element
    /// Aborts if the output polynomial is the identity
    pub fn set_non_identity_constant(
        &mut self,
        v: CoefficientCommitment<C>,
    ) -> Result<(), ProtocolError> {
        if self.coefficients.len() == 1 && v.value() == C::Group::identity() {
            return Err(ProtocolError::EmptyOrZeroCoefficients);
        }
        self.coefficients[0] = v;

        Ok(())
    }
}

impl<C: Ciphersuite> Serialize for PolynomialCommitment<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.coefficients.serialize(serializer)
    }
}

// Deserialization enforcing non-empty vecs and non all-identity PolynomialCommitments
impl<'de, C: Ciphersuite> Deserialize<'de> for PolynomialCommitment<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let coefficients = Vec::<CoefficientCommitment<C>>::deserialize(deserializer)?;
        if coefficients.is_empty() {
            Err(serde::de::Error::custom("Polynomial must not be empty"))
        } else {
            // counts the number of successive identity elements on the highest
            // degree coefficients and aborts if the committed polynomial is the identity
            let is_identity = coefficients
                .iter()
                .rev()
                .all(|x| x.value() == C::Group::identity());
            if is_identity {
                return Err(serde::de::Error::custom(
                    "Polynomial must not be the identity",
                ));
            }
            Ok(PolynomialCommitment { coefficients })
        }
    }
}

impl<C: Ciphersuite> Add for &PolynomialCommitment<C> {
    type Output = PolynomialCommitment<C>;

    fn add(self, rhs: Self) -> Self::Output {
        let max_len = self.coefficients.len().max(rhs.coefficients.len());
        let mut coefficients: Vec<CoefficientCommitment<C>> = Vec::with_capacity(max_len);

        // add polynomials even if they have different lengths
        for i in 0..max_len {
            let a = self.coefficients.get(i);
            let b = rhs.coefficients.get(i);

            let sum = match (a, b) {
                (Some(a), Some(b)) => CoefficientCommitment::new(a.value() + b.value()),
                (Some(a), None) => *a,
                (None, Some(b)) => *b,
                (None, None) => unreachable!(),
            };

            coefficients.push(sum);
        }

        PolynomialCommitment::new(coefficients)
            .expect("coefficients must have at least one element")
    }
}

/// Computes the Lagrange coefficient (a.k.a. Lagrange basis polynomial)
/// evaluated at point x.
/// lamda_i(x) = \prod_j (x - x_j)/(x_i - x_j)  where j != i
/// Note: if `x` is None then consider it as 0.
/// Note: `x_j` are elements in `point_set`
/// Note: if `x_i` is not in `point_set` then return an error
/// Note: `point_set` must not have repeating values.
pub fn compute_lagrange_coefficient<C: Ciphersuite>(
    points_set: &[Scalar<C>],
    x_i: &Scalar<C>,
    x: Option<&Scalar<C>>,
) -> Result<SerializableScalar<C>, ProtocolError> {
    let mut num = <C::Group as Group>::Field::one();
    let mut den = <C::Group as Group>::Field::one();

    if points_set.len() <= 1 {
        // returns error if there is not enough points to interpolate
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    let mut contains_i = false;
    if let Some(x) = x {
        for x_j in points_set.iter() {
            if *x_i == *x_j {
                contains_i = true;
                continue;
            }
            num = num * (*x - *x_j);
            den = den * (*x_i - *x_j);
        }
    } else {
        for x_j in points_set.iter() {
            if *x_i == *x_j {
                contains_i = true;
                continue;
            }
            // Both signs inverted just to avoid requiring an extra negation
            num = num * *x_j;
            den = den * (*x_j - *x_i);
        }
    }

    // if i is not in the set of points
    if !contains_i {
        return Err(ProtocolError::InvalidInterpolationArguments);
    }

    // raises error if the denominator is null, i.e., the set contains duplicates
    let den = <C::Group as Group>::Field::invert(&den)
        .map_err(|_| ProtocolError::InvalidInterpolationArguments)?;
    Ok(SerializableScalar(num * den))
}

#[cfg(test)]
mod test {
    use super::*;
    use frost_core::Field;
    use frost_secp256k1::{Secp256K1Group, Secp256K1ScalarField, Secp256K1Sha256};
    use rand_core::OsRng;
    type C = Secp256K1Sha256;
    #[test]
    fn abort_no_polynomial() {
        let poly = Polynomial::<C>::new(vec![]);
        assert!(poly.is_err(), "Polynomial should be raising error");

        let vec = vec![Secp256K1ScalarField::zero(); 10];
        let poly = Polynomial::<C>::new(vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn abort_no_polynomial_commitments() {
        let poly = PolynomialCommitment::<C>::new(vec![]);
        assert!(poly.is_err(), "Polynomial should be raising error");
        let vec = vec![CoefficientCommitment::<C>::new(Secp256K1Group::identity()); 10];
        let poly = PolynomialCommitment::new(vec);
        assert!(poly.is_err(), "Polynomial should be raising error");
    }

    #[test]
    fn test_eval_interpolation(){
        let degree = 5;
        let participants = (0..degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        let ids = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|_| SerializableScalar(Secp256K1ScalarField::random(&mut rand_core::OsRng)) )
            .collect::<Vec<_>>();
        let ref_point = Some(Secp256K1ScalarField::random(&mut rand_core::OsRng));
        let point = ref_point.as_ref();
        assert!(Polynomial::<C>::eval_interpolation(&ids, &shares, point).is_ok());
        assert!(Polynomial::<C>::eval_interpolation(&ids, &shares, None).is_ok());
        assert!(Polynomial::<C>::eval_interpolation(&ids[..1], &shares[..1], None).is_err());
        assert!(Polynomial::<C>::eval_interpolation(&ids[..0], &shares[..0], None).is_err());
        assert!(Polynomial::<C>::eval_interpolation(&ids[..2], &shares, None).is_err());
    }

    #[test]
    fn poly_generate_evaluate_interpolate() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        // evaluate polynomial on 6 different points
        let participants = (0..degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|p| poly.eval_at_participant(*p))
            .collect::<Vec<_>>();

        // interpolate the polynomial using the shares at arbitrary points
        let scalars = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut OsRng);
            // interpolate on this point
            let interpolation =
                Polynomial::<C>::eval_interpolation(&scalars, &shares, Some(&point))
                    .expect("Interpolation has the correct inputs");
            // evaluate the polynomial on the point
            let evaluation = poly.eval_at_point(point);

            // verify that the interpolated points match the polynomial evaluation
            assert_eq!(interpolation.0, evaluation.0);
        }
    }

    #[test]
    fn com_generate_evaluate_interpolate() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial();
        // evaluate polynomial on 6 different points
        let participants = (0..degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();

        let shares = participants
            .iter()
            .map(|p| compoly.eval_at_participant(*p))
            .collect::<Vec<_>>();

        // interpolate the polynomial using the shares at arbitrary points
        let scalars = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        for _ in 0..100 {
            // create arbitrary point
            let point = Secp256K1ScalarField::random(&mut OsRng);
            // interpolate on this point
            let interpolation = PolynomialCommitment::<C>::eval_exponent_interpolation(
                &scalars,
                &shares,
                Some(&point),
            )
            .expect("Interpolation has the correct inputs");
            // evaluate the polynomial on the point
            let evaluation = compoly.eval_at_point(point);

            // verify that the interpolated points match the polynomial evaluation
            assert_eq!(interpolation.value(), evaluation.value());
        }
    }

    #[test]
    fn add_polynomial_commitments() {
        let degree = 5;
        // generate polynomial of degree 5
        let poly = Polynomial::<C>::generate_polynomial(None, degree, &mut OsRng)
            .expect("Generation must not fail with overwhealming probability");

        let compoly = poly.commit_polynomial();
        // add two polynomials of the same height
        let sum = compoly.add(&compoly);

        let coefpoly = compoly.get_coefficients();
        let mut coefsum = sum.get_coefficients();

        assert_eq!(coefpoly.len(), coefsum.len());

        // I need the scalar 2
        // the easiest way to do so is to create a participant with identity 1
        // transforming the identity into scalar would add +1
        let two = Participant::from(1u32).scalar::<C>();
        for (c, two_c) in coefpoly.iter().zip(&coefsum) {
            assert_eq!(c.value() * two, two_c.value())
        }

        coefsum.extend(&coefsum.clone());
        let extend_sum_compoly =
            PolynomialCommitment::new(coefsum).expect("We have proper coefficients");
        // add two polynomials of different heights
        let ext_sum_left = extend_sum_compoly.add(&compoly).get_coefficients();
        let ext_sum_right = compoly.add(&extend_sum_compoly).get_coefficients();
        for (c_left, c_right) in ext_sum_left.iter().zip(ext_sum_right) {
            assert_eq!(c_left.value(), c_right.value());
        }

        let three = Participant::from(2u32).scalar::<C>();
        for i in 0..ext_sum_left.len() {
            let c = ext_sum_left[i].value();
            if i < ext_sum_left.len() / 2 {
                assert_eq!(c, coefpoly[i].value() * three);
            } else {
                let index = i - ext_sum_left.len() / 2;
                assert_eq!(c, coefpoly[index].value() * two);
            }
        }
    }
}
