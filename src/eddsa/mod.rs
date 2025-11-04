// src/ecdsa/mod.rs
//! ECDSA module including presignature and rerandomization logic.

mod secure_scalar;
use secure_scalar::SecureScalar;

use k256::Scalar;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// PresignOutput holds the presignature scalars `c` and `beta`.
/// Both are secret values that must be securely destroyed after use.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
#[zeroize(drop)]
pub struct PresignOutput {
    pub c: SecureScalar,
    pub beta: SecureScalar,
}

impl PresignOutput {
    /// Consume this presignature securely and execute a closure with the Scalars.
    /// This enforces single-use semantics and ensures secrets are wiped on drop.
    pub fn with_consumed<F, R>(self, f: F) -> R
    where
        F: FnOnce(Scalar, Scalar) -> R,
    {
        let c_scalar = self.c.to_scalar().expect("invalid scalar c");
        let beta_scalar = self.beta.to_scalar().expect("invalid scalar beta");
        f(c_scalar, beta_scalar)
    }
}

/// RerandomizedPresignOutput holds rerandomized presignature values.
/// These are equally sensitive and must also be wiped automatically.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
#[zeroize(drop)]
pub struct RerandomizedPresignOutput {
    pub c: SecureScalar,
    pub beta: SecureScalar,
}

impl RerandomizedPresignOutput {
    pub fn with_consumed<F, R>(self, f: F) -> R
    where
        F: FnOnce(Scalar, Scalar) -> R,
    {
        let c_scalar = self.c.to_scalar().expect("invalid scalar c");
        let beta_scalar = self.beta.to_scalar().expect("invalid scalar beta");
        f(c_scalar, beta_scalar)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_presign_output_consumes_and_zeroizes() {
        let c = Scalar::generate_vartime(&mut OsRng);
        let beta = Scalar::generate_vartime(&mut OsRng);
        let presign = PresignOutput {
            c: SecureScalar::from_scalar(&c),
            beta: SecureScalar::from_scalar(&beta),
        };

        let result = presign.with_consumed(|c_used, b_used| {
            assert_ne!(c_used, Scalar::ZERO);
            assert_ne!(b_used, Scalar::ZERO);
            99
        });

        assert_eq!(result, 99);
    }

    #[test]
    fn test_rerandomized_presign_output_consumes() {
        let c = Scalar::generate_vartime(&mut OsRng);
        let beta = Scalar::generate_vartime(&mut OsRng);
        let rerand = RerandomizedPresignOutput {
            c: SecureScalar::from_scalar(&c),
            beta: SecureScalar::from_scalar(&beta),
        };

        let result = rerand.with_consumed(|c_used, b_used| {
            assert_ne!(c_used, Scalar::ZERO);
            assert_ne!(b_used, Scalar::ZERO);
            1
        });

        assert_eq!(result, 1);
    }
}
