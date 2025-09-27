//! Threshold-cryptography parameter validation.
//!
//! Provides a safe API to validate the number of faulty nodes (`f`) for a given number of
//! Participants (`N`) and derive the canonical threshold (`t`) for different cryptography schemes.
//!
//! # Parameters
//!
//! - **`N`**: Total participants.
//! - **`f`**: Maximum assumed faulty participants.
//! - **`t` (threshold)**: Minimum participants required to generate a signature, derived from `N` and `f`.
//!
//! # Usage
//! ```
//! use threshold_signatures::threshold::{Scheme, validate_and_derive_threshold};
//!
//! // DKG: t = f + 1, requires f <= floor(N/3)
//! let n = 7;
//! let f = 2;
//! let threshold = validate_and_derive_threshold(Scheme::Dkg, n, f).unwrap();
//! assert_eq!(threshold, 3); // t = f + 1
//!
//! // OtBasedEcdsa: t = f + 1, no additional requirements
//! let threshold_ot_based = validate_and_derive_threshold(Scheme::OtBasedEcdsa, n, f).unwrap();
//! assert_eq!(threshold_ot_based, 3); // t = f + 1
//!
//! // Robust ECDSA: t = f, requires 2f + 1 <= N
//! let threshold_robust = validate_and_derive_threshold(Scheme::RobustEcdsa, n, f).unwrap();
//! assert_eq!(threshold_robust, 2); // t = f
//!
//! // Invalid DKG: f too large
//! assert!(validate_and_derive_threshold(Scheme::Dkg, 7, 3).is_err());
//! ```
use thiserror::Error;

/// Supported cryptographic schemes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Scheme {
    /// Distributed Key Generation
    Dkg,
    /// OT-based ECDSA
    OtBasedEcdsa,
    /// Robust ECDSA
    RobustEcdsa,
}

/// Errors returned during threshold validation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ValidationError {
    /// The number of participants `N` must be at least 1.
    #[error("N must be >= 1")]
    NTooSmall,
    /// The number of faulty participants `f` must be less than `N`.
    #[error("f must be < N")]
    FNotLessThanN,
    /// For DKG, `f` must satisfy `f <= floor(N/3)`.
    #[error("f must satisfy f <= floor(N/3) for DKG")]
    FTooLargeForDkg,
    /// For Robust ECDSA, there must be enough participants to guarantee security (`2f+1 <= N`).
    #[error("insufficient participants for robust ecdsa (need 2f+1 <= N)")]
    InsufficientForRobust,
    /// The derived threshold must not be zero.
    #[error("threshold cannot be zero")]
    ThresholdIsZero,
    /// An arithmetic operation resulted in an overflow.
    #[error("overflow/invalid arithmetic")]
    ArithmeticError,
}

/// Parameter validation and canonical threshold derivation for multi-party signature schemes.
///
/// - **`n`**: Total number of participants.
/// - **`f`**: Maximum number of tolerated faulty or malicious participants.
/// - **`threshold (t`)**: Minimum number of participants required to generate a signature, derived from `n` and `f`.
///
/// Returns valid threshold value or ValidationError
pub fn validate_and_derive_threshold(
    scheme: Scheme,
    n: usize,
    f: usize,
) -> Result<usize, ValidationError> {
    if n == 0 {
        return Err(ValidationError::NTooSmall);
    }
    if f >= n {
        return Err(ValidationError::FNotLessThanN);
    }

    let threshold = match scheme {
        Scheme::Dkg => {
            // require f <= floor(n/3) which is equivalent to 3f <= n
            if f.checked_mul(3).ok_or(ValidationError::ArithmeticError)? > n {
                return Err(ValidationError::FTooLargeForDkg);
            }
            f.checked_add(1).ok_or(ValidationError::ArithmeticError)?
        }
        Scheme::OtBasedEcdsa => f.checked_add(1).ok_or(ValidationError::ArithmeticError)?,
        Scheme::RobustEcdsa => {
            // threshold = f, require 2f+1 <= n
            let two_f_plus_one = f
                .checked_mul(2)
                .and_then(|v| v.checked_add(1))
                .ok_or(ValidationError::ArithmeticError)?;
            if two_f_plus_one > n {
                return Err(ValidationError::InsufficientForRobust);
            }
            f
        }
    };

    if threshold == 0 {
        return Err(ValidationError::ThresholdIsZero);
    }

    Ok(threshold)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dkg_success() {
        // n=7, f=2 -> threshold=3. 3*2 <= 7 is true.
        assert_eq!(validate_and_derive_threshold(Scheme::Dkg, 7, 2), Ok(3));

        // Minimal valid DKG: n=1, f=0 -> t=f+1=1
        assert_eq!(validate_and_derive_threshold(Scheme::Dkg, 1, 0), Ok(1));
    }

    #[test]
    fn dkg_failure_f_too_large() {
        // n=7, f=3 -> 3*3 > 7, which is invalid for DKG.
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 7, 3),
            Err(ValidationError::FTooLargeForDkg)
        );
    }

    #[test]
    fn dkg_failure_n_too_small() {
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 0, 0),
            Err(ValidationError::NTooSmall)
        );
    }

    #[test]
    fn dkg_failure_f_not_less_than_n() {
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 3, 3),
            Err(ValidationError::FNotLessThanN)
        );
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 3, 4),
            Err(ValidationError::FNotLessThanN)
        );
    }

    #[test]
    fn ot_based_ecdsa_success() {
        // n=7, f=2 -> threshold=3.
        assert_eq!(
            validate_and_derive_threshold(Scheme::OtBasedEcdsa, 7, 2),
            Ok(3)
        );

        // Maximal f: n=5, f=4 -> t=f+1=5
        assert_eq!(
            validate_and_derive_threshold(Scheme::OtBasedEcdsa, 5, 4),
            Ok(5)
        );
    }

    #[test]
    fn threshold_zero_is_invalid() {
        // For RobustEcdsa, if f=0, the threshold becomes 0, which is invalid.
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 2, 0),
            Err(ValidationError::ThresholdIsZero)
        );
    }

    #[test]
    fn aritometic_overflow() {
        // Test overflow for 2*f + 1 in RobustECDSA
        let f_robust = usize::MAX / 2 + 1;
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, usize::MAX, f_robust),
            Err(ValidationError::ArithmeticError)
        );

        // Test overflow for 3*f in DKG
        let f_dkg = usize::MAX / 3 + 1;
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, usize::MAX, f_dkg),
            Err(ValidationError::ArithmeticError)
        );

        // Overflow for f+1 in OtBasedEcdsa is not reachable because it requires
        // f = usize::MAX, which would fail the `f < n` check.
        let f_add = usize::MAX;
        assert_eq!(
            validate_and_derive_threshold(Scheme::OtBasedEcdsa, usize::MAX, f_add),
            Err(ValidationError::FNotLessThanN)
        );
    }

    #[test]
    fn robust_ecdsa_edge_minimal() {
        // n=3, f=1 is the smallest valid configuration for RobustEcdsa where f > 0.
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 3, 1),
            Ok(1)
        );
    }

    #[test]
    fn ot_based_ecdsa_edge_max_f() {
        // Test that f can be n-1 for OtBasedEcdsa, as it has no upper bound on f relative to n.
        let n = 5;
        let f = n - 1;
        assert_eq!(
            validate_and_derive_threshold(Scheme::OtBasedEcdsa, n, f),
            Ok(n)
        );
    }

    #[test]
    fn robust_ecdsa_basic() {
        // Minimal valid: n=3, f=1 -> t=f=1
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 3, 1),
            Ok(1)
        );
        // Typical: n=7, f=2 -> t=f=2
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 7, 2),
            Ok(2)
        );
        // Insufficient participants: n=4, f=2 -> invalid
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 4, 2),
            Err(ValidationError::InsufficientForRobust)
        );
        // Threshold zero: n=2, f=0 -> invalid
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 2, 0),
            Err(ValidationError::ThresholdIsZero)
        );
    }

    #[test]
    fn invalid_inputs() {
        // n=0 -> invalid
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 0, 0),
            Err(ValidationError::NTooSmall)
        );
        // f >= n -> invalid
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, 3, 3),
            Err(ValidationError::FNotLessThanN)
        );
        assert_eq!(
            validate_and_derive_threshold(Scheme::OtBasedEcdsa, 3, 4),
            Err(ValidationError::FNotLessThanN)
        );
    }

    #[test]
    fn cross_scheme_consistency() {
        use Scheme::*;
        let schemes = [Dkg, OtBasedEcdsa, RobustEcdsa];

        // Test cases include minimal, typical, and larger n/f values.
        let test_cases = [(1, 0), (3, 1), (5, 2), (7, 2), (10, 3)];

        for &scheme in &schemes {
            for &(n, f) in &test_cases {
                let result = validate_and_derive_threshold(scheme, n, f);
                match scheme {
                    Dkg => {
                        if f * 3 <= n && n > 0 && f < n {
                            assert_eq!(result.unwrap(), f + 1);
                        } else {
                            assert!(result.is_err());
                        }
                    }
                    OtBasedEcdsa => {
                        if n > 0 && f < n {
                            assert_eq!(result.unwrap(), f + 1);
                        } else {
                            assert!(result.is_err());
                        }
                    }
                    RobustEcdsa => {
                        if f == 0 {
                            // Threshold zero is invalid
                            assert_eq!(result, Err(ValidationError::ThresholdIsZero));
                        } else if 2 * f < n && n > 0 && f < n {
                            assert_eq!(result.unwrap(), f);
                        } else {
                            assert!(result.is_err());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn dkg_floor_boundary_cases() {
        // N divisible by 3
        let n = 6;
        let f_valid = n / 3; // 2
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, n, f_valid),
            Ok(f_valid + 1)
        );
        let f_invalid = f_valid + 1; // 3
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, n, f_invalid),
            Err(ValidationError::FTooLargeForDkg)
        );

        // N not divisible by 3
        let n = 7;
        let f_valid = n / 3; // 2
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, n, f_valid),
            Ok(f_valid + 1)
        );
        let f_invalid = f_valid + 1; // 3
        assert_eq!(
            validate_and_derive_threshold(Scheme::Dkg, n, f_invalid),
            Err(ValidationError::FTooLargeForDkg)
        );
    }

    #[test]
    fn robust_ecdsa_small_n_f() {
        // Minimal participants
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 1, 0),
            Err(ValidationError::ThresholdIsZero)
        );
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, 2, 1),
            Err(ValidationError::InsufficientForRobust)
        );
    }

    #[test]
    fn robust_ecdsa_max_f() {
        // Last valid f: 2f+1 <= n
        let n = 7;
        let f = (n - 1) / 2; // f=3 -> 2*3+1=7 valid
        assert_eq!(
            validate_and_derive_threshold(Scheme::RobustEcdsa, n, f),
            Ok(f)
        );
    }
}
