// src/ecdsa/secure_scalar.rs
//! SecureScalar ensures cryptographic scalars are wiped from memory after use.
//! It wraps a 32-byte array and automatically zeroizes on drop.

use k256::{Scalar, FieldBytes};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A wrapper for a 32-byte scalar that zeroizes memory automatically when dropped.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
#[zeroize(drop)]
pub struct SecureScalar(pub [u8; 32]);

impl SecureScalar {
    /// Convert a k256::Scalar into a SecureScalar by copying its canonical bytes.
    pub fn from_scalar(s: &Scalar) -> Self {
        let bytes = s.to_bytes();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(bytes.as_ref());
        Self(arr)
    }

    /// Convert SecureScalar back to a k256::Scalar (for short-term use only).
    pub fn to_scalar(&self) -> Option<Scalar> {
        let fb: FieldBytes = self.0.into();
        Scalar::from_repr(fb)
    }

    /// Returns the inner byte array (read-only) if needed for serialization.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::Scalar;
    use rand_core::OsRng;

    #[test]
    fn test_secure_scalar_roundtrip() {
        let scalar = Scalar::generate_vartime(&mut OsRng);
        let wrapped = SecureScalar::from_scalar(&scalar);
        let recovered = wrapped.to_scalar().unwrap();
        assert_eq!(scalar.to_bytes().as_ref(), recovered.to_bytes().as_ref());
    }
}
