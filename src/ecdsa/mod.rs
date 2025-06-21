//! This module serves as a wrapper for ECDSA scheme.
use elliptic_curve::{ops::Invert, Field, Group};

use crate::compat::{CSCurve, x_coordinate};

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_secp256k1::{
    keys::SigningShare,
    Secp256K1Sha256,
    VerifyingKey,
};

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, Eq, PartialEq)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}


/// Represents a signature that supports different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars.
/// The first is derived from using the x-coordinate of an elliptic curve point (big_r),
/// and the second is computed using the typical ecdsa signing equation.
/// Deriving the x-coordination implies losing information about big_r, some variants
/// may thus include an extra information to recover this point.
///
/// This signature supports all variants by containing big_r entirely
#[derive(Clone)]
pub struct FullSignature<C: CSCurve> {
    /// This is the entire first point.
    pub big_r: C::AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: C::Scalar,
}

impl<C: CSCurve> FullSignature<C> {
    #[must_use]
    pub fn verify(&self, public_key: &C::AffinePoint, msg_hash: &C::Scalar) -> bool {
        let r: C::Scalar = x_coordinate::<C>(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (C::ProjectivePoint::generator() * (*msg_hash * s_inv))
            + (C::ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate::<C>(&reproduced.into()) == r
    }
}


impl From<crate::generic_dkg::KeygenOutput<Secp256K1Sha256>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Secp256K1Sha256>) -> Self {
        Self {
            private_share: value.private_share,
            public_key: value.public_key,
        }
    }
}

impl ScalarSerializationFormat for Secp256K1Sha256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::BigEndian
    }
}

impl Ciphersuite for Secp256K1Sha256 {}

pub mod dkg_ecdsa;
pub mod math;
#[cfg(test)]
mod test;

pub mod robust_ecdsa;
// pub mod ot_based_ecdsa;