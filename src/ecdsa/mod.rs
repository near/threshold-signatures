//! This module serves as a wrapper for ECDSA scheme.
use elliptic_curve::{
    bigint::{ArrayEncoding, U256, U512},
    sec1::FromEncodedPoint,
    PrimeField,
    ops::{Invert, Reduce},
    point::AffineCoordinates,
};

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

use k256::ProjectivePoint;

use rand_core::CryptoRngCore;

use frost_secp256k1::{
    keys::SigningShare,
    Secp256K1Sha256,
    Secp256K1ScalarField,
    VerifyingKey,
    Field,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use k256::AffinePoint;


#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}

pub type Scalar = <Secp256K1ScalarField as Field>::Scalar;

/// This is the trait that any curve usable in this library must implement.
/// This library does provide a few feature-gated implementations for curves
/// itself, beyond that you'll need to implement this trait yourself.
///
/// The bulk of the trait are the bounds requiring a curve according
/// to RustCrypto's traits.
///
/// Beyond that, we also require that curves have a name, for domain separation,
/// and a way to serialize points with serde.
pub trait PointScalarFunctions {
    /// Serialize a point with serde.
    fn serialize_point<S: Serializer>(
        point: &AffinePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error>;

    /// Deserialize a point with serde.
    fn deserialize_point<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AffinePoint, D::Error>;

    /// transform bytes into scalar
    fn from_bytes_to_scalar(bytes: [u8; 32]) -> Option<Scalar>;

    /// transform bytes into affine point
    fn from_bytes_to_affine(bytes: [u8; 33]) -> Option<ProjectivePoint>;

    /// A function to sample a random scalar, guaranteed to be constant-time.
    /// By this, it's meant that we will make pull a fixed amount of
    /// data from the rng.
    fn sample_scalar_constant_time<R: CryptoRngCore>(r: &mut R) -> Scalar;
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
impl PointScalarFunctions for Secp256K1Sha256{
    fn serialize_point<S: Serializer>(
        point: &AffinePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        point.serialize(serializer)
    }

    fn deserialize_point<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<AffinePoint, D::Error> {
        AffinePoint::deserialize(deserializer)
    }

    fn sample_scalar_constant_time<R: CryptoRngCore>(r: &mut R) -> Scalar {
        let mut data = [0u8; 64];
        r.fill_bytes(&mut data);
        <Scalar as Reduce<U512>>::reduce_bytes(&data.into())
    }

    fn from_bytes_to_scalar(bytes: [u8; 32]) -> Option<Scalar> {
        let bytes = U256::from_be_slice(bytes.as_slice());
        Scalar::from_repr(bytes.to_be_byte_array()).into_option()
    }

    fn from_bytes_to_affine(bytes: [u8; 33]) -> Option<ProjectivePoint> {
        let encoded_point = match k256::EncodedPoint::from_bytes(bytes) {
            Ok(encoded) => encoded,
            Err(_) => return None,
        };
        match Option::<AffinePoint>::from(AffinePoint::from_encoded_point(
            &encoded_point,
        )) {
            Some(point) => Some(ProjectivePoint::from(point)),
            None => None,
        }
    }
}

/// Get the x coordinate of a point, as a scalar
pub(crate) fn x_coordinate(point: &AffinePoint) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&point.x())
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
pub struct FullSignature{
    /// This is the entire first point.
    pub big_r: AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: Scalar,
}

impl FullSignature{
    #[must_use]
    // This verification tests the signature including whether s has been normalized
    pub fn verify(&self, public_key: &AffinePoint, msg_hash: &Scalar) -> bool {
        let r: Scalar = x_coordinate(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (ProjectivePoint::GENERATOR * (*msg_hash * s_inv))
            + (ProjectivePoint::from(*public_key) * (r * s_inv));
        x_coordinate(&reproduced.into()) == r
    }
}


pub mod dkg_ecdsa;
pub mod robust_ecdsa;
pub mod ot_based_ecdsa;
#[cfg(test)]
mod test;