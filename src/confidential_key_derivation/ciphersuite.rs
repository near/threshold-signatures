use digest::{consts::U48, generic_array::GenericArray};
use elliptic_curve::hash2curve::{hash_to_field, ExpandMsgXmd, FromOkm};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::confidential_key_derivation::{ElementG1, Signature, VerifyingKey};
use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BLS12381SHA256;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BLS12381G2Group;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BLS12381G1Group;

#[derive(Clone, Copy)]
pub struct BLS12381ScalarField;

pub type BLS12381Scalar = blstrs::Scalar;

pub use blstrs;
pub use blstrs::G1Projective;
pub use blstrs::G2Projective;
pub use elliptic_curve::{Field, Group};

impl ScalarSerializationFormat for BLS12381SHA256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl crate::Ciphersuite for BLS12381SHA256 {}

const CONTEXT_STRING: &str = "NEAR-BLS12381-G2-SHA256-v1";

// We are currently not using all the functionality. Therefore,
// I implemented only those that we use.
impl frost_core::Ciphersuite for BLS12381SHA256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = BLS12381G2Group;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    #[allow(unused)]
    fn H1(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H2(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H3(m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        unimplemented!()
    }

    #[allow(unused)]
    fn H4(m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    #[allow(unused)]
    fn H5(_m: &[u8]) -> Self::HashOutput {
        unimplemented!()
    }

    fn HDKG(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m))
    }

    #[allow(unused)]
    fn HID(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        unimplemented!()
    }
}

impl frost_core::Field for BLS12381ScalarField {
    type Scalar = blstrs::Scalar;

    type Serialization = [u8; 32];

    fn zero() -> Self::Scalar {
        blstrs::Scalar::ZERO
    }

    fn one() -> Self::Scalar {
        blstrs::Scalar::ONE
    }

    fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, frost_core::FieldError> {
        scalar
            .invert()
            .into_option()
            .ok_or(frost_core::FieldError::InvalidZeroScalar)
    }

    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
        blstrs::Scalar::random(rng)
    }

    fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
        scalar.to_bytes_le()
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, frost_core::FieldError> {
        blstrs::Scalar::from_bytes_le(buf)
            .into_option()
            .ok_or(frost_core::FieldError::MalformedScalar)
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

// Taken from blstrs, unfortunately not public
const COMPRESSED_SIZE_G2: usize = 96;

impl frost_core::Group for BLS12381G2Group {
    type Field = BLS12381ScalarField;

    type Element = blstrs::G2Projective;

    type Serialization = [u8; COMPRESSED_SIZE_G2];

    fn cofactor() -> <Self::Field as frost_core::Field>::Scalar {
        <Self::Field as frost_core::Field>::Scalar::ONE
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        Self::Element::generator()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
}

// Taken from blstrs, unfortunately not public
const COMPRESSED_SIZE_G1: usize = 48;

impl frost_core::Group for BLS12381G1Group {
    type Field = BLS12381ScalarField;

    type Element = blstrs::G1Projective;

    type Serialization = [u8; COMPRESSED_SIZE_G1];

    fn cofactor() -> <Self::Field as frost_core::Field>::Scalar {
        <Self::Field as frost_core::Field>::Scalar::ONE
    }

    fn identity() -> Self::Element {
        Self::Element::identity()
    }

    fn generator() -> Self::Element {
        Self::Element::generator()
    }

    fn serialize(element: &Self::Element) -> Result<Self::Serialization, frost_core::GroupError> {
        if element.is_identity().into() {
            Err(frost_core::GroupError::InvalidIdentityElement)
        } else {
            Ok(element.to_compressed())
        }
    }

    fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, frost_core::GroupError> {
        Self::Element::from_compressed(buf).into_option().map_or(
            Err(frost_core::GroupError::MalformedElement),
            |point| {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            },
        )
    }
}

pub fn verify_signature(
    verifying_key: &VerifyingKey,
    msg: &[u8],
    signature: &Signature,
) -> Result<(), frost_core::Error<BLS12381SHA256>> {
    let base1 = hash2curve(msg).into();
    let element1 = verifying_key.to_element().into();
    let base2 =
        <<BLS12381SHA256 as frost_core::Ciphersuite>::Group as frost_core::Group>::generator()
            .into();
    let element2 = signature.into();
    if blstrs::pairing(&base1, &element1) == blstrs::pairing(&element2, &base2) {
        Ok(())
    } else {
        Err(frost_core::Error::InvalidSignature)
    }
}

const DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

pub fn hash2curve(bytes: &[u8]) -> ElementG1 {
    G1Projective::hash_to_curve(bytes, DOMAIN, &[])
}

// From https://github.com/ZcashFoundation/frost/blob/3ffc19d8f473d5bc4e07ed41bc884bdb42d6c29f/frost-secp256k1/src/lib.rs#L161
fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> blstrs::Scalar {
    let mut u = [ScalarWrapper(
        <BLS12381ScalarField as frost_core::Field>::zero(),
    )];
    hash_to_field::<ExpandMsgXmd<Sha256>, ScalarWrapper>(&[msg], domain, &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0].0
}

#[derive(Clone, Copy, Default)]
struct ScalarWrapper(blstrs::Scalar);
// WARNING: this is just a PoC, not a correct implementation
// TODO: https://github.com/near/threshold-signatures/issues/105
impl FromOkm for ScalarWrapper {
    type Length = U48;

    fn from_okm(data: &GenericArray<u8, Self::Length>) -> Self {
        #[allow(non_snake_case)]
        let F_2_192 = blstrs::Scalar::from_bytes_be(&[
            0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ])
        .unwrap();

        let mut d0 = GenericArray::default();
        d0[8..].copy_from_slice(&data[0..24]);
        let d0 = blstrs::Scalar::from_bytes_be(&d0.into()).unwrap();

        let mut d1 = GenericArray::default();
        d1[8..].copy_from_slice(&data[24..]);
        let d1 = blstrs::Scalar::from_bytes_be(&d1.into()).unwrap();

        Self(d0 * F_2_192 + d1)
    }
}

#[cfg(test)]
mod tests {
    use blstrs::Scalar;
    use elliptic_curve::Field;
    use elliptic_curve::Group;
    use rand_core::OsRng;

    use crate::confidential_key_derivation::ciphersuite::verify_signature;
    use crate::confidential_key_derivation::VerifyingKey;
    use crate::{
        confidential_key_derivation::{
            ciphersuite::{hash2curve, BLS12381SHA256},
            ElementG2,
        },
        test::check_common_traits_for_type,
    };

    #[test]
    fn check_bls12381_g2_sha256_common_traits() {
        check_common_traits_for_type(&BLS12381SHA256);
    }

    #[test]
    fn test_verify_signature() {
        let x = Scalar::random(OsRng);
        let g2 = ElementG2::generator();
        let g2x = g2 * x;
        let hm = hash2curve(b"hello world");
        let sigma = hm * x;

        assert!(verify_signature(&VerifyingKey::new(g2x), b"hello world", &sigma).is_ok());
    }
}
