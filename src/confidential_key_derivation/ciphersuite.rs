use digest::{consts::U48, generic_array::GenericArray};
use elliptic_curve::{
    hash2curve::{hash_to_field, ExpandMsgXmd, FromOkm},
    Field, Group,
};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use crate::crypto::ciphersuite::{BytesOrder, ScalarSerializationFormat};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BLS12381G2SHA256;

impl ScalarSerializationFormat for BLS12381G2SHA256 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl crate::Ciphersuite for BLS12381G2SHA256 {}

fn hash_to_scalar(domain: &[&[u8]], msg: &[u8]) -> blstrs::Scalar {
    let mut u = [ScalarWrapper(
        <BLS12381G2ScalarField as frost_core::Field>::zero(),
    )];
    hash_to_field::<ExpandMsgXmd<Sha256>, ScalarWrapper>(&[msg], domain, &mut u)
        .expect("should never return error according to error cases described in ExpandMsgXmd");
    u[0].0
}

const CONTEXT_STRING: &str = "NEAR-BLS12381-G2-SHA256-v1";

impl frost_core::Ciphersuite for BLS12381G2SHA256 {
    const ID: &'static str = CONTEXT_STRING;

    type Group = BLS12381G2Group;

    type HashOutput = [u8; 64];

    type SignatureSerialization = [u8; 64];

    fn H1(_m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        // hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho", m])
        unimplemented!()
    }

    fn H2(_m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        // hash_to_scalar(&[m])
        unimplemented!()
    }

    fn H3(_m: &[u8]) -> <<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar {
        // hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce", m])
        unimplemented!()
    }

    fn H4(_m: &[u8]) -> Self::HashOutput {
        // hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
        unimplemented!()
    }

    fn H5(_m: &[u8]) -> Self::HashOutput {
        // hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
        unimplemented!()
    }

    fn HDKG(
        m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg"], m))
    }

    fn HID(
        _m: &[u8],
    ) -> Option<<<Self::Group as frost_core::Group>::Field as frost_core::Field>::Scalar> {
        // Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"id", m]))
        unimplemented!()
    }
}

#[derive(Clone, Copy)]
pub struct BLS12381G2ScalarField;

impl frost_core::Field for BLS12381G2ScalarField {
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
        match blstrs::Scalar::from_bytes_le(buf).into() {
            Some(s) => Ok(s),
            None => Err(frost_core::FieldError::MalformedScalar),
        }
    }

    fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
        Self::serialize(scalar)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct BLS12381G2Group;

// Taken from blstrs, unfortunately not public
const COMPRESSED_SIZE: usize = 96;

impl frost_core::Group for BLS12381G2Group {
    type Field = BLS12381G2ScalarField;

    type Element = blstrs::G2Projective;

    type Serialization = [u8; COMPRESSED_SIZE];

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
        match Self::Element::from_compressed(buf).into_option() {
            Some(point) => {
                if point.is_identity().into() {
                    Err(frost_core::GroupError::InvalidIdentityElement)
                } else {
                    Ok(point)
                }
            }
            None => Err(frost_core::GroupError::MalformedElement),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ScalarWrapper(blstrs::Scalar);
// WARNING: this is just a PoC, not a correct implementation
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

        ScalarWrapper(d0 * F_2_192 + d1)
    }
}
