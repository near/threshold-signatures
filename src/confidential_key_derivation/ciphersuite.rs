use std::sync::LazyLock;

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
        match blstrs::Scalar::from_bytes_le(buf).into() {
            Some(s) => Ok(s),
            None => Err(frost_core::FieldError::MalformedScalar),
        }
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

#[derive(Clone, Copy, Debug, Default)]
struct ScalarWrapper(blstrs::Scalar);

static R: LazyLock<blstrs::Scalar> =
    LazyLock::new(|| blstrs::Scalar::pow(&blstrs::Scalar::from(2), [256]));

const MODULUS: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

impl ScalarWrapper {
    fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        Self::from_u512([
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[0..8]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[8..16]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[16..24]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[24..32]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[32..40]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[40..48]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[48..56]).unwrap()),
            u64::from_le_bytes(<[u8; 8]>::try_from(&bytes[56..64]).unwrap()),
        ])
    }

    fn from_u512(limbs: [u64; 8]) -> Self {
        // We reduce an arbitrary 512-bit number by decomposing it into two 256-bit digits
        // with the higher bits multiplied by 2^256. Thus, we perform two reductions
        //
        // 1. the lower bits are multiplied by R^2, as normal
        // 2. the upper bits are multiplied by R^2 * 2^256 = R^3
        //
        // and computing their sum in the field. It remains to see that arbitrary 256-bit
        // numbers can be placed into Montgomery form safely using the reduction. The
        // reduction works so long as the product is less than R=2^256 multiplied by
        // the modulus. This holds because for any `c` smaller than the modulus, we have
        // that (2^256 - 1)*c is an acceptable product for the reduction. Therefore, the
        // reduction always works so long as `c` is in the field; in this case it is either the
        // constant `R2` or `R3`.
        // Thanks to the reduction, these unwraps to Scalar are safe
        let reduced_limbs0 = Self::reduce(limbs[..4].try_into().unwrap());
        let reduced_limbs1 = Self::reduce(limbs[4..8].try_into().unwrap());
        let d0 = blstrs::Scalar::from_u64s_le(&reduced_limbs0).unwrap();
        let d1 = blstrs::Scalar::from_u64s_le(&reduced_limbs1).unwrap();
        // Convert to Montgomery form
        Self(d0 + d1 * *R)
    }

    // This is only needed because blstrs does not provide any method for constructing a Scalar
    // while applying modular reduction to the input
    fn reduce(limbs: [u64; 4]) -> [u64; 4] {
        const P2_64: u128 = 1u128 << 64;
        let mut reduced_limbs = [0u128; 4];

        let mut result = [0; 4];
        result.copy_from_slice(&limbs);
        let mut reps = 0;
        while !Self::is_reduced(result) {
            let mut remainder = 0;
            for i in 0..4 {
                reduced_limbs[i] = result[i] as u128;
                if reduced_limbs[i] >= MODULUS[i] as u128 + remainder {
                    reduced_limbs[i] -= MODULUS[i] as u128 + remainder;
                    remainder = 0;
                } else {
                    reduced_limbs[i] += P2_64 - (MODULUS[i] as u128 + remainder);
                    remainder = 1;
                }
                assert!(reduced_limbs[i] < P2_64);
                result[i] = reduced_limbs[i] as u64;
            }
            reps += 1;
            assert!(remainder == 0);
        }
        assert!(reps <= 2);
        result
    }

    fn is_reduced(limbs: [u64; 4]) -> bool {
        for i in (0..4).rev() {
            match limbs[i].cmp(&(MODULUS[i])) {
                std::cmp::Ordering::Less => {
                    return true;
                }
                std::cmp::Ordering::Equal => {}
                std::cmp::Ordering::Greater => {
                    return false;
                }
            }
        }
        true
    }
}

// Follows https://github.com/zkcrypto/bls12_381/blob/6bb96951d5c2035caf4989b6e4a018435379590f/src/hash_to_curve/map_scalar.rs
impl FromOkm for ScalarWrapper {
    // ceil(log2(p)) = 255, m = 1, k = 128.
    type Length = U48;

    fn from_okm(okm: &GenericArray<u8, Self::Length>) -> Self {
        let mut bs = [0u8; 64];
        bs[16..].copy_from_slice(okm);
        bs.reverse(); // into little endian
        ScalarWrapper::from_bytes_wide(&bs)
    }
}

#[cfg(test)]
mod tests {
    use blstrs::Scalar;
    use digest::generic_array::GenericArray;
    use elliptic_curve::hash2curve::FromOkm;
    use elliptic_curve::Field;
    use elliptic_curve::Group;
    use rand_core::OsRng;

    use crate::confidential_key_derivation::ciphersuite::verify_signature;
    use crate::confidential_key_derivation::ciphersuite::ScalarWrapper;
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
        check_common_traits_for_type(BLS12381SHA256);
    }

    #[test]
    fn test_hash_to_scalar() {
        let tests: &[(&[u8], &str)] = &[
            (
                &[0u8; 48],
                "ScalarWrapper(Scalar(0x0000000000000000000000000000000000000000000000000000000000000000))",
            ),
            (
                b"aaaaaabbbbbbccccccddddddeeeeeeffffffgggggghhhhhh",
                "ScalarWrapper(Scalar(0x2228450bf55d8fe62395161bd3677ff6fc28e45b89bc87e02a818eda11a8c5da))",
            ),
            (
                b"111111222222333333444444555555666666777777888888",
                "ScalarWrapper(Scalar(0x4aa543cbd2f0c8f37f8a375ce2e383eb343e7e3405f61e438b0a15fb8899d1ae))",
            ),
        ];
        for (input, expected) in tests {
            let output = format!(
                "{:?}",
                <ScalarWrapper as FromOkm>::from_okm(GenericArray::from_slice(input))
            );
            assert_eq!(&output, expected);
        }
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
