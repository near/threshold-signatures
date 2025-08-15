use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const HASH_LABEL: &[u8] = b"Near threshold signature generic hash";
const HASH_LEN: usize = 32;

/// The output of a generic hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashOutput([u8; HASH_LEN]);

impl AsRef<[u8]> for HashOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Hash some value to produce a short digest as follows
/// SHA256(HASH_LABEL || msgpack(value))
pub fn hash<T: Serialize>(val: &T) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update(HASH_LABEL);
    rmp_serde::encode::write(&mut hasher, val).expect("failed to encode value");
    HashOutput(hasher.finalize().into())
}

/// Hashes using a domain separator as follows:
/// SHA256(HASH_LABEL || msgpack([domain_separator, data])
/// This function DOES NOT internally increment the domain separator
pub fn domain_separate_hash<T: Serialize>(domain_separator: u32, data: &T) -> HashOutput {
    let preimage = (domain_separator, data);
    hash(&preimage)
}

#[cfg(test)]
pub(crate) use test::scalar_hash;

#[cfg(test)]
mod test {
    use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};

    use super::{domain_separate_hash, hash};
    use digest::{Digest, FixedOutput};
    use ecdsa::hazmat::DigestPrimitive;
    use k256::{FieldBytes, Scalar, Secp256k1};

    #[test]
    fn test_same_inputs_hash() {
        let val = ("abc", 123);
        let hash1 = hash(&val);
        let hash2 = hash(&val);
        assert_eq!(hash1.0, hash2.0);

        let hash1 = domain_separate_hash(42, &val);
        let hash2 = domain_separate_hash(42, &val);
        assert_eq!(hash1.0, hash2.0);
    }

    #[test]
    fn test_different_inputs_hash() {
        let val1 = ("abc", 123);
        let val2 = ("abc", 124);
        let hash1 = hash(&val1);
        let hash2 = hash(&val2);
        assert_ne!(hash1.0, hash2.0);

        let hash1 = domain_separate_hash(41, &val1);
        let hash2 = domain_separate_hash(42, &val1);
        assert_ne!(hash1.0, hash2.0);

        let hash2 = domain_separate_hash(41, &val2);
        assert_ne!(hash1.0, hash2.0);
    }

    #[cfg(test)]
    /// Hashes a message string into an arbitrary scalar
    pub(crate) fn scalar_hash(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }
}
