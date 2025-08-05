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

/// Hash some value to produce a short digest.
pub fn hash<T: Serialize>(val: &T) -> HashOutput {
    let mut hasher = Sha256::new();
    hasher.update(HASH_LABEL);
    rmp_serde::encode::write(&mut hasher, val).expect("failed to encode value");
    HashOutput(hasher.finalize().into())
}

/// Hashes using a domain separator
/// The domain separator has to be manually incremented after the use of this function
pub fn domain_separate_hash<T: Serialize>(domain_separator: u32, data: &T) -> HashOutput {
    let preimage = (domain_separator, data);
    hash(&preimage)
}

#[cfg(test)]
pub(crate) use test::scalar_hash_secp256k1;

#[cfg(test)]
mod test {
    use elliptic_curve::{ops::Reduce, Curve, CurveArithmetic};
    use digest::{Digest, FixedOutput};
    use ecdsa::hazmat::DigestPrimitive;
    use k256::{FieldBytes, Scalar, Secp256k1};

    #[cfg(test)]
    /// Hashes a message string into an arbitrary scalar
    pub(crate) fn scalar_hash_secp256k1(msg: &[u8]) -> <Secp256k1 as CurveArithmetic>::Scalar {
        // follows  https://datatracker.ietf.org/doc/html/rfc9591#name-cryptographic-hash-function
        let digest = <Secp256k1 as DigestPrimitive>::Digest::new_with_prefix(msg);
        let m_bytes: FieldBytes = digest.finalize_fixed();
        <Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&m_bytes)
    }
}
