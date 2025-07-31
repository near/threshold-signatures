//! This module serves as a wrapper for Ed25519 scheme.
use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::Ed25519Sha512;

pub type KeygenOutput = crate::KeygenOutput::<Ed25519Sha512>;

impl From<crate::generic_dkg::KeygenOutput<Ed25519Sha512>> for KeygenOutput {
    fn from(value: crate::generic_dkg::KeygenOutput<Ed25519Sha512>) -> Self {
        Self {
            private_share: value.private_share,
            public_key: value.public_key,
        }
    }
}

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;
