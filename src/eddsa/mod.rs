//! This module serves as a wrapper for Ed25519 scheme.
use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};
use frost_ed25519::Ed25519Sha512;

pub type KeygenOutput = crate::KeygenOutput::<Ed25519Sha512>;

impl ScalarSerializationFormat for Ed25519Sha512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for Ed25519Sha512 {}

pub type Signature = Option<frost_ed25519::Signature>; // None for participants and Some for coordinator

pub mod dkg_ed25519;
pub mod sign;
#[cfg(test)]
mod test;
