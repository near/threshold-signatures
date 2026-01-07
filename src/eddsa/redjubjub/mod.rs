//! This module serves as a wrapper for Ed25519 scheme.
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

// JubJub Curve
pub type JubjubBlake2b512 = reddsa::frost::redjubjub::JubjubBlake2b512;
// JubJub Field
pub type JubjubScalarField = reddsa::frost::redjubjub::JubjubScalarField;
// JubJub Group
pub type JubjubGroup = reddsa::frost::redjubjub::JubjubGroup;

pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;

impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}

impl Ciphersuite for JubjubBlake2b512 {}

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<frost_core::Signature<JubjubBlake2b512>>;
