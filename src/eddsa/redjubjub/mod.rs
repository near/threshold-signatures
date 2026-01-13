//! This module serves as a wrapper for Ed25519 scheme.
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

// JubJub Curve
pub use reddsa::frost::redjubjub::JubjubBlake2b512;
impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}
impl Ciphersuite for JubjubBlake2b512 {}


pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;
/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<frost_core::Signature<JubjubBlake2b512>>;

/// Abstracts over different RedJubJub parameter choices, [`Binding`]
/// and [`SpendAuth`].
pub use reddsa::SpendAuth;
pub use reddsa::Binding;


/// Randomizers for key pairs
use reddsa::SigningKey;