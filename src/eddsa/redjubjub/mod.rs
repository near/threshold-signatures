//! This module serves as a wrapper for distributed RedDSA a.k.a. rerandomized FROST from [GK](https://eprint.iacr.org/2024/436.pdf)
//! This is implemented on JubJub Curve with only the "Spend Authorization" set of parameters.
//! Check https://zips.z.cash/protocol/protocol.pdf#concretespendauthsig for more info about the set of parameters.
pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zeroize::ZeroizeOnDrop;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

// JubJub Curve
pub use reddsa::frost::redjubjub::JubjubBlake2b512;
impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}
impl Ciphersuite for JubjubBlake2b512 {}

pub type SigningShare = crate::SigningShare<JubjubBlake2b512>;
pub type SigningCommitments = frost_core::round1::SigningCommitments<JubjubBlake2b512>;
pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput,
}

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub nonces: frost_core::round1::SigningNonces<JubjubBlake2b512>,
    #[zeroize[skip]]
    pub commitments_map: BTreeMap<frost_ed25519::Identifier, SigningCommitments>,
}


/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<frost_core::Signature<JubjubBlake2b512>>;

