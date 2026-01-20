//! A wrapper for distributed `RedDSA` on `JubJub` curve with only the `Spend Authorization`.
//!
//! Check [GK](https://eprint.iacr.org/2024/436.pdf) and <https://zips.z.cash/protocol/protocol.pdf#concretespendauthsig>
pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;

use crate::crypto::ciphersuite::{BytesOrder, Ciphersuite, ScalarSerializationFormat};

use reddsa::frost::redjubjub::{
    round1::{SigningCommitments, SigningNonces},
    Identifier, VerifyingKey,
    Signature as redjubjubSig, Error, Randomizer, RandomizedParams,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// JubJub Curve
pub use reddsa::frost::redjubjub::JubjubBlake2b512;

impl ScalarSerializationFormat for JubjubBlake2b512 {
    fn bytes_order() -> BytesOrder {
        BytesOrder::LittleEndian
    }
}
impl Ciphersuite for JubjubBlake2b512 {}

pub type KeygenOutput = crate::KeygenOutput<JubjubBlake2b512>;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Signature {
    pub signature: redjubjubSig,
    pub randomizer: Randomizer,
}

impl Signature {
    pub fn new(signature: redjubjubSig, randomizer: Randomizer) -> Self {
        Self { signature, randomizer }
    }
    pub fn verify(&self, public_key: &VerifyingKey, message: Vec<u8>) -> Result<(), Error> {
        let randomparameters = RandomizedParams::from_randomizer(public_key, self.randomizer);
        randomparameters.randomized_verifying_key().verify(&message, &self.signature)
    }
}

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    pub keygen_out: KeygenOutput,
}

// Not sure what to do with the Zeroization
// use zeroize::ZeroizeOnDrop;
// #[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, ZeroizeOnDrop)]

/// The output of the presigning protocol.
///
/// This output is basically all the parts of the signature that we can perform
/// without knowing the message.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub nonces: SigningNonces,
    // #[zeroize[skip]]
    pub commitments_map: BTreeMap<Identifier, SigningCommitments>,
}

/// Signature would be Some for coordinator and None for other participants
pub type SignatureOption = Option<Signature>;
