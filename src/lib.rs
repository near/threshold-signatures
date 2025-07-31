mod crypto;

mod generic_dkg;
mod participants;

pub mod protocol;

pub mod ecdsa;
pub mod eddsa;

#[cfg(test)]
mod test;



use crypto::ciphersuite::Ciphersuite;
use frost_core::{keys::SigningShare, VerifyingKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}
