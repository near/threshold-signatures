use serde::{Deserialize, Serialize};

use crate::{
    ecdsa::{
        Scalar,
        AffinePoint,
        KeygenOutput,
    },
};

/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type KeygenOutput<Secp256K1Sha256> from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: usize,
}

// The output of the presigning protocol.
/// Contains the signature precomputed parts performed
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub alpha_i: Scalar,
    pub beta_i: Scalar,
}

pub mod presign;
pub mod sign;
#[cfg(test)]
pub mod test;