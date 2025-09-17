pub mod presign;
pub mod sign;
#[cfg(test)]
mod test;

use crate::{
    ecdsa::{AffinePoint, KeygenOutput, RerandomizationArguments, Scalar, Tweak},
    protocol::errors::ProtocolError,
};
use serde::{Deserialize, Serialize};

/// The necessary inputs for the creation of a presignature.
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type KeygenOutput<Secp256K1Sha256> from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: usize,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: AffinePoint,

    /// Our secret shares of the nonces.
    pub k_i: Scalar,
    pub alpha_i: Scalar,
    pub beta_i: Scalar,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed elements
/// independently of the message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RerandomizedPresignOutput {
    /// The rerandomized public nonce commitment.
    big_r: AffinePoint,

    /// Our rerandomized secret shares of the nonces.
    alpha_i: Scalar,
    beta_i: Scalar,
}

impl RerandomizedPresignOutput {
    pub fn new(
        presignature: PresignOutput,
        tweak: Tweak,
        args: RerandomizationArguments,
    ) -> Result<Self, ProtocolError> {
        if presignature.big_r != *args.big_r {
            return Err(ProtocolError::IncompatibleRerandomizationInputs);
        }
        let delta = args.derive_randomness();
        let rerandomized_big_r = presignature.big_r * delta;
        let inv_delta = delta.invert();
        if inv_delta.is_none().into() {
            return Err(ProtocolError::AssertionFailed(
                "expected a non-zero randomness".to_string(),
            ));
        }

        // cannot fail due to the previous check
        let inv_delta = inv_delta.unwrap();

        let rerandomized_alpha_i =
            (presignature.alpha_i + tweak.value() * presignature.k_i) * inv_delta;
        Ok(RerandomizedPresignOutput {
            big_r: rerandomized_big_r.into(),
            alpha_i: rerandomized_alpha_i,
            beta_i: presignature.beta_i,
        })
    }

    #[cfg(test)]
    /// Outputs the same elements as in the PresignatureOutput
    /// Used for testing the core schemes without rerandomization
    pub fn new_without_rerandomization(presignature: PresignOutput) -> Self {
        RerandomizedPresignOutput {
            big_r: presignature.big_r,
            alpha_i: presignature.alpha_i,
            beta_i: presignature.beta_i,
        }
    }
}
