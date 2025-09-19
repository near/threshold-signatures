//! Confidential Key Derivation (CKD) protocol.
//!
//! This module provides the implementation of the Confidential Key Derivation (CKD) protocol,
//! which allows a client to derive a unique key for a specific application without revealing
//! the application identifier to the key derivation service.
//!
//! The protocol is based on a combination of Oblivious Transfer (OT) and Diffie-Hellman key exchange.
//!
//! For more details, refer to the `confidential_key_derivation.md` document in the `docs` folder.

pub mod app_id;
pub mod protocol;

pub use app_id::AppId;

use frost_secp256k1::{keys::SigningShare, Secp256K1Sha256, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Key Pairs containing secret share of the participant along with the master verification key
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeygenOutput {
    pub private_share: SigningShare,
    pub public_key: VerifyingKey,
}

pub(crate) type CoefficientCommitment = frost_core::keys::CoefficientCommitment<Secp256K1Sha256>;
pub(crate) type Element = frost_core::Element<Secp256K1Sha256>;
pub(crate) type Scalar = frost_core::Scalar<Secp256K1Sha256>;

/// The output of the confidential key derivation protocol when run by the coordinator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDCoordinatorOutput {
    big_y: CoefficientCommitment,
    big_c: CoefficientCommitment,
    big_d: CoefficientCommitment,
}

impl CKDCoordinatorOutput {
    pub fn new(big_y: Element, big_c: Element, big_d: Element) -> Self {
        CKDCoordinatorOutput {
            big_y: CoefficientCommitment::new(big_y),
            big_c: CoefficientCommitment::new(big_c),
            big_d: CoefficientCommitment::new(big_d),
        }
    }

    /// Outputs big_y
    pub fn big_y(&self) -> CoefficientCommitment {
        self.big_y
    }

    /// Outputs big_c
    pub fn big_c(&self) -> CoefficientCommitment {
        self.big_c
    }

    /// Outputs big_d
    pub fn big_d(&self) -> CoefficientCommitment {
        self.big_d
    }

    /// Takes a secret scalar and the MPC public key and verifies
    /// C − a ⋅ Y == a ⋅ PK
    pub fn verify(&self, secret_scalar: Scalar, mpc_pk: CoefficientCommitment) -> bool {
        self.big_d.value() - self.big_y.value() * secret_scalar == mpc_pk.value() * secret_scalar
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( app_id )
    pub fn unmask(&self, secret_scalar: Scalar) -> CoefficientCommitment {
        CoefficientCommitment::new(self.big_c.value() - self.big_y.value() * secret_scalar)
    }
}

/// None for participants and Some for coordinator
pub type CKDOutput = Option<CKDCoordinatorOutput>;
