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

use blst::{
    blst_p1, blst_p1_add, blst_p1_affine, blst_p1_cneg, blst_p1_mult, blst_p1_to_affine,
    blst_scalar,
    min_pk::{AggregatePublicKey, PublicKey, SecretKey},
};
use serde::{Deserialize, Serialize};

/// Key Pairs containing secret share of the participant along with the master verification key
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct KeygenOutput {
    pub private_share: SecretKey,
    pub public_key: PublicKey,
}

pub(crate) type Scalar = SecretKey;
pub(crate) type Element = PublicKey;
pub(crate) type CoefficientCommitment = PublicKey;

/// The output of the confidential key derivation protocol when run by the coordinator
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CKDCoordinatorOutput {
    big_y: CoefficientCommitment,
    big_c: CoefficientCommitment,
}

impl CKDCoordinatorOutput {
    pub fn new(big_y: Element, big_c: Element) -> Self {
        CKDCoordinatorOutput { big_y, big_c }
    }

    /// Outputs big_y
    pub fn big_y(&self) -> CoefficientCommitment {
        self.big_y
    }

    /// Outputs big_c
    pub fn big_c(&self) -> CoefficientCommitment {
        self.big_c
    }

    /// Takes a secret scalar and returns
    /// s <- C − a ⋅ Y = msk ⋅ H ( app_id )
    pub fn unmask(&self, secret_scalar: Scalar) -> CoefficientCommitment {
        let scalar = from_secret_key_to_scalar(&secret_scalar);
        let big_y = AggregatePublicKey::from_public_key(&self.big_y).into();
        let big_c = AggregatePublicKey::from_public_key(&self.big_c).into();
        let mut result = blst_p1::default();
        let mut result_affine = blst_p1_affine::default();
        unsafe {
            blst_p1_mult(&mut result, &big_y, scalar.b.as_ptr(), 255);
            blst_p1_cneg(&mut result, true);
            blst_p1_add(&mut result, &result, &big_c);
            blst_p1_to_affine(&mut result_affine, &result);
        };
        result_affine.into()
    }
}

fn from_secret_key_to_scalar(s: &SecretKey) -> blst_scalar {
    <&blst::min_pk::SecretKey as std::convert::Into<&blst_scalar>>::into(s).clone()
}

/// None for participants and Some for coordinator
pub type CKDOutput = Option<CKDCoordinatorOutput>;
