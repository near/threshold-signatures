mod crypto;
pub mod participants;

pub mod confidential_key_derivation;
pub mod ecdsa;
pub mod eddsa;
pub mod errors;
pub mod thresholds;

#[cfg(feature = "test-utils")]
pub mod test_utils;

// TODO: We should probably no expose the full modules, but only the types
// that make sense for our library
pub use blstrs;
pub use frost_core;
pub use frost_ed25519;
pub use frost_secp256k1;

pub use crypto::ciphersuite::Ciphersuite;
pub use participants::ParticipantList;
// For benchmark
pub use crypto::polynomials::{
    batch_compute_lagrange_coefficients, batch_invert, compute_lagrange_coefficient,
};
use zeroize::ZeroizeOnDrop;

mod dkg;
pub mod protocol;
use crate::dkg::{assert_keys_invariants, do_keygen, do_reshare, reshare_assertions};
use crate::errors::InitializationError;
use crate::participants::Participant;
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::Protocol;
use crate::thresholds::MaxMalicious;
use rand_core::CryptoRngCore;
use std::marker::Send;

use frost_core::serialization::SerializableScalar;
use frost_core::{keys::SigningShare, Group, VerifyingKey};

use serde::{Deserialize, Serialize};

pub type Scalar<C> = frost_core::Scalar<C>;
pub type Element<C> = frost_core::Element<C>;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq, ZeroizeOnDrop)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    #[zeroize[skip]]
    pub public_key: VerifyingKey<C>,
    #[zeroize[skip]]
    pub max_malicious: MaxMalicious,
}

/// This is a necessary element to be able to derive different keys
/// from signing shares.
/// We do not bind the user with the way to compute the inner scalar of the tweak
#[derive(Copy, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(bound = "C: Ciphersuite")]
pub struct Tweak<C: Ciphersuite>(SerializableScalar<C>);

impl<C: Ciphersuite> Tweak<C> {
    pub fn new(tweak: Scalar<C>) -> Self {
        Self(SerializableScalar(tweak))
    }

    /// Outputs the inner value of the tweak
    pub fn value(&self) -> Scalar<C> {
        self.0 .0
    }

    /// Derives the signing share as x + tweak
    pub fn derive_signing_share(&self, private_share: &SigningShare<C>) -> SigningShare<C> {
        let derived_share = private_share.to_scalar() + self.value();
        SigningShare::new(derived_share)
    }

    /// Derives the verifying key as X + tweak . G
    pub fn derive_verifying_key(&self, public_key: &VerifyingKey<C>) -> VerifyingKey<C> {
        let derived_share = public_key.to_element() + C::Group::generator() * self.value();
        VerifyingKey::new(derived_share)
    }
}

/// Generic key generation function agnostic of the curve
pub fn keygen<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    max_malicious: MaxMalicious,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_keys_invariants(participants, me, max_malicious)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, max_malicious, rng);
    Ok(make_protocol(comms, fut))
}

/// Performs the key reshare protocol
#[allow(clippy::too_many_arguments)]
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_max_malicious: MaxMalicious,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_max_malicious: MaxMalicious,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_max_malicious;
    let (participants, old_participants) = reshare_assertions::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_max_malicious,
        old_participants,
    )?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants,
        me,
        threshold,
        old_signing_key,
        old_public_key,
        old_participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
}

/// Performs the refresh protocol
pub fn refresh<C: Ciphersuite>(
    old_keygen: &KeygenOutput<C>,
    old_participants: &[Participant],
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    Element<C>: Send,
    Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_keys_invariants(old_participants, me, old_keygen.max_malicious)?;
    let fut = do_reshare(
        comms.shared_channel(),
        participants.clone(),
        me,
        old_keygen.max_malicious,
        Some(old_keygen.private_share),
        old_keygen.public_key,
        participants,
        rng,
    );
    Ok(make_protocol(comms, fut))
}
