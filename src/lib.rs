mod crypto;
mod dkg;
mod participants;

pub mod confidential_key_derivation;
pub mod ecdsa;
pub mod eddsa;
pub mod protocol;
#[cfg(test)]
mod test;

pub use frost_core;
use frost_core::serialization::SerializableScalar;
pub use frost_ed25519;
pub use frost_secp256k1;
// For benchmark
pub use crypto::polynomials::{
    batch_compute_lagrange_coefficients, batch_invert, compute_lagrange_coefficient,
};

use crypto::ciphersuite::Ciphersuite;
use frost_core::{keys::SigningShare, Group, VerifyingKey};
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use std::marker::Send;

use crate::dkg::{assert_keygen_invariants, do_keygen, do_reshare, reshare_assertions};
use crate::protocol::internal::{make_protocol, Comms};
use crate::protocol::{errors::InitializationError, Participant, Protocol};

type Scalar<C> = frost_core::Scalar<C>;

#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[serde(bound = "C: Ciphersuite")]
/// Generic type of key pairs
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
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
    threshold: usize,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let comms = Comms::new();
    let participants = assert_keygen_invariants(participants, me, threshold)?;
    let fut = do_keygen::<C>(comms.shared_channel(), participants, me, threshold, rng);
    Ok(make_protocol(comms, fut))
}

/// Performs the key reshare protocol
#[allow(clippy::too_many_arguments)]
pub fn reshare<C: Ciphersuite>(
    old_participants: &[Participant],
    old_threshold: usize,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    new_participants: &[Participant],
    new_threshold: usize,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let comms = Comms::new();
    let threshold = new_threshold;
    let (participants, old_participants) = reshare_assertions::<C>(
        new_participants,
        me,
        threshold,
        old_signing_key,
        old_threshold,
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
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: &[Participant],
    old_threshold: usize,
    me: Participant,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = KeygenOutput<C>>, InitializationError>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    if old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(format!(
            "The participant {me:?} is running refresh without an old share",
        )));
    }
    let comms = Comms::new();
    let threshold = old_threshold;
    let (participants, old_participants) = reshare_assertions::<C>(
        old_participants,
        me,
        threshold,
        old_signing_key,
        threshold,
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
