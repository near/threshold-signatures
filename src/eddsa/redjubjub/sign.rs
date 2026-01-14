//! This module and the frost one are supposed to have the same helper function
//! However, currently the reddsa is implemented  wraps a signature generation functionality from `Frost` library
//!  into `cait-sith::Protocol` representation.
use super::{KeygenOutput, SignatureOption, PresignOutput, JubjubBlake2b512};
use crate::errors::{InitializationError, ProtocolError};
use crate::participants::{Participant, ParticipantList};
use crate::protocol::helpers::recv_from_others;
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::Protocol;

use frost_core::keys::{KeyPackage, PublicKeyPackage, SigningShare};
use frost_core::{aggregate, round2, VerifyingKey};
use rand_core::CryptoRngCore;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

type J = JubjubBlake2b512;


/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
/// 
/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
pub fn sign(
    participants: &[Participant],
    threshold: usize,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = SignatureOption>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    }

    let comms = Comms::new();
    let chan = comms.shared_channel();
    let fut = fut_wrapper(
        chan,
        participants,
        threshold,
        me,
        coordinator,
        keygen_output,
        message,
        rng,
    );
    Ok(make_protocol(comms, fut))
}


#[allow(clippy::too_many_arguments)]
async fn fut_wrapper(
    chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    message: Vec<u8>,
    mut rng: impl CryptoRngCore,
) -> Result<SignatureOption, ProtocolError> {
    if me == coordinator {
        do_sign_coordinator(
            chan,
            participants,
            threshold,
            me,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    } else {
        do_sign_participant(
            chan,
            threshold,
            me,
            coordinator,
            keygen_output,
            message,
            &mut rng,
        )
        .await
    }
}

/// Returns a future that executes signature protocol for *the Coordinator*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
async fn do_sign_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    // signature_randomizer: Randomizer<J>,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1
    let mut signature_shares: BTreeMap<frost_core::Identifier::<JubjubBlake2b512>, round2::SignatureShare::<J>> =
        BTreeMap::new();

    let signature_share = create_signature_share(threshold, me, keygen_output, presignature, message)?;

    let sign_waitpoint = chan.next_waitpoint();
    signature_shares.insert(me.to_identifier()?, signature_share);
    for (from, signature_share) in recv_from_others(&chan, sign_waitpoint, &participants, me).await?
    {
        signature_shares.insert(from.to_identifier()?, signature_share);
    }

    // --- Signature aggregation.
    // * Converted collected signature shares into the signature.
    // * Signature is verified internally during `aggregate()` call.

    // Step 2.6 and 2.7
    // We supply empty map as `verifying_shares` because we have disabled "cheater-detection" feature flag.
    // Feature "cheater-detection" only points to a malicious participant, if there's such.
    // It doesn't bring any additional guarantees.
    let public_key_package = PublicKeyPackage::new(BTreeMap::new(), vk_package);
    let signature = aggregate(&signing_package, &signature_shares, &public_key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))?;

    Ok(Some(signature))
}

/// Returns a future that executes signature protocol for *a Participant*.
///
/// WARNING: Extracted from FROST documentation:
/// In all of the main FROST ciphersuites, the entire message must be sent
/// to participants. In some cases, where the message is too big, it may be
/// necessary to send a hash of the message instead. We strongly suggest
/// creating a specific ciphersuite for this, and not just sending the hash
/// as if it were the message.
/// For reference, see how RFC 8032 handles "pre-hashing".
async fn do_sign_participant(
    mut chan: SharedChannel,
    threshold: usize,
    me: Participant,
    coordinator: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    // signature_randomizer: Randomizer<J>,
) -> Result<SignatureOption, ProtocolError> {
    // --- Round 1.
    if coordinator == me {
        return Err(ProtocolError::AssertionFailed(
            "the do_sign_participant function cannot be called
            for a coordinator"
                .to_string(),
        ));
    }
    
    let signature_share = create_signature_share(threshold, me, keygen_output, presignature, message)?;

    let sign_waitpoint = chan.next_waitpoint();
    chan.send_private(sign_waitpoint, coordinator, &signature_share)?;

    Ok(None)
}

fn create_signature_share(
    threshold: usize,
    me: Participant,
    keygen_output: KeygenOutput,
    presignature: PresignOutput,
    message: Vec<u8>,
    // signature_randomizer: Randomizer<J>,
) -> Result<frost_core::round2::SignatureShare<J>, ProtocolError>{
    let signing_package = frost_core::SigningPackage::<J>::new(presignature.commitments_map, message.as_slice());
    let vk_package = keygen_output.public_key;
    let key_package = construct_key_package(threshold, me, keygen_output.private_share, &vk_package)?;
    // Ensures the values are zeroized on drop
    let key_package = Zeroizing::new(key_package);
    round2::sign(&signing_package, &presignature.nonces, &key_package)
        .map_err(|e| ProtocolError::AssertionFailed(e.to_string()))
}

/// A function that takes a signing share and a keygenOutput
/// and construct a public key package used for frost signing
fn construct_key_package(
    threshold: usize,
    me: Participant,
    signing_share: SigningShare<J>,
    verifying_key: &VerifyingKey<J>,
) -> Result<KeyPackage<J>, ProtocolError> {
    let identifier = me.to_identifier()?;
    let verifying_share = signing_share.into();

    Ok(KeyPackage::new(
        identifier,
        signing_share,
        verifying_share,
        *verifying_key,
        u16::try_from(threshold).map_err(|_| {
            ProtocolError::Other("threshold cannot be converted to u16".to_string())
        })?,
    ))
}
