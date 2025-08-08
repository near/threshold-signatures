// This module provides generic functions to be used
// in the implemented schemes testing cases

use rand_core::{OsRng, RngCore};
use std::error::Error;

use crate::protocol::{run_protocol, InitializationError, Participant, Protocol};
use crate::{keygen, refresh, reshare, Ciphersuite, KeygenOutput, VerifyingKey};

// +++++++++++++++++ Participants Utilities +++++++++++++++++ //
/// Generates a vector of participants
/// enumerated from 0 to number
pub fn generate_participants(number: usize) -> Vec<Participant> {
    (0..number)
        .map(|i| Participant::from(i as u32))
        .collect::<Vec<_>>()
}

/// Generates a vector of participants
/// enumerated from 0 to number
pub fn generate_random_participants(number: usize) -> Vec<Participant> {
    let mut participants = (0..number)
        .map(|_| Participant::from(OsRng.next_u32()))
        .collect::<Vec<_>>();
    participants.sort();
    participants
}

// +++++++++++++++++ DKG Functions +++++++++++++++++ //
/// Runs distributed keygen
pub(crate) fn run_keygen<C: Ciphersuite>(
    participants: &[Participant],
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput<C>)>, Box<dyn Error>>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)> =
        Vec::with_capacity(participants.len());

    for p in participants {
        let protocol = keygen::<C>(participants, *p, threshold)?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// Runs distributed refresh
pub(crate) fn run_refresh<C: Ciphersuite>(
    participants: &[Participant],
    keys: Vec<(Participant, KeygenOutput<C>)>,
    threshold: usize,
) -> Result<Vec<(Participant, KeygenOutput<C>)>, Box<dyn Error>>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in keys.iter() {
        let protocol = refresh::<C>(
            Some(out.private_share),
            out.public_key,
            participants,
            threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// runs distributed reshare
pub(crate) fn run_reshare<C: Ciphersuite>(
    participants: &[Participant],
    pub_key: &VerifyingKey<C>,
    keys: Vec<(Participant, KeygenOutput<C>)>,
    old_threshold: usize,
    new_threshold: usize,
    new_participants: Vec<Participant>,
) -> Result<Vec<(Participant, KeygenOutput<C>)>, Box<dyn Error>>
where
    frost_core::Element<C>: Send,
    frost_core::Scalar<C>: Send,
{
    assert!(!new_participants.is_empty());
    let mut setup: Vec<_> = vec![];

    for new_participant in &new_participants {
        let mut is_break = false;
        for (p, k) in &keys {
            if p == new_participant {
                setup.push((*p, (Some(k.private_share), k.public_key)));
                is_break = true;
                break;
            }
        }
        if !is_break {
            setup.push((*new_participant, (None, *pub_key)));
        }
    }

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = KeygenOutput<C>>>)> =
        Vec::with_capacity(participants.len());

    for (p, out) in setup.iter() {
        let protocol = reshare(
            participants,
            old_threshold,
            out.0,
            out.1,
            &new_participants,
            new_threshold,
            *p,
        )?;
        protocols.push((*p, Box::new(protocol)));
    }

    let result = run_protocol(protocols)?;
    Ok(result)
}

/// Assert that each participant has the same view of the public key
pub(crate) fn assert_public_key_invariant<C: Ciphersuite>(
    participants: &[(Participant, KeygenOutput<C>)],
) -> Result<(), Box<dyn Error>> {
    let public_key_package = participants.first().unwrap().1.public_key;

    if participants
        .iter()
        .any(|(_, key_pair)| key_pair.public_key != public_key_package)
    {
        panic!("public key package is not the same for all participants");
    }

    Ok(())
}

// +++++++++++++++++ Signing Functions +++++++++++++++++ //
/// Runs the signing algorithm.
/// Only used for unit tests.
pub(crate) fn run_sign<C: Ciphersuite, PresignOutput, Signature: Clone, F>(
    participants_presign: Vec<(Participant, PresignOutput)>,
    public_key: frost_core::Element<C>,
    msg_hash: frost_core::Scalar<C>,
    sign: F,
) -> Result<Vec<(Participant, Signature)>, Box<dyn Error>>
where
    F: Fn(
        &[Participant],
        Participant,
        frost_core::Element<C>,
        PresignOutput,
        frost_core::Scalar<C>,
    ) -> Result<Box<dyn Protocol<Output = Signature>>, InitializationError>,
{
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = Signature>>)> =
        Vec::with_capacity(participants_presign.len());

    let participants: Vec<Participant> = participants_presign.iter().map(|(p, _)| *p).collect();
    let participants = participants.as_slice();
    for (p, presignature) in participants_presign.into_iter() {
        let protocol = sign(participants, p, public_key, presignature, msg_hash)?;

        protocols.push((p, protocol));
    }

    Ok(run_protocol(protocols)?)
}

/// For algorithms that make use of a Coordinator and normal Participants.
/// Checks that only the coordinator gets an output
pub(crate) fn assert_only_coordinator_output<ProtocolOutput>(
    data: Vec<(Participant, Option<ProtocolOutput>)>,
) -> ProtocolOutput {
    // test one single some for the coordinator
    let mut some_iter = data.into_iter().filter(|(_, out)| out.is_some());

    let coordinator_output = some_iter
        .next()
        .map(|(_, out)| out.unwrap())
        .expect("Cannot have zero coordinators");
    assert!(some_iter.next().is_none(), "Detected multiple coordinators");
    coordinator_output
}

// +++++++++++++++++ Full Signing Protocol +++++++++++++++++ //
