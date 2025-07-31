// This module provides generic functions to be used
// in the implemented schemes testing cases

use rand_core::{OsRng, RngCore};

use crate::KeygenOutput;
use crate::protocol::Participant;
use crate::Ciphersuite;

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
