#![allow(
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

mod dkg;
mod mockrng;
pub mod mpc_interface;
mod participant_simulation;
mod participants;
mod presign;
mod run_protocol;
mod sign;
mod snapshot;

use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::KeygenOutput;

/// Type representing DKG output keys
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
/// Type representing DKG output protocols runs
pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;
/// Type for a deterministic RNG
pub use mockrng::MockCryptoRng;

pub use dkg::{assert_public_key_invariant, run_keygen, run_refresh, run_reshare};
pub use mockrng::create_multiple_rngs;
pub use participant_simulation::Simulator;
pub use participants::{generate_participants, generate_participants_with_random_ids};
pub use presign::ecdsa_generate_rerandpresig_args;
pub use run_protocol::{
    run_protocol, run_protocol_with_snapshots, run_simulated_protocol, run_two_party_protocol,
};
pub use sign::{check_one_coordinator_output, run_sign};
pub use snapshot::ProtocolSnapshot;
