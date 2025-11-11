pub mod common;
mod dkg;
mod sign;
mod presign;
mod mockrng;
mod run_protocol;

use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::KeygenOutput;

/// Type representing DKG output keys
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
/// Type representing DKG output protocols runs
pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;
/// Type for a deterministic RNG
pub use mockrng::MockCryptoRng;

pub use dkg::{run_keygen, run_refresh, run_reshare, assert_public_key_invariant};
pub use sign::{run_sign, check_one_coordinator_output};
pub use presign::ecdsa_generate_rerandpresig_args;
pub use run_protocol::{run_protocol, run_two_party_protocol};


