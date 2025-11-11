pub mod common;
mod dkg;
mod mockrng;
mod run_protocol;

use crate::participants::Participant;
use crate::protocol::Protocol;
use crate::KeygenOutput;

pub use run_protocol::{run_protocol, run_two_party_protocol};
pub use dkg::{run_keygen, run_refresh, run_reshare, assert_public_key_invariant};
pub use mockrng::MockCryptoRng;

/// Type representing DKG output keys
pub type GenOutput<C> = Vec<(Participant, KeygenOutput<C>)>;
/// Type representing DKG output protocols runs
pub type GenProtocol<C> = Vec<(Participant, Box<dyn Protocol<Output = C>>)>;
