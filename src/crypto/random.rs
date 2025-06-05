use serde::{Deserialize, Serialize};
use rand_core::CryptoRngCore;

const RANDOMIZER_LEN: usize = 32;

// +++++++++ Randomizers +++++++++

/// Represents the randomizer used to make a commit hiding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Randomizer([u8; RANDOMIZER_LEN]);
impl Randomizer {
    /// Generate a new randomizer value by sampling from an RNG.
    pub fn random<R: CryptoRngCore>(rng: &mut R) -> Self {
        let mut out = [0u8; RANDOMIZER_LEN];
        rng.fill_bytes(&mut out);
        Self(out)
    }
}
impl AsRef<[u8]> for Randomizer {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
