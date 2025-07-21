use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::serde::encode_writer;

use super::random::Randomizer;

const COMMIT_LABEL: &[u8] = b"Near threshold signature commitment";
const COMMIT_LEN: usize = 32;

/// Represents a commitment to some value.
///
/// This commit is both binding, in that it can't be opened to a different
/// value than the one committed, and hiding, in that it hides the value
/// committed inside (perfectly).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment([u8; COMMIT_LEN]);

impl Commitment {
    fn compute<T: Serialize>(val: &T, r: &Randomizer) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_LABEL);
        hasher.update(r.as_ref());
        hasher.update(b"start data");
        encode_writer(&mut hasher, val);
        Commitment(hasher.finalize().into())
    }

    /// Check that a value and a randomizer match this commitment.
    #[must_use]
    pub fn check<T: Serialize>(&self, val: &T, r: &Randomizer) -> bool {
        let actual = Self::compute(val, r);
        *self == actual
    }
}

/// Commit to an arbitrary serializable value.
///
/// This also returns a fresh randomizer, which is used to make sure that the
/// commitment perfectly hides the value contained inside.
///
/// This value will need to be sent when opening the commitment to allow
/// others to check that the opening is valid.
pub fn commit<T: Serialize, R: CryptoRngCore>(rng: &mut R, val: &T) -> (Commitment, Randomizer) {
    let r = Randomizer::random(rng);
    let c = Commitment::compute(val, &r);
    (c, r)
}
