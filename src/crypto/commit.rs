use rand_core::CryptoRngCore;
use rmp_serde::encode::{write, Error};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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
    fn compute<T: Serialize>(val: &T, r: &Randomizer) -> Result<Self, Error> {
        let mut hasher = Sha256::new();
        hasher.update(COMMIT_LABEL);
        hasher.update(r.as_ref());
        hasher.update(b"start data");
        write(&mut hasher, val)?;
        Ok(Commitment(hasher.finalize().into()))
    }

    /// Check that a value and a randomizer match this commitment.
    pub fn check<T: Serialize>(&self, val: &T, r: &Randomizer) -> Result<bool, Error> {
        let actual = Self::compute(val, r)?;
        Ok(*self == actual)
    }
}

/// Commit to an arbitrary serializable value.
///
/// This also returns a fresh randomizer, which is used to make sure that the
/// commitment perfectly hides the value contained inside.
///
/// This value will need to be sent when opening the commitment to allow
/// others to check that the opening is valid.
pub fn commit<T: Serialize, R: CryptoRngCore>(
    rng: &mut R,
    val: &T,
) -> Result<(Commitment, Randomizer), Error> {
    let r = Randomizer::random(rng);
    let c = Commitment::compute(val, &r)?;
    Ok((c, r))
}
