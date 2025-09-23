//! Kani proofs for the `strobe` module.
//!
//! This file is separate from `strobe.rs` to keep production code clean of
//! verification-specific dependencies and concerns.
use crate::crypto::proofs::strobe::{transmute_state, AlignedKeccakState};

/// Kani proofs for the `strobe` module.

pub mod proofs {
    use super::*;

    #[kani::proof]
    fn check_transmute_state_correctness() {
        // Create a symbolic/nondeterministic `AlignedKeccakState`. Kani will explore
        // all possible byte patterns for this array.
        let mut state: AlignedKeccakState = kani::any();

        // Call the function under test, which contains the `unsafe` block.
        // We immediately dereference the result to create an owned copy. This is
        // crucial to end the mutable borrow on `state` right away, allowing us
        // to immutably borrow `state` in the next step.
        let transmuted_array: [u64; 25] = *transmute_state(&mut state);

        // Implement the safe, little-endian equivalent.
        // We iterate over the 200-byte buffer in 8-byte chunks and convert
        // each chunk to a u64 using the specified little-endian byte order,
        // as required by the Keccak standard.
        let mut safe_slice = [0u64; 25];
        for (i, chunk) in state.chunks_exact(8).enumerate() {
            let chunk_array: [u8; 8] = chunk.try_into().unwrap();
            safe_slice[i] = u64::from_le_bytes(chunk_array);
        }

        // Assert that the result of the `unsafe` transmutation is bit-for-bit
        // identical to the result of the safe, endian-aware implementation.
        // This proof will fail if the `unsafe` code is incorrect or if the
        // host machine is not little-endian.
        assert_eq!(transmuted_array, safe_slice);
    }
}
