pub mod ot_based_ecdsa;
pub mod robust_ecdsa;


extern crate threshold_signatures;
use threshold_signatures::{
    test::{random_32_bytes, generate_participants_with_random_ids},
    ecdsa::{Tweak, RerandomizationArguments, Secp256K1Sha256,},
    participants::ParticipantList,
};

use frost_core::Ciphersuite;
use rand_core::{CryptoRngCore, OsRng};
use k256::{
    ecdsa::{SigningKey, VerifyingKey}, Scalar,
};

// Outputs pk, R, hash, participants, entropy, randomness
pub fn generate_rerandpresig_args(
    rng: &mut impl CryptoRngCore,
    num_participants: usize,
) -> (RerandomizationArguments, Scalar) {
    let sk = SigningKey::random(&mut OsRng);
    let pk = *VerifyingKey::from(sk).as_affine();
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));
    let (_, big_r) = <Secp256K1Sha256>::generate_nonce(&mut OsRng);
    let big_r = big_r.to_affine();

    let msg_hash = random_32_bytes(rng);
    let entropy = random_32_bytes(rng);
    // Generate unique ten ParticipantId values
    let participants = generate_participants_with_random_ids(num_participants, rng);
    let participants = ParticipantList::new(&participants).unwrap();

    let args = RerandomizationArguments::new(pk, tweak, msg_hash, big_r, participants, entropy);
    let delta = args.derive_randomness().unwrap();
    (args, delta)
}
