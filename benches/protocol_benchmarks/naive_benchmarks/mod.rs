pub mod ot_based_ecdsa;
pub mod robust_ecdsa;

extern crate threshold_signatures;
use k256::AffinePoint;
use threshold_signatures::{
    ecdsa::{RerandomizationArguments, Scalar, Secp256K1Sha256, Tweak},
    participants::{Participant, ParticipantList},
    test_utils::random_32_bytes,
};

use frost_secp256k1::{Secp256K1ScalarField, VerifyingKey};
use rand_core::{CryptoRngCore, OsRng};

// Outputs pk, R, hash, participants, entropy, randomness
pub fn generate_rerandpresig_args(
    rng: &mut impl CryptoRngCore,
    participants: &[Participant],
    pk: VerifyingKey,
    big_r: AffinePoint,
) -> (RerandomizationArguments, Scalar) {
    let pk = pk.to_element().to_affine();
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));

    let msg_hash = <Secp256K1ScalarField as frost_core::Field>::random(&mut OsRng);
    let entropy = random_32_bytes(rng);
    // Generate unique ten ParticipantId values
    let participants =
        ParticipantList::new(participants).expect("Participant list generation should not fail");

    let args = RerandomizationArguments::new(
        pk,
        tweak,
        msg_hash.to_bytes().into(),
        big_r,
        participants,
        entropy,
    );
    (args, msg_hash)
}
