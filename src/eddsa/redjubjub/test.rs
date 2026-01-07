use crate::test_utils::{generate_participants, MockCryptoRng};

use rand::SeedableRng;
type C = reddsa::frost::redjubjub::JubjubBlake2b512;

#[test]
fn test_keygen() {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let participants = generate_participants(3);
    let threshold = 2;
    crate::dkg::test::test_keygen::<C, _>(&participants, threshold, &mut rng);
}
