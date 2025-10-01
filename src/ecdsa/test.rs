type C = frost_secp256k1::Secp256K1Sha256;

use crate::test::generate_participants;
use crate::Participant;

#[test]
fn test_keygen() {
    let participants = vec![
        Participant::from(31u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let threshold = 2;
    crate::dkg::test::test_keygen::<C>(participants, threshold);
}

#[test]
fn test_refresh() {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(31u32),
        Participant::from(2u32),
    ];
    let threshold = 2;
    crate::dkg::test::test_refresh::<C>(participants, threshold);
}

#[test]
fn test_reshare() {
    let participants = generate_participants(3);
    let threshold0 = 2;
    let threshold1 = 3;
    crate::dkg::test::test_reshare::<C>(participants, threshold0, threshold1)
}
