type C = frost_secp256k1::Secp256K1Sha256;

use std::error::Error;

#[test]
fn test_keygen() -> Result<(), Box<dyn Error>> {
    crate::dkg::test::test_keygen::<C>()
}

#[test]
fn test_refresh() -> Result<(), Box<dyn Error>> {
    crate::dkg::test::test_refresh::<C>()
}

#[test]
fn test_reshare() -> Result<(), Box<dyn Error>> {
    crate::dkg::test::test_reshare::<C>()
}
