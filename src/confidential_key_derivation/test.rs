type C = crate::confidential_key_derivation::ciphersuite::BLS12381SHA256;

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
