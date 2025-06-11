use k256::{AffinePoint, Secp256k1};
use std::error::Error;

use crate::compat::scalar_hash;

use super::{
    presign::{presign, PresignArguments, PresignOutput},
    sign::sign,
};

use crate::protocol::{run_protocol, Participant, Protocol};
use crate::ecdsa::{
    test::run_keygen,
    KeygenOutput,
    sign::FullSignature,
};

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    max_malicious: usize,
) -> Vec<(Participant, PresignOutput)> {

    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, keygen_out) in participants.into_iter() {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                threshold: max_malicious,
            },
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[allow(clippy::type_complexity)]
pub fn run_sign(
    participants: Vec<(Participant, PresignOutput)>,
    public_key: AffinePoint,
    msg: &[u8],
) -> Vec<(Participant, FullSignature<Secp256k1>)> {
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = FullSignature<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, presign_out) in participants.into_iter() {
        let protocol = sign(
            &participant_list,
            p,
            public_key,
            presign_out,
            scalar_hash(msg),
        );
        assert!(protocol.is_ok());
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        Participant::from(4u32),
        Participant::from(5u32),
        Participant::from(6u32),
        Participant::from(7u32),
    ];
    let max_malicious = 3;

    let mut keygen_result = run_keygen(&participants.clone(), max_malicious+1)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key.clone();
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let mut presign_result = run_presign(keygen_result, max_malicious);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 7;
    let mut participants: Vec<_> = (0..participants_count)
        .map(|_| Participant::from(rand::random::<u32>()))
        .collect();
    participants.sort();
    let max_malicious = 3;

    let mut keygen_result = run_keygen(&participants.clone(), max_malicious+1)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key.clone();
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let mut presign_result = run_presign(keygen_result, max_malicious);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}
