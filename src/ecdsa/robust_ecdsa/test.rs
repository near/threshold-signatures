use std::error::Error;
use k256::Scalar;

use super::{
    presign::{presign, PresignArguments, PresignOutput},
    sign::sign,
};

use crate::protocol::{run_protocol, Participant, Protocol, InitializationError};
use crate::ecdsa::{
    test::{
        assert_public_key_invariant,
        run_keygen,
        run_reshare,
        run_sign,
    },
    KeygenOutput,
    FullSignature,
};
// TODO: The following crates need to be done away with
use crate::compat::CSCurve;

fn sign_box<C: CSCurve>(
    participants: &[Participant],
    me: Participant,
    public_key: C::AffinePoint,
    presignature: PresignOutput,
    msg_hash: Scalar,
) -> Result<Box<dyn Protocol<Output = FullSignature<C>>>, InitializationError>{
    sign(participants, me, public_key, presignature, msg_hash)
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = FullSignature<C>>>)
}

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

#[test]
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        Participant::from(4u32),
        Participant::from(5u32),
        Participant::from(6u32),
        Participant::from(7u32),
        Participant::from(8u32),
        Participant::from(9u32),
        Participant::from(10u32),
    ];
    let max_malicious = 3;
    let threshold = max_malicious+1;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0)?;

    let pub_key = result0[2].1.public_key.clone();

    // Run heavy reshare
    let max_malicious = 4;
    let new_threshold = max_malicious+1;

    let mut new_participant = participants.clone();
    new_participant.push(Participant::from(31u32));
    new_participant.push(Participant::from(32u32));
    new_participant.push(Participant::from(33u32));
    let mut key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages)?;
    key_packages.sort_by_key(|(p, _)| *p);

    let public_key = key_packages[0].1.public_key.clone();

    // Presign
    let mut presign_result =
        run_presign(key_packages, max_malicious);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg, sign_box);
    Ok(())
}

#[test]
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let participants = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
        Participant::from(3u32),
        Participant::from(4u32),
    ];
    let max_malicious = 2;
    let threshold = max_malicious+1;
    let result0 = run_keygen(&participants, threshold)?;
    assert_public_key_invariant(&result0)?;

    let pub_key = result0[2].1.public_key.clone();

    // Run heavy reshare
    let max_malicious = 1;
    let new_threshold = max_malicious+1;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let mut key_packages = run_reshare(
        &participants,
        &pub_key,
        result0,
        threshold,
        new_threshold,
        new_participant.clone(),
    )?;
    assert_public_key_invariant(&key_packages)?;
    key_packages.sort_by_key(|(p, _)| *p);

    let public_key = key_packages[0].1.public_key.clone();

    // Presign
    let mut presign_result =
        run_presign(key_packages, max_malicious);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg, sign_box);
    Ok(())
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

    run_sign(presign_result, public_key.to_element().to_affine(), msg, sign_box);
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

    run_sign(presign_result, public_key.to_element().to_affine(), msg, sign_box);
    Ok(())
}