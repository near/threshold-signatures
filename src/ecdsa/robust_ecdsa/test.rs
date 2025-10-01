use std::error::Error;

use super::{presign::presign, sign::sign, PresignArguments, PresignOutput};

use crate::crypto::hash::test::scalar_hash_secp256k1;
use crate::ecdsa::robust_ecdsa::RerandomizedPresignOutput;
use crate::ecdsa::{
    Element, KeygenOutput, ParticipantList, RerandomizationArguments, Secp256K1Sha256, Signature,
    SignatureOption, Tweak,
};
use crate::protocol::{run_protocol, Participant, Protocol};
use crate::test::{
    assert_public_key_invariant, generate_participants, generate_participants_with_random_ids,
    one_coordinator_output, run_keygen, run_refresh, run_reshare,
};
use crate::threshold::Scheme;

use rand_core::{OsRng, RngCore};

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing does not rerandomize the presignatures and tests only the core protocol
pub fn run_sign_without_rerandomization(
    participants_presign: Vec<(Participant, PresignOutput)>,
    public_key: Element,
    msg: &[u8],
) -> Result<(Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // choose a coordinator at random
    let index = OsRng.next_u32() % participants_presign.len() as u32;
    let coordinator = participants_presign[index as usize].0;

    // run sign instanciation with the necessary arguments
    let result = crate::test::run_sign::<Secp256K1Sha256, _, _, _>(
        participants_presign,
        coordinator,
        public_key,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            let rerand_presig =
                RerandomizedPresignOutput::new_without_rerandomization(&presignature);
            sign(participants, coordinator, me, pk, rerand_presig, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;
    // test one single some for the coordinator
    let signature = one_coordinator_output(result, coordinator)?;

    Ok((coordinator, signature))
}

/// Runs signing by calling the generic `run_sign` function from `crate::test`
/// This signing mimics what should happen in real world, i.e.,
/// rerandomizing the presignatures
pub fn run_sign_with_rerandomization(
    participants_presign: &[(Participant, PresignOutput)],
    public_key: Element,
    msg: &[u8],
) -> Result<(Tweak, Participant, Signature), Box<dyn Error>> {
    // hash the message into secp256k1 field
    let msg_hash = scalar_hash_secp256k1(msg);

    // generate a random tweak
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));
    // generate a random public entropy
    let mut entropy: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let pk = public_key.to_affine();
    let big_r = participants_presign[0].1.big_r;
    let participants = ParticipantList::new(
        &participants_presign
            .iter()
            .map(|(p, _)| *p)
            .collect::<Vec<Participant>>(),
    )
    .unwrap();
    let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();
    let rerand_args =
        RerandomizationArguments::new(pk, msg_hash_bytes, big_r, participants, entropy);
    let public_key = frost_core::VerifyingKey::new(public_key);
    let derived_pk = tweak.derive_verifying_key(&public_key).to_element();

    let rerand_participants_presign = participants_presign
        .iter()
        .map(|(p, presig)| {
            RerandomizedPresignOutput::rerandomize_presign(presig, &tweak, &rerand_args)
                .map(|out| (*p, out))
        })
        .collect::<Result<_, _>>()?;

    // choose a coordinator at random
    let index = OsRng.next_u32() % participants_presign.len() as u32;
    let coordinator = participants_presign[index as usize].0;

    // run sign instanciation with the necessary arguments
    let result = crate::test::run_sign::<Secp256K1Sha256, _, _, _>(
        rerand_participants_presign,
        coordinator,
        derived_pk,
        msg_hash,
        |participants, coordinator, me, pk, presignature, msg_hash| {
            let pk = pk.to_affine();
            sign(participants, coordinator, me, pk, presignature, msg_hash)
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        },
    )?;
    // test one single some for the coordinator
    let signature = one_coordinator_output(result, coordinator)?;
    Ok((tweak, coordinator, signature))
}

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    max_malicious: usize,
) -> Result<Vec<(Participant, PresignOutput)>, Box<dyn Error>> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (p, keygen_out) in participants {
        let protocol = presign(
            &participant_list,
            p,
            PresignArguments {
                keygen_out,
                threshold: max_malicious,
            },
            OsRng,
        )?;
        protocols.push((p, Box::new(protocol)));
    }

    let mut result = run_protocol(protocols)?;
    result.sort_by_key(|(p, _)| *p);
    Ok(result)
}

#[test]
fn test_refresh() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious;
    let keys = run_keygen(Scheme::RobustEcdsa, &participants, threshold)?;
    assert_public_key_invariant(&keys);
    // run refresh on these
    let key_packages = run_refresh(Scheme::RobustEcdsa, &participants, &keys, threshold)?;
    let public_key = key_packages[0].1.public_key;
    assert_public_key_invariant(&key_packages);
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";
    run_sign_without_rerandomization(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
/// Tests the resharing protocol when more participants are added to the pool
fn test_reshare_sign_more_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(11);

    let max_malicious = 3;
    let threshold = max_malicious + 1;
    let result0 = run_keygen(Scheme::RobustEcdsa, &participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 4;
    let new_threshold = max_malicious + 1;

    let mut new_participant = participants.clone();
    new_participant.push(Participant::from(31u32));
    new_participant.push(Participant::from(32u32));
    new_participant.push(Participant::from(33u32));
    let key_packages = run_reshare(
        Scheme::RobustEcdsa,
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
    )?;
    assert_public_key_invariant(&key_packages);

    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";
    run_sign_without_rerandomization(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
/// Tests the resharing protocol when participants are kicked out of the pool
fn test_reshare_sign_less_participants() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(5);

    let max_malicious = 2;
    let threshold = max_malicious;
    let result0 = run_keygen(Scheme::RobustEcdsa, &participants, threshold)?;
    assert_public_key_invariant(&result0);

    let pub_key = result0[2].1.public_key;

    // Run heavy reshare
    let max_malicious = 1;
    let new_threshold = max_malicious + 1;
    let mut new_participant = participants.clone();
    new_participant.pop();
    let key_packages = run_reshare(
        Scheme::RobustEcdsa,
        &participants,
        &pub_key,
        &result0,
        threshold,
        new_threshold,
        &new_participant,
    )?;
    assert_public_key_invariant(&key_packages);
    let public_key = key_packages[0].1.public_key;
    // Presign
    let presign_result = run_presign(key_packages, max_malicious)?;

    let msg = b"hello world";
    run_sign_without_rerandomization(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e() -> Result<(), Box<dyn Error>> {
    let participants = generate_participants(8);
    let max_malicious = 3; //f

    let keygen_result = run_keygen(Scheme::RobustEcdsa, &participants, max_malicious)?;

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious)?;

    let msg = b"hello world";
    run_sign_without_rerandomization(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut OsRng);
    let max_malicious = 3;

    let keygen_result = run_keygen(Scheme::RobustEcdsa, &participants, max_malicious)?;
    assert_public_key_invariant(&keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious)?;

    let msg = b"hello world";
    run_sign_without_rerandomization(presign_result, public_key.to_element(), msg)?;
    Ok(())
}

#[test]
fn test_e2e_random_identifiers_with_rerandomization() -> Result<(), Box<dyn Error>> {
    let participants_count = 7;
    let participants = generate_participants_with_random_ids(participants_count, &mut OsRng);
    let max_malicious = 3;

    let keygen_result = run_keygen(Scheme::RobustEcdsa, &participants, max_malicious)?;
    assert_public_key_invariant(&keygen_result);

    let public_key = keygen_result[0].1.public_key;
    assert_public_key_invariant(&keygen_result);
    let presign_result = run_presign(keygen_result, max_malicious)?;

    let msg = b"hello world";
    run_sign_with_rerandomization(&presign_result, public_key.to_element(), msg)?;
    Ok(())
}
