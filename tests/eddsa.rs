#![allow(clippy::unwrap_used)]
mod common;

use common::{
    choose_coordinator_at_random, generate_participants, run_keygen, run_protocol, run_reshare,
    GenProtocol,
};

use threshold_signatures::{
    self, frost::eddsa::{sign::sign, PresignOutput, Ed25519Sha512, SignatureOption}, participants::Participant, test_utils::frost_run_presignature, ReconstructionLowerBound
};

type C = Ed25519Sha512;
type KeygenOutput = threshold_signatures::KeygenOutput<C>;


fn run_sign(
    threshold: ReconstructionLowerBound,
    participants: &[(Participant, KeygenOutput)],
    coordinator: Participant,
    presig: Vec<(Participant, PresignOutput)>,
    msg_hash: &[u8],
) -> Vec<(Participant, SignatureOption)> {   
    let mut protocols: GenProtocol<SignatureOption> = Vec::with_capacity(participants.len());

    let participants_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();
    for ((p, keygen_output), (participant_redundancy, presignature)) in
        participants.iter().zip(presig.iter()){
        assert_eq!(p, participant_redundancy);
        let protocol = sign(
            &participants_list,
            threshold,
            *p,
            coordinator,
            keygen_output.clone(),
            presignature.clone(),
            msg_hash.to_vec(),
        )
        .unwrap();

        protocols.push((*p, Box::new(protocol)));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_run_presign() {
    let participants = generate_participants(5);
    let threshold = 4;
    let actual_signers = 4;
    let keys = run_keygen::<C>(&participants, threshold.into());
    let presign = frost_run_presignature(&keys, threshold, actual_signers).unwrap();
    for (i, (p1, presig1)) in presign.iter().enumerate() {
        for (p2, presig2) in presign.iter().skip(i + 1) {
            assert_ne!(p1, p2);
            assert_ne!(presig1.nonces, presig2.nonces);
            assert_eq!(presig1.commitments_map, presig2.commitments_map);
        }
    }
}

#[test]
fn test_sign() {
    let participants = generate_participants(5);
    let threshold = 4;
    let actual_signers = 4;
    let keys = run_keygen::<C>(&participants, threshold.into());
    assert_eq!(keys.len(), participants.len());
    let public_key = keys[0].1.public_key;

    let msg_hash = *b"hello worldhello worldhello worlregerghwhrth";
    let coordinator = choose_coordinator_at_random(&participants);
    let presign = frost_run_presignature(&keys, threshold, actual_signers).unwrap();
    let participant_keys = keys.into_iter().collect::<Vec<_>>();
    
    let all_sigs = run_sign(
        threshold.into(),
        participant_keys.as_slice(),
        coordinator,
        presign,
        &msg_hash,
    );

    let signature = all_sigs
        .into_iter()
        .filter(|(p, sig)| *p == coordinator && sig.is_some())
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .1
        .unwrap();

    assert!(public_key.verify(&msg_hash, &signature).is_ok());

    let mut new_participants = participants.clone();
    new_participants.push(Participant::from(20u32));
    let new_threshold = 5;

    let new_keys = run_reshare(
        &participants,
        &public_key,
        participant_keys.as_slice(),
        threshold.into(),
        new_threshold.into(),
        &new_participants,
    );
    let new_public_key = new_keys.get(&participants[0]).unwrap().public_key;

    assert_eq!(public_key, new_public_key);
}
