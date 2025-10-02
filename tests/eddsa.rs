mod common;

use common::{generate_participants, run_keygen};

use rand::Rng;
use rand_core::{OsRng, RngCore};

use threshold_signatures::{
    self,
    eddsa::{sign::sign, Ed25519Sha512, SignatureOption},
    protocol::{run_protocol, Participant, Protocol},
    ParticipantList,
};

type C = Ed25519Sha512;
type KeygenOutput = threshold_signatures::KeygenOutput<C>;

fn run_sign(
    participants: &[(Participant, KeygenOutput)],
    coordinators: &[Participant],
    threshold: usize,
    msg_hash: [u8; 32],
) -> Vec<(Participant, SignatureOption)> {
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(participants.len());

    let participants_list = participants.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    let coordinators = ParticipantList::new(coordinators).unwrap();
    for (participant, key_pair) in participants {
        let protocol = if coordinators.contains(*participant) {
            let protocol = sign(
                &participants_list,
                threshold,
                *participant,
                *participant,
                key_pair.clone(),
                msg_hash.as_ref().to_vec(),
                OsRng,
            )
            .unwrap();
            Box::new(protocol)
        } else {
            // pick any coordinator
            let mut rng = OsRng;
            let index = rng.next_u32() as usize % coordinators.len();
            let coordinator = coordinators.get_participant(index).unwrap();
            // run the signing scheme
            let protocol = sign(
                &participants_list,
                threshold,
                *participant,
                coordinator,
                key_pair.clone(),
                msg_hash.as_ref().to_vec(),
                OsRng,
            )
            .unwrap();
            Box::new(protocol)
        };
        protocols.push((*participant, protocol));
    }

    run_protocol(protocols).unwrap()
}

#[test]
fn test_sign() {
    let participants = generate_participants(11);
    let max_malicious = 5;
    let threshold = max_malicious + 1;
    let keys = run_keygen::<C>(&participants, threshold);
    assert_eq!(keys.len(), participants.len());
    let public_key = keys.get(&participants[0]).unwrap().public_key;

    let msg_hash = *b"hello worldhello worldhello worl";
    // choose a coordinator at random
    let index = rand::rngs::OsRng.gen_range(0..participants.len());
    let coordinator = participants[index];
    let participants = keys.into_iter().collect::<Vec<_>>();
    let all_sigs = run_sign(participants.as_slice(), &[coordinator], threshold, msg_hash);

    let signature = all_sigs
        .into_iter()
        .filter(|(p, sig)| *p == coordinator && sig.is_some())
        .collect::<Vec<_>>()
        .first()
        .unwrap()
        .1
        .unwrap();

    assert!(public_key.verify(&msg_hash, &signature).is_ok());
}
