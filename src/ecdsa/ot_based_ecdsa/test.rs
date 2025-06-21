use rand_core::OsRng;
use super::presign::{presign, PresignArguments, PresignOutput};
use super::triples::{self, TriplePub, TripleShare};

pub fn run_presign(
    participants: Vec<(Participant, KeygenOutput)>,
    shares0: Vec<TripleShare<Secp256k1>>,
    shares1: Vec<TripleShare<Secp256k1>>,
    pub0: &TriplePub<Secp256k1>,
    pub1: &TriplePub<Secp256k1>,
    threshold: usize,
) -> Vec<(Participant, PresignOutput<Secp256k1>)> {
    assert!(participants.len() == shares0.len());
    assert!(participants.len() == shares1.len());

    #[allow(clippy::type_complexity)]
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = PresignOutput<Secp256k1>>>,
    )> = Vec::with_capacity(participants.len());

    let participant_list: Vec<Participant> = participants.iter().map(|(p, _)| *p).collect();

    for (((p, keygen_out), share0), share1) in participants
        .into_iter()
        .zip(shares0.into_iter())
        .zip(shares1.into_iter())
    {
        let protocol = presign(
            &participant_list,
            p,
            &participant_list,
            p,
            PresignArguments {
                triple0: (share0, pub0.clone()),
                triple1: (share1, pub1.clone()),
                keygen_out,
                threshold,
            },
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
    ];
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key.clone();
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, threshold);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, threshold);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}

#[test]
fn test_e2e_random_identifiers() -> Result<(), Box<dyn Error>> {
    let participants_count = 3;
    let mut participants: Vec<_> = (0..participants_count)
        .map(|_| Participant::from(rand::random::<u32>()))
        .collect();
    participants.sort();
    let threshold = 3;

    let mut keygen_result = run_keygen(&participants.clone(), threshold)?;
    keygen_result.sort_by_key(|(p, _)| *p);

    let public_key = keygen_result[0].1.public_key.clone();
    assert_eq!(keygen_result[0].1.public_key, keygen_result[1].1.public_key);
    assert_eq!(keygen_result[1].1.public_key, keygen_result[2].1.public_key);

    let (pub0, shares0) = triples::deal(&mut OsRng, &participants, threshold);
    let (pub1, shares1) = triples::deal(&mut OsRng, &participants, threshold);

    let mut presign_result = run_presign(keygen_result, shares0, shares1, &pub0, &pub1, threshold);
    presign_result.sort_by_key(|(p, _)| *p);

    let msg = b"hello world";

    run_sign(presign_result, public_key.to_element().to_affine(), msg);
    Ok(())
}
