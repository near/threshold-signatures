#![allow(dead_code)]
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use k256::AffinePoint;
use rand::Rng;
use rand_core::{CryptoRngCore, OsRng};

use threshold_signatures::{
    ecdsa::ot_based_ecdsa,
    ecdsa::robust_ecdsa,
    ecdsa::{
        ot_based_ecdsa::triples::{generate_triple_many, TriplePub, TripleShare},
        KeygenOutput, Scalar, SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
    },
};

use std::{env, sync::LazyLock};

// fix malicious number of participants
pub static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

/********************* OT Based ECDSA *********************/
type OTECDSAPreparedTriples = Vec<(
    Participant,
    Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>,
)>;

/// Used to prepare ot based ecdsa triples for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn ot_ecdsa_prepare_triples(
    participant_num: usize,
    threshold: usize,
) -> OTECDSAPreparedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let participants = generate_participants_with_random_ids(participant_num, &mut OsRng);

    for p in participants.clone() {
        let protocol = generate_triple_many::<2>(&participants, p, threshold, OsRng)
            .expect("Triple generation should succeed");
        protocols.push((p, Box::new(protocol)));
    }
    protocols
}

type OTECDSAPreparedPresig = (
    Vec<(
        Participant,
        Box<dyn Protocol<Output = ot_based_ecdsa::PresignOutput>>,
    )>,
    VerifyingKey,
);

/// Used to prepare ot based ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn ot_ecdsa_prepare_presign(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
    threshold: usize,
) -> OTECDSAPreparedPresig {
    let mut two_triples = two_triples.to_owned();
    two_triples.sort_by_key(|(p, _)| *p);

    // collect all participants
    let participants: Vec<Participant> = two_triples
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, threshold);
    let pk = key_packages[0].1.public_key;

    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = ot_based_ecdsa::PresignOutput>>,
    )> = Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in key_packages.into_iter().zip(shares0).zip(shares1) {
        let protocol = ot_based_ecdsa::presign::presign(
            &participants,
            p,
            ot_based_ecdsa::PresignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out,
                threshold,
            },
        )
        .expect("Presigning should succeed");
        protocols.push((p, Box::new(protocol)));
    }
    (protocols, pk)
}

/// Used to prepare ot based ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn ot_ecdsa_prepare_sign(
    result: &[(Participant, ot_based_ecdsa::PresignOutput)],
    pk: VerifyingKey,
) -> Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let index = OsRng.gen_range(0..result.len());
    let coordinator = result[index].0;

    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(&mut OsRng, &participants, pk, result[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                ot_based_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result {
        let protocol = ot_based_ecdsa::sign::sign(
            args.participants.participants(),
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    protocols
}

pub fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i % 2 == 0 {
            even.push(x);
        } else {
            odd.push(x);
        }
    }
    (even, odd)
}

/********************* Robust ECDSA *********************/
/// Used to prepare robust ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn robust_ecdsa_prepare_presign(
    num_participants: usize,
    rngs: &[impl CryptoRngCore + Send + Clone + 'static],
) -> RobustECDSAPreparedPresig {
    assert_eq!(
        rngs.len(),
        num_participants,
        "There must be enought Rngs as participants"
    );

    let participants = generate_participants_with_random_ids(num_participants, &mut OsRng);
    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, *MAX_MALICIOUS + 1);
    let mut protocols: Vec<(
        Participant,
        Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>,
    )> = Vec::with_capacity(participants.len());

    for (i, (p, keygen_out)) in key_packages.iter().enumerate() {
        let protocol = robust_ecdsa::presign::presign(
            &participants,
            *p,
            robust_ecdsa::PresignArguments {
                keygen_out: keygen_out.clone(),
                threshold: *MAX_MALICIOUS,
            },
            rngs[i].clone(),
        )
        .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>)
        .expect("Presignature should succeed");
        protocols.push((*p, protocol));
    }
    (protocols, key_packages, participants)
}

/// Used to prepare robust ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn robust_ecdsa_prepare_sign(
    result: &[(Participant, robust_ecdsa::PresignOutput)],
    pk: VerifyingKey,
) -> RobustECDSASig {
    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();

    // choose a coordinator at random
    let coordinator_index = OsRng.gen_range(0..result.len());
    let coordinator = result[coordinator_index].0;

    let (args, msg_hash) =
        ecdsa_generate_rerandpresig_args(&mut OsRng, &participants, pk, result[0].1.big_r);
    let derived_pk = args
        .tweak
        .derive_verifying_key(&pk)
        .to_element()
        .to_affine();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (
                *p,
                robust_ecdsa::RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = robust_ecdsa::sign::sign(
            &participants,
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        )
        .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .expect("Signing should succeed");
        protocols.push((p, protocol));
    }
    (
        protocols,
        coordinator_index,
        result[coordinator_index].1.clone(),
        derived_pk,
        msg_hash,
    )
}

/// Benches the presigning protocol
type RobustECDSAPreparedPresig = (
    Vec<(
        Participant,
        Box<dyn Protocol<Output = robust_ecdsa::PresignOutput>>,
    )>,
    Vec<(Participant, KeygenOutput)>,
    Vec<Participant>,
);
/// Benches the presigning protocol
type RobustECDSASig = (
    Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)>,
    usize,
    robust_ecdsa::RerandomizedPresignOutput,
    AffinePoint,
    Scalar,
);
