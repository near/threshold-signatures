use criterion::{criterion_group, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::Rng;
use rand_core::SeedableRng;

mod bench_utils;
use crate::bench_utils::{
    ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples,
    run_simulated_protocol, LATENCY, MAX_MALICIOUS, SAMPLE_SIZE,
};

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        create_rngs, run_protocol, run_protocol_and_take_snapshots, MockCryptoRng, Simulator,
    },
};

fn threshold() -> usize {
    *MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let latency = *LATENCY;
    let rounds = 8;

    let mut group = c.benchmark_group("triples");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_triples_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}_LATENCY_{latency}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_triples(num),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot, rounds),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let latency = *LATENCY;
    let rounds = 2;

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let rngs = create_rngs(num, &mut rng);
    let (protocols, _) = ot_ecdsa_prepare_triples(num, threshold(), &rngs, &mut rng);
    let two_triples = run_protocol(protocols).expect("Running triple preparations should succeed");

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}_LATENCY_{latency}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_presign(&two_triples),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot, rounds),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let latency = *LATENCY;
    let rounds = 1;

    let mut rng = MockCryptoRng::seed_from_u64(42);
    let rngs = create_rngs(num, &mut rng);
    let (protocols, _) = ot_ecdsa_prepare_triples(num, threshold(), &rngs, &mut rng);
    let two_triples = run_protocol(protocols).expect("Running triples preparation should succeed");

    let (protocols, key_packages, _) =
        ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng);
    let result = run_protocol(protocols).expect("Running presign preparation should succeed");
    let pk = key_packages[0].1.public_key;

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_sign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}_LATENCY_{latency}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&result, pk),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot, rounds),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate ot based ecdsa triples for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_triples(participant_num: usize) -> PreparedSimulatedTriples {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let rngs = create_rngs(participant_num, &mut rng);
    let (protocols, participants) =
        ot_ecdsa_prepare_triples(participant_num, threshold(), &rngs, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..participant_num);
    let real_participant = participants[index_real_participant];
    let real_protocol = generate_triple_many::<2>(
        &participants,
        real_participant,
        threshold(),
        rngs[index_real_participant].clone(),
    )
    .map(|prot| Box::new(prot) as Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>)
    .expect("The rerun of the triple generation should not but raising error");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    (real_participant, real_protocol, simulated_protocol)
}

/// Used to simulate ot based ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_presign(
    two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)],
) -> PreparedSimulatedPresig {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let (protocols, key_packages, participants) =
        ot_ecdsa_prepare_presign(two_triples, threshold(), &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    let mut rng = MockCryptoRng::seed_from_u64(41);
    // choose the real_participant at random
    let index_real_participant = rng.gen_range(0..participants_num());
    let (real_participant, keygen_out) = key_packages[index_real_participant].clone();
    let (p, shares) = &two_triples[index_real_participant];
    assert_eq!(*p, real_participant);
    let (share0, pub0) = shares[0].clone();
    let (share1, pub1) = shares[1].clone();

    let real_protocol = presign(
        &participants,
        real_participant,
        PresignArguments {
            triple0: (share0, pub0),
            triple1: (share1, pub1),
            keygen_out,
            threshold: threshold(),
        },
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presigning should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    (real_participant, real_protocol, simulated_protocol)
}

/// Used to simulate ot based ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
pub fn prepare_simulated_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
) -> PreparedSimulatedSig {
    let mut rng = MockCryptoRng::seed_from_u64(40);
    let (protocols, coordinator_index, presignature, derived_pk, msg_hash) =
        ot_ecdsa_prepare_sign(result, pk, &mut rng);
    let (_, protocolsnapshot) = run_protocol_and_take_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let (real_participant, _) = result[coordinator_index];

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();
    let real_protocol = sign(
        &participants,
        real_participant,
        real_participant,
        derived_pk,
        presignature,
        msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Simulated signing should succeed");

    // now preparing the being the coordinator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    (real_participant, real_protocol, simulated_protocol)
}

type PreparedSimulatedTriples = (
    Participant,
    Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>,
    Simulator,
);

type PreparedSimulatedPresig = (
    Participant,
    Box<dyn Protocol<Output = PresignOutput>>,
    Simulator,
);

type PreparedSimulatedSig = (
    Participant,
    Box<dyn Protocol<Output = SignatureOption>>,
    Simulator,
);
