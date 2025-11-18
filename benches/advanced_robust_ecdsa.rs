use criterion::{criterion_group, Criterion};
use frost_secp256k1::VerifyingKey;
use rand::Rng;
use rand_core::OsRng;

mod bench_utils;
use crate::bench_utils::{robust_ecdsa_prepare_presign, robust_ecdsa_prepare_sign, MAX_MALICIOUS};

use threshold_signatures::{
    ecdsa::{
        robust_ecdsa::{presign::presign, sign::sign, PresignArguments, PresignOutput},
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        create_multiple_rngs, run_protocol, run_protocol_with_snapshots, run_simulated_protocol,
        Simulator,
    },
};

fn participants_num() -> usize {
    2 * *MAX_MALICIOUS + 1
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));
    group.bench_function(
        format!("robust_ecdsa_presign_advanced_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulate_presign(num),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("sign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let rngs = create_multiple_rngs(num);
    let (protocols, key_packages, _) = robust_ecdsa_prepare_presign(num, &rngs);
    let result = run_protocol(protocols).expect("Prepare sign should not");
    let pk = key_packages[0].1.public_key;

    group.bench_function(
        format!("robust_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_sign(&result, pk),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_presign, bench_sign);
criterion::criterion_main!(benches);

/****************************** Helpers ******************************/
/// Used to simulate robust ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulate_presign(num_participants: usize) -> PreparedPresig {
    // Running presign a first time with snapshots
    let rngs = create_multiple_rngs(num_participants);
    let (protocols, key_packages, participants) =
        robust_ecdsa_prepare_presign(num_participants, &rngs);

    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // choose the real_participant at random
    let index_real_participant = OsRng.gen_range(0..num_participants);
    let (real_participant, keygen_out) = key_packages[index_real_participant].clone();
    let real_protocol = presign(
        &participants,
        real_participant,
        PresignArguments {
            keygen_out,
            threshold: *MAX_MALICIOUS,
        },
        rngs[index_real_participant].clone(), // provide the exact same randomness
    )
    .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
    .expect("Presignature should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    (real_participant, real_protocol, simulated_protocol)
}

/// Used to simulate robust ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
) -> PreparedSimulatedSig {
    let (protocols, coordinator_index, presignature, derived_pk, msg_hash) =
        robust_ecdsa_prepare_sign(result, pk);
    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // collect all participants
    let participants: Vec<Participant> =
        result.iter().map(|(participant, _)| *participant).collect();
    // choose the real_participant being the coordinator
    let (real_participant, _) = result[coordinator_index];
    let real_protocol = sign(
        &participants,
        real_participant,
        real_participant,
        derived_pk,
        presignature,
        msg_hash,
    )
    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
    .expect("Presignature should succeed");

    // now preparing the simulator
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");

    (real_participant, real_protocol, simulated_protocol)
}

/// Helps with the benches of the presigning protocol
type PreparedPresig = (
    Participant,
    Box<dyn Protocol<Output = PresignOutput>>,
    Simulator,
);

/// Helps with the benches of the signing protocol
type PreparedSimulatedSig = (
    Participant,
    Box<dyn Protocol<Output = SignatureOption>>,
    Simulator,
);
