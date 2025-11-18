use criterion::{criterion_group, Criterion};
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;

mod bench_utils;
use crate::bench_utils::{robust_ecdsa_prepare_presign, MAX_MALICIOUS};

use threshold_signatures::{
    ecdsa::{
        robust_ecdsa::{
            presign::presign, sign::sign, PresignArguments, PresignOutput,
            RerandomizedPresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        create_multiple_rngs, ecdsa_generate_rerandpresig_args,
        generate_participants_with_random_ids, run_keygen, run_protocol,
        run_protocol_with_snapshots, run_simulated_protocol, Simulator,
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
    let (protocols, pk) = robust_ecdsa_prepare_presign(num, rngs);
    let mut result = run_protocol(protocols).expect("Prepare sign should not");
    result.sort_by_key(|(p, _)| *p);

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

/// Helps with the benches of the presigning protocol
type PreparedPresig = (
    Participant,
    Box<dyn Protocol<Output = PresignOutput>>,
    Simulator,
);

/// Used to simulate robust ecdsa presignatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulate_presign(num_participants: usize) -> PreparedPresig {
    let participants = generate_participants_with_random_ids(num_participants, &mut OsRng);
    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, *MAX_MALICIOUS + 1);
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    // Running presign a first time with snapshots
    let rngs = create_multiple_rngs(num_participants);
    for (i, (p, keygen_out)) in key_packages.iter().enumerate() {
        let protocol = presign(
            &participants,
            *p,
            PresignArguments {
                keygen_out: keygen_out.clone(),
                threshold: *MAX_MALICIOUS,
            },
            rngs[i].clone(),
        )
        .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
        .expect("Presignature should succeed");
        protocols.push((*p, protocol));
    }
    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // now preparing the simulator
    // choose the real_participant at random
    let index_real_participant = OsRng.gen_range(0..num_participants);
    let real_participant = participants[index_real_participant];
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    let mut real_protocol = None;
    for (p, keygen_out) in key_packages {
        if p == real_participant {
            real_protocol = Some(
                presign(
                    &participants,
                    real_participant,
                    PresignArguments {
                        keygen_out,
                        threshold: *MAX_MALICIOUS,
                    },
                    rngs[index_real_participant].clone(), // provide the exact same randomness
                )
                .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
                .expect("Presignature should succeed"),
            );
        }
    }
    let real_protocol =
        real_protocol.expect("The real participant should also be included in the protocol");
    (real_participant, real_protocol, simulated_protocol)
}

/// Helps with the benches of the signing protocol
type PreparedSimulatedSig = (
    Participant,
    Box<dyn Protocol<Output = SignatureOption>>,
    Simulator,
);
/// Used to simulate robust ecdsa signatures for benchmarking
/// # Panics
/// Would panic in case an abort happens stopping the entire benchmarking
fn prepare_simulated_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
) -> PreparedSimulatedSig {
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
                RerandomizedPresignOutput::rerandomize_presign(presig, &args)
                    .expect("Rerandomizing presignature should succeed"),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result.clone() {
        let protocol = sign(
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

    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // now preparing the simulator
    // choose the real_participant being the coordinator
    let real_participant = coordinator;
    let simulated_protocol =
        Simulator::new(real_participant, protocolsnapshot).expect("Simulator should not be empty");
    let mut real_protocol = None;
    for (p, presignature) in result {
        if p == real_participant {
            real_protocol = Some(
                sign(
                    args.participants.participants(),
                    coordinator,
                    p,
                    derived_pk,
                    presignature,
                    msg_hash,
                )
                .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
                .expect("Presignature should succeed"),
            );
        }
    }
    let real_protocol =
        real_protocol.expect("The real participant should also be included in the protocol");
    (real_participant, real_protocol, simulated_protocol)
}

criterion_group!(benches, bench_presign, bench_sign);
criterion::criterion_main!(benches);
