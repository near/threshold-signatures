use criterion::Criterion;
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use rand_core::OsRng;
use rand::Rng;
use crate::protocol_benchmarks::naive_benchmarks::generate_rerandpresig_args;

extern crate threshold_signatures;
use threshold_signatures::{
    test::{run_keygen, run_protocol, generate_participants_with_random_ids},
    ecdsa::SignatureOption,
    ecdsa::robust_ecdsa::{
        presign::presign,
        sign::sign,
        PresignArguments, PresignOutput, RerandomizedPresignOutput,
    },
    protocol::Protocol,
    participants::Participant,
};

const MAX_MALICIOUS: usize = 6;
const PARTICIPANTS_NUM: usize = 13;

/// Benches the presigning protocol
pub fn bench_presign(c: &mut Criterion) {
    let mut group = c.benchmark_group(
        &format!(
            "Presign Robust ECDSA: {} malicious parties and {} participating parties",
            MAX_MALICIOUS,
            PARTICIPANTS_NUM
        )
    );
    group.measurement_time(std::time::Duration::from_secs(300));

    group.bench_function("Presignature generation", |b| {
        b.iter_batched(||
            prepare_presign(PARTICIPANTS_NUM),
            |(protocols, _)| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
            );
        });
}

/// Benches the signing protocol
pub fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group(
        &format!(
            "Sign Robust ECDSA: {} malicious parties and {} participating parties",
            MAX_MALICIOUS,
            PARTICIPANTS_NUM
        )
    );
    group.measurement_time(std::time::Duration::from_secs(300));

    let (protocols, pk) = prepare_presign(PARTICIPANTS_NUM);
    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);

    group.bench_function("Signature generation", |b| {
        b.iter_batched(||
            prepare_sign(&result, pk),
            |protocols| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
        );
    });
}

/// Benches the presigning protocol
fn prepare_presign(num_participants: usize) -> (Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>, VerifyingKey){
    let participants = generate_participants_with_random_ids(num_participants, &mut OsRng);
    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, MAX_MALICIOUS + 1);
    let pk = key_packages[0].1.public_key.clone();
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
            Vec::with_capacity(participants.len());

    for (p, keygen_out) in key_packages {
            let protocol = presign(
                &participants,
                p,
                PresignArguments {
                    keygen_out,
                    threshold: MAX_MALICIOUS,
                },
                OsRng,
            ).unwrap();
            protocols.push((p, Box::new(protocol)));
        }
        (protocols, pk)
}

fn prepare_sign(
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
)-> Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)>{

    // To collect all participants:
    let participants: Vec<Participant> = result.iter()
    .map(|(participant, _)| participant.clone()) // or `.copied()` if `Participant: Copy`
    .collect();

    // choose a coordinator at random
    let index = OsRng.gen_range(0..result.len());
    let coordinator = result[index].0;

    let (args, msg_hash) = generate_rerandpresig_args(&mut OsRng, participants, pk);
    let derived_pk = args.tweak.derive_verifying_key(&pk).to_element().to_affine();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (   *p,
                RerandomizedPresignOutput::rerandomize_presign(presig, &args).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result {
        let protocol = sign(
            args.participants.participants(),
            coordinator,
            p,
            derived_pk,
            presignature,
            msg_hash,
        ).map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .unwrap();
        protocols.push((p, protocol));
    }
    protocols
}