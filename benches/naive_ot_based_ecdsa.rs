use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{
    ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples, LATENCY,
    MAX_MALICIOUS, SAMPLE_SIZE,
};
use rand_core::SeedableRng;
use threshold_signatures::test_utils::{create_rngs, run_protocol, MockCryptoRng};

fn threshold() -> usize {
    *MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let latency = *LATENCY;
    let max_malicious = *MAX_MALICIOUS;

    let mut group = c.benchmark_group("triples");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}_LATENCY_{latency}"),
        |b| {
            b.iter_batched(
                || {
                    let rngs = create_rngs(num, &mut rng);
                    ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs, &mut rng)
                },
                |(protocols, _)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let latency = *LATENCY;
    let max_malicious = *MAX_MALICIOUS;

    let rngs = create_rngs(num, &mut rng);
    let (protocols, _) = ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs, &mut rng);
    let two_triples = run_protocol(protocols).expect("Running triple preparations should succeed");

    let mut group = c.benchmark_group("presign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}_LATENCY_{latency}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng),
                |(protocols, ..)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the signing protocol
fn bench_sign(c: &mut Criterion) {
    let mut rng = MockCryptoRng::seed_from_u64(42);
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;

    let rngs = create_rngs(num, &mut rng);
    let (protocols, _) = ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs, &mut rng);
    let two_triples = run_protocol(protocols).expect("Running triples preparation should succeed");

    let (protocols, key_packages, _) =
        ot_ecdsa_prepare_presign(&two_triples, threshold(), &mut rng);
    let pk = key_packages[0].1.public_key;
    let result = run_protocol(protocols).expect("Running presign preparation should succeed");

    let mut group = c.benchmark_group("sign");
    group.sample_size(*SAMPLE_SIZE);
    group.bench_function(
        format!("ot_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_sign(&result, pk, &mut rng),
                |(protocols, ..)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);
