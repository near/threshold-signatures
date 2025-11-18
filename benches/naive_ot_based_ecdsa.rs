use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{
    ot_ecdsa_prepare_presign, ot_ecdsa_prepare_sign, ot_ecdsa_prepare_triples, MAX_MALICIOUS,
};
use threshold_signatures::test_utils::{create_multiple_rngs, run_protocol};

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
    let mut group = c.benchmark_group("triples");
    group.measurement_time(std::time::Duration::from_secs(200));

    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let rngs = create_multiple_rngs(num);
                    ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs)
                },
                run_protocol,
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let rngs = create_multiple_rngs(num);
    let protocols = ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs);
    let two_triples = run_protocol(protocols).expect("Running triple preparations should succeed");

    group.bench_function(
        format!("ot_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_presign(&two_triples, threshold()),
                |(protocols, ..)| run_protocol(protocols),
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
    let protocols = ot_ecdsa_prepare_triples(participants_num(), threshold(), &rngs);
    let two_triples = run_protocol(protocols).expect("Running triples preparation should succeed");

    let (protocols, key_packages, _) = ot_ecdsa_prepare_presign(&two_triples, threshold());
    let pk = key_packages[0].1.public_key;
    let result = run_protocol(protocols).expect("Running presign preparation should succeed");

    group.bench_function(
        format!("ot_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || ot_ecdsa_prepare_sign(&result, pk),
                |(protocols, ..)| run_protocol(protocols),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);
