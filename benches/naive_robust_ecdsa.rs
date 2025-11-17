use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS,
    robust_ecdsa_prepare_sign,
    robust_ecdsa_prepare_presign
};
use threshold_signatures::test_utils::run_protocol;

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
        format!("robust_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || robust_ecdsa_prepare_presign(participants_num()),
                |(protocols, _)| run_protocol(protocols),
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

    let (protocols, pk) = robust_ecdsa_prepare_presign(participants_num());
    let mut result = run_protocol(protocols).expect("Prepare sign should not");
    result.sort_by_key(|(p, _)| *p);

    group.bench_function(
        format!("robust_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || robust_ecdsa_prepare_sign(&result, pk),
                run_protocol,
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

criterion_group!(benches, bench_presign, bench_sign);
criterion::criterion_main!(benches);
