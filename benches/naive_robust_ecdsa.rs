use criterion::{criterion_group, Criterion};
mod bench_utils;
use crate::bench_utils::{robust_ecdsa_prepare_presign, robust_ecdsa_prepare_sign, MAX_MALICIOUS};
use threshold_signatures::test_utils::{
    create_multiple_rngs,
    run_protocol
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
        format!("robust_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || {
                    let rngs = create_multiple_rngs(num);
                    robust_ecdsa_prepare_presign(num, rngs)
                    },
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

    let rngs = create_multiple_rngs(num);
    let (protocols, pk) = robust_ecdsa_prepare_presign(num, rngs);
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
