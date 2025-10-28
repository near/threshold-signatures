mod crypto_benchmarks;
mod protocol_benchmarks;

use criterion::{criterion_group, criterion_main};
use crypto_benchmarks::{inversion, lagrange};
use protocol_benchmarks::naive_benchmarks::{ot_based_ecdsa, robust_ecdsa};

criterion_group!(
    crypto_benchmarks,
    lagrange::bench_lagrange_computation,
    lagrange::bench_inversion_vs_multiplication,
    inversion::bench_inversion,
);

criterion_group!(
    ot_based_ecdsa_naive,
    ot_based_ecdsa::bench_triples,
    ot_based_ecdsa::bench_presign,
    ot_based_ecdsa::bench_sign,
);

criterion_group!(
    robust_ecdsa_naive,
    robust_ecdsa::bench_presign,
    robust_ecdsa::bench_sign,
);

// criterion_main!(crypto_benchmarks);
criterion_main!(ot_based_ecdsa_naive, robust_ecdsa_naive);