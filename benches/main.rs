mod crypto_benchmarks;
mod protocol_benchmarks;

use criterion::{criterion_group, criterion_main};
use crypto_benchmarks::{inversion, lagrange};

criterion_group!(
    crypto_benchmarks,
    lagrange::bench_lagrange_computation,
    lagrange::bench_inversion_vs_multiplication,
    inversion::bench_inversion,
);

criterion_main!(crypto_benchmarks);
