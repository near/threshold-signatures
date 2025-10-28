use criterion::{criterion_group, criterion_main, Criterion};
use std::env;

mod crypto_benchmarks;
mod protocol_benchmarks;

use crypto_benchmarks::{inversion, lagrange};
use protocol_benchmarks::naive_benchmarks::{ot_based_ecdsa, robust_ecdsa};

/// Can be ran using:
/// BENCH=<option> cargo bench --features benchmarking
/// Example: BENCH=crypto cargo bench --features benchmarking
fn choose_benchmark(c: &mut Criterion) {
    let group = env::var("BENCH").ok().unwrap_or("none".to_string());

    // Crypto benchmarks
    if matches!(group.as_str(), "crypto" | "all") {
        lagrange::bench_lagrange_computation(c);
        lagrange::bench_inversion_vs_multiplication(c);
        inversion::bench_inversion(c);
    }

    // OT-based ECDSA benchmarks
    if matches!(group.as_str(), "naive_ot_ecdsa" | "all") {
        ot_based_ecdsa::bench_triples(c);
        ot_based_ecdsa::bench_presign(c);
        ot_based_ecdsa::bench_sign(c);
    }

    // Robust ECDSA benchmarks
    if matches!(group.as_str(), "naive_robust_ecdsa" | "all") {
        robust_ecdsa::bench_presign(c);
        robust_ecdsa::bench_sign(c);
    }
}

criterion_group!(benches, choose_benchmark);
criterion_main!(benches);
