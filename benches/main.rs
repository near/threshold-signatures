use criterion::{criterion_group, criterion_main, Criterion};
use std::sync::LazyLock;
use std::env;

mod crypto_benchmarks;
mod protocol_benchmarks;

use crypto_benchmarks::{inversion, lagrange};
use protocol_benchmarks::naive_benchmarks::{ot_based_ecdsa, robust_ecdsa};

// fix malicious number of participants
static MAX_MALICIOUS: LazyLock<usize> = std::sync::LazyLock::new(|| {
    env::var("MAX_MALICIOUS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(6)
});

fn show_help() {
    eprintln!(
        r"Usage:
  BENCH=<benchgroupname> MAX_MALICIOUS=<n> cargo bench --features benchmarking [-- <criterion options>]

Available BENCH groups:
  crypto               Run crypto-related benchmarks
  naive_ot_ecdsa       Run naive OT-based ECDSA benchmarks
  naive_robust_ecdsa   Run naive robust ECDSA benchmarks
  all                  Run all benchmarks

Optional env vars:
  MAX_MALICIOUS=<n>    Set max malicious participants (default: 6)

Examples:
  BENCH=crypto cargo bench --features benchmarking
  BENCH=naive_robust_ecdsa MAX_MALICIOUS=10 cargo bench --features benchmarking -- --sample-size=50
"
    );
}

/// Can be ran using:
/// BENCH=<option> cargo bench --features benchmarking
/// Example: BENCH=crypto cargo bench --features benchmarking
fn choose_benchmark(c: &mut Criterion) {
    let group = env::var("BENCH").unwrap_or_default();
    if group.is_empty() || group == "help" {
        show_help();
        return;
    }
    let run_all = group == "all";

    // Cryptography tools benchmarks
    if run_all || group == "crypto" {
        lagrange::bench_lagrange_computation(c);
        lagrange::bench_inversion_vs_multiplication(c);
        inversion::bench_inversion(c);
    }

    // OT-based ECDSA benchmarks
    if run_all || group == "naive_ot_ecdsa" {
        ot_based_ecdsa::bench_triples(c);
        ot_based_ecdsa::bench_presign(c);
        ot_based_ecdsa::bench_sign(c);
    }

    // Robust ECDSA benchmarks
    if run_all || group == "naive_robust_ecdsa" {
        robust_ecdsa::bench_presign(c);
        robust_ecdsa::bench_sign(c);
    }

    if !run_all && !matches!(group.as_str(),
                "crypto" | "naive_ot_ecdsa" | "naive_robust_ecdsa"){
        eprintln!("Please fix the environment variables properly.");
        show_help();
    }
}

criterion_group!(benches, choose_benchmark);
#[cfg(feature = "benchmarking")]
criterion_main!(benches);

/// This will only exist if the "benchmarking" feature is NOT enabled.
#[cfg(not(feature = "benchmarking"))]
fn main() {
    eprintln!(
        r#"The "benchmarking" feature is not enabled.
        To run benchmarks, please use:
            cargo bench --features benchmarking
        "#
    );
}
