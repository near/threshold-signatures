mod crypto_benchmarks;
mod protocol_benchmarks;

use criterion::{criterion_main, criterion_group};
use crypto_benchmarks::{inversion, lagrange};
use protocol_benchmarks::inexact_ot_based_ecdsa;

criterion_group!(
    crypto_benchmarks,
    lagrange::bench_lagrange_computation,
    lagrange::bench_inversion_vs_multiplication,
    inversion::bench_inversion,
);

criterion_group!(
    ot_based_ecdsa,
    // inexact_ot_based_ecdsa::bench_triples,
    // inexact_ot_based_ecdsa::bench_presign,
    inexact_ot_based_ecdsa::bench_sign,
);

// criterion_main!(crypto_benchmarks);
criterion_main!(ot_based_ecdsa);
