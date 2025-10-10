mod crypto_benchmarks;

use crypto_benchmarks::{inversion, lagrange};

fn main() {
    lagrange::benches();
    inversion::benches();
}
