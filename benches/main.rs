mod crypto_benchmarks;

use crypto_benchmarks::*;

fn main() {
    lagrange::benches();
    inversion::benches();
}
