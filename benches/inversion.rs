use criterion::{criterion_group, criterion_main, Criterion};
use frost_core::{Field, Group};
use frost_secp256k1::{Secp256K1ScalarField, Secp256K1Sha256};
use rand_core::OsRng;
use threshold_signatures::batch_invert;

fn bench_inversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("inversion");

    group.measurement_time(std::time::Duration::from_secs(10));

    let num_inversions = 10_000;
    let values: Vec<_> = (0..num_inversions)
        .map(|_| Secp256K1ScalarField::random(&mut OsRng))
        .collect();

    group.bench_function("individual inversion", |b| {
        b.iter(|| {
            values
                .iter()
                .map(|v| {
                    <<Secp256K1Sha256 as frost_core::Ciphersuite>::Group as Group>::Field::invert(v)
                        .unwrap()
                })
                .collect::<Vec<_>>()
        })
    });

    group.bench_function("batch inversion", |b| {
        b.iter(|| batch_invert::<Secp256K1Sha256>(&values).unwrap())
    });
}

criterion_group!(benches, bench_inversion);
criterion_main!(benches);
