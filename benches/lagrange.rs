use criterion::{criterion_group, Criterion};
use frost_core::Field;
use frost_secp256k1::{Secp256K1ScalarField, Secp256K1Sha256};
use rand_core::OsRng;
use std::hint::black_box;
use threshold_signatures::{
    batch_compute_lagrange_coefficients, compute_lagrange_coefficient, protocol::Participant,
};

type C = Secp256K1Sha256;

fn bench_lagrange_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("Lagrange Computation");

    for degree in [10, 100].iter() {
        let participants = (0..*degree + 1)
            .map(|i| Participant::from(i as u32))
            .collect::<Vec<_>>();
        let ids = participants
            .iter()
            .map(|p| p.scalar::<C>())
            .collect::<Vec<_>>();
        let point = Some(Secp256K1ScalarField::random(&mut OsRng));

        group.bench_with_input(
            format!("sequential_degree_{}", degree),
            &(ids.clone(), point),
            |b, (ids, point)| {
                b.iter(|| {
                    for id in ids.iter() {
                        let coeff =
                            compute_lagrange_coefficient::<C>(ids, id, point.as_ref()).unwrap();
                        black_box(coeff);
                    }
                });
            },
        );

        group.bench_with_input(
            format!("batch_degree_{}", degree),
            &(ids.clone(), point),
            |b, (ids, point)| {
                b.iter(|| {
                    let coeff =
                        batch_compute_lagrange_coefficients::<C>(ids, point.as_ref()).unwrap();
                    black_box(coeff);
                });
            },
        );

        // x = 0
        let point_x0 = Some(Secp256K1ScalarField::zero());
        group.bench_with_input(
            format!("batch_x0_degree_{}", degree),
            &(ids.clone(), point_x0),
            |b, (ids, point)| {
                b.iter(|| {
                    let coeff =
                        batch_compute_lagrange_coefficients::<C>(ids, point.as_ref()).unwrap();
                    black_box(coeff);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_lagrange_computation,);
