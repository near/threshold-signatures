use criterion::{criterion_group, Criterion};
use frost_secp256k1::{Secp256K1Sha256, VerifyingKey};
use rand::Rng;
use rand_core::OsRng;

mod bench_utils;
use crate::bench_utils::{
    MAX_MALICIOUS,
    split_even_odd,
    ot_ecdsa_prepare_triples,
};

use threshold_signatures::{
    ecdsa::{
        ot_based_ecdsa::{
            presign::presign,
            sign::sign,
            triples::{generate_triple_many, TriplePub, TripleShare},
            PresignArguments, PresignOutput, RerandomizedPresignOutput,
        },
        SignatureOption,
    },
    participants::Participant,
    protocol::Protocol,
    test_utils::{
        Simulator,
        create_multiple_rngs,
        ecdsa_generate_rerandpresig_args, generate_participants_with_random_ids, run_keygen,
        run_protocol, run_protocol_with_snapshots, run_simulated_protocol
    },
};

fn threshold() -> usize {
    *MAX_MALICIOUS + 1
}

fn participants_num() -> usize {
    *MAX_MALICIOUS + 1
}

/// Benches the triples protocol
fn bench_triples(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("triples");
    group.measurement_time(std::time::Duration::from_secs(200));

    group.bench_function(
        format!("ot_ecdsa_triples_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_triples(participants_num()),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

/// Benches the presigning protocol
fn bench_presign(c: &mut Criterion) {
    let num = participants_num();
    let max_malicious = *MAX_MALICIOUS;
    let mut group = c.benchmark_group("presign");
    group.measurement_time(std::time::Duration::from_secs(300));

    let protocols = ot_ecdsa_prepare_triples(participants_num(), threshold);
    let two_triples = run_protocol(protocols).expect("Running triple preparations should succeed");

    group.bench_function(
        format!("ot_ecdsa_presign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
        |b| {
            b.iter_batched(
                || prepare_simulated_presign(&two_triples),
                |(rparticipant, rprot, sprot)| run_simulated_protocol(rparticipant, rprot, sprot),
                criterion::BatchSize::SmallInput,
            );
        },
    );
}

// /// Benches the signing protocol
// fn bench_sign(c: &mut Criterion) {
//     let num = participants_num();
//     let max_malicious = *MAX_MALICIOUS;

//     let mut group = c.benchmark_group("sign");
//     group.measurement_time(std::time::Duration::from_secs(300));

//     let protocols = prepare_triples(participants_num());
//     let two_triples = run_protocol(protocols).expect("Running triples preparation should succeed");

//     let (protocols, pk) = prepare_presign(&two_triples);
//     let mut result = run_protocol(protocols).expect("Running presign preparation should succeed");
//     result.sort_by_key(|(p, _)| *p);

//     group.bench_function(
//         format!("ot_ecdsa_sign_naive_MAX_MALICIOUS_{max_malicious}_PARTICIPANTS_{num}"),
//         |b| {
//             b.iter_batched(
//                 || prepare_sign(&result, pk),
//                 run_protocol,
//                 criterion::BatchSize::SmallInput,
//             );
//         },
//     );
// }

type PreparedSimulatedTriples = (
    Participant,
    Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>,
    Simulator,
);
fn prepare_simulated_triples(participant_num: usize) -> PreparedSimulatedTriples {
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participant_num);
    let participants = generate_participants_with_random_ids(participant_num, &mut OsRng);

    let rngs = create_multiple_rngs(&participants);

    for (i, p) in participants.iter().enumerate() {
        let protocol = generate_triple_many::<2>(&participants, *p, threshold(), rngs[i].clone())
            .expect("Triple generation should succeed");
        protocols.push((*p, Box::new(protocol)));
    }
    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // now preparing the simulator
    // choose the real_participant at random
    let index_real_participant = OsRng.gen_range(0..participant_num);
    let real_participant = participants[index_real_participant];
    let simulated_protocol = Simulator::new(real_participant, protocolsnapshot)
                            .expect("Simulator should not be empty");
    let real_protocol =
      generate_triple_many::<2>(&participants, real_participant, threshold(), rngs[index_real_participant].clone())
      .map(|prot| Box::new(prot) as Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>)
      .expect("The rerun of the triple generation should not but raising error");

    (real_participant, real_protocol, simulated_protocol)
}

// type PreparedPresig = (
//     Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>,
//     VerifyingKey,
// );
type PreparedSimulatedPresig = (
    Participant,
    Box<dyn Protocol<Output = PresignOutput>>,
    Simulator,
);
fn prepare_simulated_presign(two_triples: &[(Participant, Vec<(TripleShare, TriplePub)>)]) -> PreparedSimulatedPresig {
    let mut two_triples = two_triples.to_owned();
    two_triples.sort_by_key(|(p, _)| *p);

    // collect all participants
    let participants: Vec<Participant> = two_triples
        .iter()
        .map(|(participant, _)| *participant)
        .collect();

    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, threshold());

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
        Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in key_packages.clone().into_iter().zip(shares0.clone()).zip(shares1.clone()) {
        let protocol = presign(
            &participants,
            p,
            PresignArguments {
                triple0: (share0, pub0[0].clone()),
                triple1: (share1, pub1[0].clone()),
                keygen_out,
                threshold: threshold(),
            },
        )
        .expect("Presigning should succeed");
        protocols.push((p, Box::new(protocol)));
    }

    let (_, protocolsnapshot) = run_protocol_with_snapshots(protocols)
        .expect("Running protocol with snapshot should not have issues");

    // now preparing the simulator
    // choose the real_participant at random
    let index_real_participant = OsRng.gen_range(0..participants.len());
    let real_participant = participants[index_real_participant];
    let simulated_protocol = Simulator::new(real_participant, protocolsnapshot)
                            .expect("Simulator should not be empty");

    let mut real_protocol = None;

    for (((p, keygen_out), share0), share1) in key_packages.into_iter().zip(shares0).zip(shares1) {
        if p == real_participant{
          real_protocol = Some(
            presign(
              &participants,
              p,
              PresignArguments {
                  triple0: (share0, pub0[0].clone()),
                  triple1: (share1, pub1[0].clone()),
                  keygen_out,
                  threshold: threshold(),
              },
            )
            .map(|presig| Box::new(presig) as Box<dyn Protocol<Output = PresignOutput>>)
            .expect("Presigning should succeed")
          )
        };
      }
    let real_protocol = real_protocol.expect("The real participant should also be included in the protocol");
    (real_participant, real_protocol, simulated_protocol)

}

// criterion_group!(benches, bench_presign);
criterion_group!(benches, bench_triples, bench_presign);
// criterion_group!(benches, bench_triples, bench_presign, bench_sign);
criterion::criterion_main!(benches);
