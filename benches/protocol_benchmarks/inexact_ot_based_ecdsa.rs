use criterion::Criterion;
use frost_secp256k1::{Secp256K1Sha256, Secp256K1ScalarField, VerifyingKey};
use rand_core::{OsRng, RngCore};
use rand::Rng;

extern crate threshold_signatures;
use threshold_signatures::{
    test::{
        generate_participants_with_random_ids,
        run_keygen,
    },
    ecdsa::{Tweak, RerandomizationArguments, SignatureOption},
    ecdsa::ot_based_ecdsa::{
        triples::{
            generate_triple_many, TripleShare, TriplePub
        },
        presign::presign,
        sign::sign,
        PresignArguments, PresignOutput, RerandomizedPresignOutput,
    },
    protocol::{Protocol, Participant, benchmarking::run_protocol},
    ParticipantList,
};

const THRESHOLD: usize = 4;
const PARTICIPANTS_NUM: usize = 7;


fn split_even_odd<T: Clone>(v: Vec<T>) -> (Vec<T>, Vec<T>) {
    let mut even = Vec::with_capacity(v.len() / 2 + 1);
    let mut odd = Vec::with_capacity(v.len() / 2);
    for (i, x) in v.into_iter().enumerate() {
        if i % 2 == 0 {
            even.push(x);
        } else {
            odd.push(x);
        }
    }
    (even, odd)
}

fn prepare_triples(participants: &[Participant]) -> Vec<(Participant, Box<dyn Protocol<Output = Vec<(TripleShare, TriplePub)>>>)>{
    let rng = OsRng;
    let mut protocols: Vec<(_, Box<dyn Protocol<Output = _>>)> =
        Vec::with_capacity(participants.len());

    for &p in participants {
        let protocol = generate_triple_many::<2>(&participants, p, THRESHOLD, rng);
        let protocol = protocol.unwrap();
        protocols.push((p, Box::new(protocol)));
    }
    protocols
}

fn prepare_presign(
    participants: &[Participant],
    shares0: &[TripleShare],
    shares1: &[TripleShare],
    pub0: &[TriplePub],
    pub1: &[TriplePub]
) -> (Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>, VerifyingKey){

    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, THRESHOLD).unwrap();
    let pk = key_packages[0].1.public_key.clone();
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
            Vec::with_capacity(participants.len());

    for (((p, keygen_out), share0), share1) in key_packages
            .into_iter()
            .zip(shares0)
            .zip(shares1)
    {
            let protocol = presign(
                participants,
                p,
                PresignArguments {
                    triple0: (share0.clone(), pub0[0].clone()),
                    triple1: (share1.clone(), pub1[0].clone()),
                    keygen_out,
                    threshold: THRESHOLD,
                },
            )
            .unwrap();
            protocols.push((p, Box::new(protocol)));
        }
        (protocols, pk)

}


fn prepare_sign(
    participants: &[Participant],
    result: &[(Participant, PresignOutput)],
    pk: VerifyingKey,
)-> Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)>{

    // hash the message into secp256k1 field
    // generate a random tweak
    let tweak = Tweak::new(frost_core::random_nonzero::<Secp256K1Sha256, _>(&mut OsRng));
    // generate a random public entropy
    let mut entropy: [u8; 32] = [0u8; 32];
    OsRng.fill_bytes(&mut entropy);

    let participant_list = ParticipantList::new(participants).unwrap();

    // choose a coordinator at random
    let index = OsRng.gen_range(0..participants.len());
    let coordinator = result[index].0;

    let big_r = result[0].1.big_r;
    let msg_hash = <Secp256K1ScalarField as frost_core::Field>::random(&mut OsRng);
    let msg_hash_bytes: [u8; 32] = msg_hash.to_bytes().into();

    let rerand_args = RerandomizationArguments::new(
        pk.to_element().to_affine(),
        msg_hash_bytes,
        big_r,
        participant_list,
        entropy
    );

    let derived_pk = tweak.derive_verifying_key(&pk).to_element();

    let result = result
        .iter()
        .map(|(p, presig)| {
            (   *p,
                RerandomizedPresignOutput::new(presig, &tweak, &rerand_args).unwrap(),
            )
        })
        .collect::<Vec<_>>();

    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = SignatureOption>>)> =
        Vec::with_capacity(result.len());

    for (p, presignature) in result {
        let protocol = sign(
            &participants,
            coordinator,
            p,
            derived_pk.to_affine(),
            presignature,
            msg_hash,
        ).map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
        .unwrap();
        protocols.push((p, protocol));
    }
    protocols
}

pub fn bench_triples(c: &mut Criterion) {
    let mut group = c.benchmark_group("Triples generation ot-based ECSDA");
    group.measurement_time(std::time::Duration::from_secs(200));

    let mut rng = OsRng;
    let participants = generate_participants_with_random_ids(PARTICIPANTS_NUM, &mut rng);

    group.bench_function("Triple generation", |b| {
        b.iter_batched(||
            prepare_triples(&participants),
            |protocols| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
        );
    });
}

pub fn bench_presign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Presign ot-based ECSDA");
    group.measurement_time(std::time::Duration::from_secs(300));

    let mut rng = OsRng;
    let participants = generate_participants_with_random_ids(PARTICIPANTS_NUM, &mut rng);
    let protocols = prepare_triples(&participants);
    let mut two_triples = run_protocol(protocols).unwrap();

    two_triples.sort_by_key(|(p, _)| *p);
    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    group.bench_function("Presignature generation", |b| {
        b.iter_batched(||
            prepare_presign(&participants, &shares0, &shares1, &pub0, &pub1),
            |(protocols, _)| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
            );
        });
}

pub fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sign ot-based ECSDA");
    group.measurement_time(std::time::Duration::from_secs(300));

    let mut rng = OsRng;
    let participants = generate_participants_with_random_ids(PARTICIPANTS_NUM, &mut rng);
    let protocols = prepare_triples(&participants);
    let mut two_triples = run_protocol(protocols).unwrap();

    two_triples.sort_by_key(|(p, _)| *p);
    let (shares, pubs): (Vec<_>, Vec<_>) = two_triples.into_iter().flat_map(|(_, vec)| vec).unzip();
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (shares0, shares1) = split_even_odd(shares);
    // split shares into shares0 and shares 1 and pubs into pubs0 and pubs1
    let (pub0, pub1) = split_even_odd(pubs);

    let (protocols, pk) = prepare_presign(&participants, &shares0, &shares1, &pub0, &pub1);
    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);


    group.bench_function("Presignature generation", |b| {
        b.iter_batched(||
            prepare_sign(&participants, &result, pk),
            |protocols| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
        );
    });
}