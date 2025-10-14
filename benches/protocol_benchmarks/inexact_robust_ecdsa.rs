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
    ecdsa::robust_ecdsa::{
        presign::presign,
        sign::sign,
        PresignArguments, PresignOutput, RerandomizedPresignOutput,
    },
    protocol::{Protocol, Participant, benchmarking::run_protocol},
    ParticipantList,
};

const MAX_MALICIOUS: usize = 6;
const PARTICIPANTS_NUM: usize = 13;

fn prepare_presign(participants: &[Participant]) -> (Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)>, VerifyingKey){
    let key_packages = run_keygen::<Secp256K1Sha256>(&participants, MAX_MALICIOUS + 1).unwrap();
    let pk = key_packages[0].1.public_key.clone();
    let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
            Vec::with_capacity(participants.len());

    for (p, keygen_out) in key_packages {
            let protocol = presign(
                participants,
                p,
                PresignArguments {
                    keygen_out,
                    threshold: MAX_MALICIOUS,
                },
                OsRng,
            ).unwrap();
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
                RerandomizedPresignOutput::rerandomize_presign(presig, &tweak, &rerand_args).unwrap(),
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

pub fn bench_presign(c: &mut Criterion) {
    let mut group = c.benchmark_group(
        &format!(
            "Presign Robust ECDSA: {} malicious parties and {} participating parties",
            MAX_MALICIOUS,
            PARTICIPANTS_NUM
        )
    );
    group.measurement_time(std::time::Duration::from_secs(300));
    let participants = generate_participants_with_random_ids(PARTICIPANTS_NUM, &mut OsRng);

    group.bench_function("Presignature generation", |b| {
        b.iter_batched(||
            prepare_presign(&participants),
            |(protocols, _)| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
            );
        });
}

pub fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group(
        &format!(
            "Sign Robust ECDSA: {} malicious parties and {} participating parties",
            MAX_MALICIOUS,
            PARTICIPANTS_NUM
        )
    );
    group.measurement_time(std::time::Duration::from_secs(300));

    let participants = generate_participants_with_random_ids(PARTICIPANTS_NUM, &mut OsRng);
    let (protocols, pk) = prepare_presign(&participants);
    let mut result = run_protocol(protocols).unwrap();
    result.sort_by_key(|(p, _)| *p);

    group.bench_function("Signature generation", |b| {
        b.iter_batched(||
            prepare_sign(&participants, &result, pk),
            |protocols| run_protocol(protocols),
            criterion::BatchSize::SmallInput, // Choose batch size based on your expected workload
        );
    });
}