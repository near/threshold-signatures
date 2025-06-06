use rand_core::OsRng;
use frost_secp256k1::{
    Secp256K1Sha256, Secp256K1Group, Secp256K1ScalarField,
    Group, Field,
};

use crate::{
    crypto::polynomials::{
        evaluate_multi_polynomials,
        generate_secret_polynomial
    },
    ecdsa::KeygenOutput,
    participants::{ParticipantCounter, ParticipantList},
    protocol::{internal::SharedChannel, Participant, ProtocolError},
};

type C = Secp256K1Sha256;
type Element = <Secp256K1Group as Group>::Element;
type Scalar = <Secp256K1ScalarField as Field>::Scalar;


/// The arguments needed to create a presignature.
#[derive(Debug, Clone)]
pub struct PresignArguments {
    /// The output of key generation, i.e. our share of the secret key, and the public key package.
    /// This is of type KeygenOutput<Secp256K1Sha256> from Frost implementation
    pub keygen_out: KeygenOutput,
    /// The desired threshold for the presignature, which must match the original threshold
    pub threshold: usize,
}

/// The output of the presigning protocol.
/// Contains the signature precomputed parts performed
/// independently of the message
#[derive(Debug, Clone)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: Element,

    /// Our secret shares of the nonces.
    pub h_i: Scalar,
    pub d_i: Scalar,
    pub e_i: Scalar,
}

/// Generates a secret polynomial where the comstant term is zero
fn zero_secret_polynomial(
    degree: usize,
    rng: &mut OsRng,
)-> Vec<Scalar> {
    let secret = Secp256K1ScalarField::zero();
    generate_secret_polynomial::<C>(secret, degree, rng)
}

/// Generates a secret polynomial where the comstant term is random
fn random_secret_polynomial(
    degree: usize,
    rng: &mut OsRng,
)-> Vec<Scalar> {
    let secret = Secp256K1ScalarField::random(rng);
    generate_secret_polynomial::<C>(secret, degree, rng)
}

/// Evaluate five polynomials at once
fn evaluate_five_polynomials(
    polynomials: [&[Scalar]; 5],
    participant: Participant,
)-> Result<[Scalar; 5], ProtocolError> {
    let package = evaluate_multi_polynomials::<C,5>(polynomials, participant)?;
    let output: [Scalar; 5] = package
        .iter()
        .map( |signing_share| signing_share.to_scalar())
        .collect::<Vec<_>>()
        .try_into()
        .expect("Package must contain exactly N elements");
    Ok(output)
}


/// /!\ Warning: the threshold in this scheme is the same as
///              the max number of malicious parties.
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<(), ProtocolError> {
// ) -> Result<PresignOutput, ProtocolError> {

    // Round 0
    let mut rng = OsRng;
    // degree t random secret shares where t is the max number of malicious parties
    let my_fk = random_secret_polynomial(threshold, &mut rng);
    let my_fa = random_secret_polynomial(threshold, &mut rng);

    // degree 2t zero secret shares where t is the max number of malicious parties
    let my_fb = zero_secret_polynomial(2*threshold, &mut rng);
    let my_fd = zero_secret_polynomial(2*threshold, &mut rng);
    let my_fe = zero_secret_polynomial(2*threshold, &mut rng);

    // send polynomial evaluations to participants
    let wait_round_0 = chan.next_waitpoint();

    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = evaluate_five_polynomials([&my_fk, &my_fa, &my_fb, &my_fd, &my_fe], p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_0, p, &package);
    }

    // Evaluate my secret shares for my polynomials
    let mut shares = evaluate_five_polynomials([&my_fk, &my_fa, &my_fb, &my_fd, &my_fe], me)?;

    // Round 1
    // Receive evaluations from all participants
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, package): (_, [Scalar; 5]) = chan.recv(wait_round_0).await?;
        if !seen.put(from) {
            continue;
        }

        // calculate the respective sum of the received different shares from each participant
        for i in 0..shares.len(){
            shares[i] += package[i];
        }
    }

    // Compute R_me = g^{k_me}
    let big_r_me = Secp256K1Group::generator() * shares[0];
    let serialize_big_r_me = Secp256K1Group::serialize(&big_r_me)
        .map_err(|_| {ProtocolError::AssertionFailed(
            "The group element R could not be serialized as it is the identity.
            Please retry the presigning".to_string())})?;

    // Compute w_me = a_me * k_me + b_me
    let w_me = shares[1] * shares[0] + shares[2];

    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &(&serialize_big_r_me, &w_me));

    Ok(())
}

