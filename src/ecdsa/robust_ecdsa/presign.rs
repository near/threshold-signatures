use rand_core::OsRng;
use frost_secp256k1::{
    Secp256K1Sha256, Secp256K1Group, Secp256K1ScalarField,
    Group, Field,
    keys::{
        SigningShare,
        VerifyingShare
    },
};

use crate::{
    crypto::polynomials::{
        evaluate_multi_polynomials,
        generate_secret_polynomial,
        eval_interpolation,
    },
    ecdsa::KeygenOutput,
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
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
)-> Result<[SigningShare; 5], ProtocolError> {
    let package = evaluate_multi_polynomials::<C,5>(polynomials, participant)?;
    Ok(package)
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
    let shares = evaluate_five_polynomials([&my_fk, &my_fa, &my_fb, &my_fd, &my_fe], me)?;
    // Extract the shares into a vec of scalars
    let mut shares: Vec<Scalar> = shares.iter()
        .map( |signing_share| signing_share.to_scalar())
        .collect();

    // Round 1
    // Receive evaluations from all participants
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, package): (_, [SigningShare; 5]) = chan.recv(wait_round_0).await?;
        if !seen.put(from) {
            continue;
        }

        // calculate the respective sum of the received different shares from each participant
        for i in 0..shares.len(){
            shares[i] += package[i].to_scalar();
        }
    }

    // Compute R_me = g^{k_me}
    let big_r_me = Secp256K1Group::generator() * shares[0];
    let big_r_me = VerifyingShare::new(big_r_me);

    // Compute w_me = a_me * k_me + b_me
    let w_me = shares[1] * shares[0] + shares[2];
    let w_me = SigningShare::new(w_me);

    // Send and receive
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &(&big_r_me, &w_me));

    // Store the sent items
    let mut signingshares_map = ParticipantMap::new(&participants);
    let mut verifyingshares_map = ParticipantMap::new(&participants);
    signingshares_map.put(me, w_me);
    verifyingshares_map.put(me, big_r_me);

    // Receive and interpolate
    seen.clear();
    seen.put(me);
    while !seen.full() {
        let (from, (big_r_p, w_p)): (_ , (VerifyingShare, SigningShare)) = chan.recv(wait_round_1).await?;
        if !seen.put(from) {
            continue;
        }
        // collect big_r_p and w_p in maps that will be later ordered
        signingshares_map.put(from, w_p);
        verifyingshares_map.put(from, big_r_p);
    }

    // polynomial interpolation of w
    let w = eval_interpolation(&signingshares_map, None);
    // exponent interpolation of big R
    // CAREFUL NOT TO INTERPOLATE MYSELF?

    Ok(())
}

