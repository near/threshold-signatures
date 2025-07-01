use rand_core::OsRng;
use elliptic_curve::{
    point::AffineCoordinates,
};
use frost_secp256k1::{
    Secp256K1Sha256, Secp256K1Group, Secp256K1ScalarField,
    Group, Field,
    keys::{
        SigningShare,
        VerifyingShare
    },
};
use serde::{Deserialize, Serialize};

use crate::{
    crypto::polynomials::{
        evaluate_multi_polynomials,
        generate_polynomial,
        eval_interpolation,
        eval_exponent_interpolation,
    },
    ecdsa::KeygenOutput,
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        internal::{make_protocol, Comms, SharedChannel},
        Participant,
        ProtocolError,
        InitializationError,
        Protocol
    },
};


type C = Secp256K1Sha256;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresignOutput {
    /// The public nonce commitment.
    pub big_r: VerifyingShare,

    /// Our secret shares of the nonces.
    pub alpha_i: SigningShare,
    pub beta_i: SigningShare,
}

/// Generates a secret polynomial where the comstant term is zero
fn zero_secret_polynomial(
    degree: usize,
    rng: &mut OsRng,
)-> Vec<Scalar> {
    let secret = Secp256K1ScalarField::zero();
    generate_polynomial::<C>(Some(secret), degree, rng)
}

/// Evaluate five polynomials at once
fn evaluate_five_polynomials(
    polynomials: [&[Scalar]; 5],
    participant: Participant,
)-> Result<[SigningShare; 5], ProtocolError> {
    let package = evaluate_multi_polynomials::<C,5>(polynomials, participant)?;
    Ok(package)
}

/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    args: PresignArguments,
) -> Result<PresignOutput, ProtocolError> {
    let threshold = args.threshold;
    // Round 0
    let mut rng = OsRng;
    // degree t random secret shares where t is the max number of malicious parties
    let my_fk = generate_polynomial::<C>(None, threshold, &mut rng);
    let my_fk = my_fk.as_slice();
    let my_fa = generate_polynomial::<C>(None, threshold, &mut rng);
    let my_fa = my_fa.as_slice();

    // degree 2t zero secret shares where t is the max number of malicious parties
    let my_fb = zero_secret_polynomial(2*threshold, &mut rng);
    let my_fb = my_fb.as_slice();
    let my_fd = zero_secret_polynomial(2*threshold, &mut rng);
    let my_fd = my_fd.as_slice();
    let my_fe = zero_secret_polynomial(2*threshold, &mut rng);
    let my_fe = my_fe.as_slice();

    // send polynomial evaluations to participants
    let wait_round_0 = chan.next_waitpoint();

    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = evaluate_five_polynomials([my_fk, my_fa, my_fb, my_fd, my_fe], p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_0, p, &package);
    }

    // Evaluate my secret shares for my polynomials
    let shares = evaluate_five_polynomials([my_fk, my_fa, my_fb, my_fd, my_fe], me)?;
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

        // ONLY FOR PASSIVE: Disregard t points
        verifyingshares_map.put(from, big_r_p);
    }

    // polynomial interpolation of w
    let w = eval_interpolation(&signingshares_map, None)?;

    // exponent interpolation of big R
    let identifiers: Vec<Scalar> =  verifyingshares_map
                    .participants()
                    .iter()
                    .map(|p| p.generic_scalar::<C>())
                    .collect();
    let verifying_shares = verifyingshares_map.into_refs_or_none()
            .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    // get only the first t+1 elements to interpolate
    // we know that identifiers.len()>threshold+1
    let first_tplus1_id = identifiers[..threshold+1].to_vec();
    let first_tplus1_vfyshares = verifying_shares[..threshold+1].to_vec();
    // evaluate the exponent interpolation on zero
    let big_r = eval_exponent_interpolation(&first_tplus1_id, &first_tplus1_vfyshares, None)?;

    // check w is non-zero and that R is not the identity
    if w.to_scalar().is_zero().into(){
        return Err(ProtocolError::ZeroScalar)
    }
    if big_r.to_element().eq(&<Secp256K1Group as Group>::identity()){
        return Err(ProtocolError::IdentityElement)
    }

    // w is non-zero due to previous check and so I can unwrap safely
    let h_me = w.to_scalar().invert().unwrap() * shares[1];

    // Some extra computation is pushed in this offline phase
    let alpha_me = h_me + shares[3];

    let big_r_x_coordinate: [u8; 32] = big_r.to_element()
            .to_affine()
            .x()
            .try_into()
            .expect("Slice is not 32 bytes long");
    let big_r_x_coordinate = <Secp256K1ScalarField as Field>::deserialize(&big_r_x_coordinate)
                            .map_err(|_| ProtocolError::ErrorReducingBytesToScalar)?;
    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = h_me * big_r_x_coordinate* x_me + shares[4];

    Ok(PresignOutput{
        big_r,
        alpha_i: SigningShare::new(alpha_me),
        beta_i: SigningShare::new(beta_me),
    })
}


/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never used.
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be strictly less than 2, found: {}",
            participants.len()
        )));
    };

    if args.threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be less or equals to participant count".to_string(),
        ));
    }

    if 2*args.threshold+1 > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*threshold+1 must be less or equals to participant count".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me){
        return Err(InitializationError::BadParameters(
            "Presign participant list does not contain me".to_string()
        ));
    };

    let ctx = Comms::new();
    let fut = do_presign(
        ctx.shared_channel(),
        participants,
        me,
        args,
    );
    Ok(make_protocol(ctx, fut))
}



#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    use crate::{
        protocol::run_protocol,
        crypto::polynomials::{
            generate_polynomial,
            evaluate_polynomial_on_participant,
        },
    };
    use frost_secp256k1::keys::PublicKeyPackage;
    use frost_secp256k1::VerifyingKey;
    use std::collections::BTreeMap;

    use k256::{ProjectivePoint};

    #[test]
    fn test_presign() {
        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
            Participant::from(3u32),
            Participant::from(4u32),
        ];
        let max_malicious = 2;

        let f = generate_polynomial::<C>(None, max_malicious, &mut OsRng);
        let big_x = ProjectivePoint::GENERATOR * f.evaluate_zero();


        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(
            Participant,
            Box<dyn Protocol<Output = PresignOutput>>,
        )> = Vec::with_capacity(participants.len());

        for p in participants{
            // simulating the key packages for each participant
            let private_share = evaluate_polynomial_on_participant::<C>(&f, p).unwrap();
            let verifying_key = VerifyingKey::new(big_x);
            let public_key_package = PublicKeyPackage::new(BTreeMap::new(), verifying_key);
            let keygen_out = KeygenOutput {
                private_share,
                public_key: *public_key_package.verifying_key(),
            };

            let protocol = presign(
                &participants[..],
                p,
                PresignArguments {
                    keygen_out,
                    threshold: max_malicious,
                },
            );
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((p, Box::new(protocol)));
        }

        let result = run_protocol(protocols);
        assert!(result.is_ok());
        let result = result.unwrap();

        assert!(result.len() == 5);
        // testing that big_r is the same accross participants
        assert_eq!(result[0].1.big_r, result[1].1.big_r);
        assert_eq!(result[1].1.big_r, result[2].1.big_r);
        assert_eq!(result[2].1.big_r, result[3].1.big_r);
        assert_eq!(result[3].1.big_r, result[4].1.big_r);
    }
}