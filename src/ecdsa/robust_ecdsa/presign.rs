use elliptic_curve::point::AffineCoordinates;
use frost_core::serialization::SerializableScalar;
use frost_secp256k1::{Group, Secp256K1Group};
use rand_core::OsRng;

use super::{PresignArguments, PresignOutput};
use crate::{
    ecdsa::{
        CoefficientCommitment, Field, Polynomial, PolynomialCommitment, Scalar,
        Secp256K1ScalarField, Secp256K1Sha256, SigningShare,
    },
    participants::{ParticipantCounter, ParticipantList, ParticipantMap},
    protocol::{
        internal::{make_protocol, Comms, SharedChannel},
        InitializationError, Participant, Protocol, ProtocolError,
    },
};

type C = Secp256K1Sha256;

/// Generates a secret polynomial where the constant term is zero
fn zero_secret_polynomial(degree: usize, rng: &mut OsRng) -> Result<Polynomial, ProtocolError> {
    let secret = Secp256K1ScalarField::zero();
    Polynomial::generate_polynomial(Some(secret), degree, rng)
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

    let polynomials = [
        // degree t random secret shares where t is the max number of malicious parties
        Polynomial::generate_polynomial(None, threshold, &mut rng)?, // fk
        Polynomial::generate_polynomial(None, threshold, &mut rng)?, // fa
        // degree 2t zero secret shares where t is the max number of malicious parties
        zero_secret_polynomial(2 * threshold, &mut rng)?, // fb
        zero_secret_polynomial(2 * threshold, &mut rng)?, // fd
        zero_secret_polynomial(2 * threshold, &mut rng)?, // fe
    ];

    // send polynomial evaluations to participants
    let wait_round_0 = chan.next_waitpoint();

    for p in participants.others(me) {
        // Securely send to each other participant a secret share
        let package = polynomials
            .iter()
            .map(|poly| poly.eval_at_participant(p))
            .collect::<Vec<_>>();

        // send the evaluation privately to participant p
        chan.send_private(wait_round_0, p, &package);
    }

    // Evaluate my secret shares for my polynomials
    let shares = polynomials
        .iter()
        .map(|poly| poly.eval_at_participant(me))
        .collect::<Vec<_>>();

    // Extract the shares into a vec of scalars
    let mut shares: Vec<Scalar> = shares.iter().map(|signing_share| signing_share.0).collect();

    // Round 1
    // Receive evaluations from all participants
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, package): (_, [SerializableScalar<C>; 5]) = chan.recv(wait_round_0).await?;
        if !seen.put(from) {
            continue;
        }

        // calculate the respective sum of the received different shares from each participant
        for i in 0..shares.len() {
            shares[i] += package[i].0;
        }
    }

    // Compute R_me = g^{k_me}
    let big_r_me = CoefficientCommitment::new(Secp256K1Group::generator() * shares[0]);

    // Compute w_me = a_me * k_me + b_me
    let w_me = shares[1] * shares[0] + shares[2];

    // Send and receive
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &(&big_r_me, &SigningShare::new(w_me)));

    // Store the sent items
    let mut signingshares_map = ParticipantMap::new(&participants);
    let mut verifyingshares_map = ParticipantMap::new(&participants);
    signingshares_map.put(me, SerializableScalar(w_me));
    verifyingshares_map.put(me, big_r_me);

    // Receive and interpolate
    while !signingshares_map.full() {
        let (from, (big_r_p, w_p)): (_, (_, SigningShare)) = chan.recv(wait_round_1).await?;
        // collect big_r_p and w_p in maps that will be later ordered
        // if the sender has already sent elements then put will return immediately
        signingshares_map.put(from, SerializableScalar(w_p.to_scalar()));
        verifyingshares_map.put(from, big_r_p);
    }

    let identifiers: Vec<Scalar> = signingshares_map
        .participants()
        .iter()
        .map(|p| p.scalar::<C>())
        .collect();

    let signingshares = signingshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    // exponent interpolation of big R
    let verifying_shares = verifyingshares_map
        .into_vec_or_none()
        .ok_or(ProtocolError::InvalidInterpolationArguments)?;

    #[cfg(feature = "actively_secure_ecdsa")]
    {
        // check that the exponent interpolations match what has been received
        for i in threshold + 1..identifiers.len() {
            let p = &identifiers[i];
            // exponent interpolation for (R0, .., Rt; i)
            let big_r_j = PolynomialCommitment::eval_exponent_interpolation(
                &identifiers[..threshold + 1],
                &verifying_shares[..threshold + 1],
                Some(p),
            )?;

            // check the interpolated R values match the received ones
            if big_r_j != verifying_shares[i] {
                return Err(ProtocolError::AssertionFailed(
                    "Exponent interpolation check failed.".to_string(),
                ));
            }
        }
    }
    // get only the first t+1 elements to interpolate
    // we know that identifiers.len()>threshold+1
    // evaluate the exponent interpolation on zero
    let big_r = PolynomialCommitment::eval_exponent_interpolation(
        &identifiers[..threshold + 1],
        &verifying_shares[..threshold + 1],
        None,
    )?;

    // check R is not identity
    if big_r.value().eq(&<Secp256K1Group as Group>::identity()) {
        return Err(ProtocolError::IdentityElement);
    }

    #[cfg(feature = "actively_secure_ecdsa")]
    {
        // Round 2
        // Compute W_me = R^{a_me}
        let big_w_me = CoefficientCommitment::new(big_r.value() * shares[1]);
        // Send W_me
        let wait_round_active = chan.next_waitpoint();
        chan.send_many(wait_round_active, &big_w_me);

        // Receive W_i
        let mut wshares_map = ParticipantMap::new(&participants);
        wshares_map.put(me, big_w_me);
        while !wshares_map.full() {
            let (from, big_w_p) = chan.recv(wait_round_active).await?;
            wshares_map.put(from, big_w_p);
        }
        // Compute exponent interpolation checks
        let wshares = wshares_map
            .into_vec_or_none()
            .ok_or(ProtocolError::InvalidInterpolationArguments)?;

        for i in threshold + 1..identifiers.len() {
            let p = &identifiers[i];
            // exponent interpolation for (W0, .., Wt; i)
            let big_w_j = PolynomialCommitment::eval_exponent_interpolation(
                &identifiers[..threshold + 1],
                &wshares[..threshold + 1],
                Some(p),
            )?;
            // check the interpolated W values match the received ones
            if big_w_j != wshares[i] {
                return Err(ProtocolError::AssertionFailed(
                    "Exponent interpolation check failed.".to_string(),
                ));
            }
        }
    }

    // polynomial interpolation of w
    let w = Polynomial::eval_interpolation(&identifiers, &signingshares, None)?;

    // check w is non-zero
    if w.0.is_zero().into() {
        return Err(ProtocolError::ZeroScalar);
    }

    // w is non-zero due to previous check and so I can unwrap safely
    let h_me = w.0.invert().unwrap() * shares[1];

    // Some extra computation is pushed in this offline phase
    let alpha_me = h_me + shares[3];

    let big_r_x_coordinate: [u8; 32] = big_r.value().to_affine().x().into();
    let big_r_x_coordinate = <Secp256K1ScalarField as Field>::deserialize(&big_r_x_coordinate)
        .map_err(|_| ProtocolError::ErrorReducingBytesToScalar)?;
    let x_me = args.keygen_out.private_share.to_scalar();
    let beta_me = h_me * big_r_x_coordinate * x_me + shares[4];

    Ok(PresignOutput {
        big_r: big_r.value().to_affine(),
        alpha_i: alpha_me,
        beta_i: beta_me,
    })
}

/// The presignature protocol.
///
/// This is the first phase of performing a signature, in which we perform
/// all the work we can do without yet knowing the message to be signed.
///
/// This work does depend on the private key though, and it's crucial
/// that a presignature is never reused.
pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be less than 2, found: {}",
            participants.len()
        )));
    };

    if args.threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be less than or equals to participant count".to_string(),
        ));
    }

    if 2 * args.threshold + 1 > participants.len() {
        return Err(InitializationError::BadParameters(
            "2*threshold+1 must be less than or equals to participant count".to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            "Presign participant list does not contain me".to_string(),
        ));
    };

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args);
    Ok(make_protocol(ctx, fut))
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_core::OsRng;

    use crate::{ecdsa::KeygenOutput, protocol::run_protocol, test::generate_participants};
    use frost_secp256k1::keys::PublicKeyPackage;
    use frost_secp256k1::VerifyingKey;
    use std::collections::BTreeMap;

    use k256::ProjectivePoint;

    #[test]
    fn test_presign() {
        let participants = generate_participants(5);

        let max_malicious = 2;

        let f = Polynomial::generate_polynomial(None, max_malicious, &mut OsRng).unwrap();
        let big_x = ProjectivePoint::GENERATOR * f.eval_at_zero().0;

        #[allow(clippy::type_complexity)]
        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = PresignOutput>>)> =
            Vec::with_capacity(participants.len());

        for p in &participants {
            // simulating the key packages for each participant
            let private_share = f.eval_at_participant(*p);
            let verifying_key = VerifyingKey::new(big_x);
            let public_key_package = PublicKeyPackage::new(BTreeMap::new(), verifying_key);
            let keygen_out = KeygenOutput {
                private_share: SigningShare::new(private_share.0),
                public_key: *public_key_package.verifying_key(),
            };

            let protocol = presign(
                &participants[..],
                *p,
                PresignArguments {
                    keygen_out,
                    threshold: max_malicious,
                },
            );
            assert!(protocol.is_ok());
            let protocol = protocol.unwrap();
            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols).unwrap();

        assert!(result.len() == 5);
        // testing that big_r is the same accross participants
        assert_eq!(result[0].1.big_r, result[1].1.big_r);
        assert_eq!(result[1].1.big_r, result[2].1.big_r);
        assert_eq!(result[2].1.big_r, result[3].1.big_r);
        assert_eq!(result[3].1.big_r, result[4].1.big_r);
    }
}
