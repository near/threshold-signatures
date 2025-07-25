use crate::crypto::{hash, HashOutput};
use crate::echo_broadcast::do_broadcast;
use crate::participants::{ParticipantCounter, ParticipantList, ParticipantMap};
use crate::protocol::internal::SharedChannel;
use crate::protocol::{InitializationError, Participant, ProtocolError};

use frost_core::keys::{
    CoefficientCommitment, SecretShare, SigningShare, VerifiableSecretSharingCommitment,
};
use frost_core::{
    Challenge, Element, Error, Field, Group, Scalar, Signature, SigningKey, VerifyingKey,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::ops::Index;

pub enum BytesOrder {
    BigEndian,
    LittleEndian,
}

pub trait ScalarSerializationFormat {
    fn bytes_order() -> BytesOrder;
}

pub trait Ciphersuite: frost_core::Ciphersuite + ScalarSerializationFormat {}

/// This function prevents calling keyshare function with inproper inputs
fn assert_keyshare_inputs<C: Ciphersuite>(
    me: Participant,
    secret: &Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
) -> Result<(Option<VerifyingKey<C>>, Option<ParticipantList>), ProtocolError> {
    let is_zero_secret = *secret == <C::Group as Group>::Field::zero();

    if let Some((old_key, old_participants)) = old_reshare_package {
        if is_zero_secret {
            //  return error if me is not a purely new joiner to the participants set
            //  prevents accidentally calling keyshare with extremely old keyshares
            //  that have nothing todo with the current resharing
            if old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a zero share but does belong to the old participant set")));
            }
        } else {
            //  return error if me is part of the old participants set
            if !old_participants.contains(me) {
                return Err(ProtocolError::AssertionFailed(
                    format!("{me:?} is running Resharing with a zero share but does belong to the old participant set")));
            }
        }
        Ok((Some(old_key), Some(old_participants)))
    } else {
        if is_zero_secret {
            return Err(ProtocolError::AssertionFailed(format!(
                "{me:?} is running DKG with a zero share"
            )));
        }
        Ok((None, None))
    }
}

/// Hashes using a domain separator
/// The domain separator has to be manually incremented after the use of this function
fn domain_separate_hash<T: Serialize>(domain_separator: u32, data: &T) -> HashOutput {
    let preimage = (domain_separator, data);
    hash(&preimage)
}

/// Creates a polynomial p of degree threshold - 1
/// and sets p(0) = secret
fn generate_secret_polynomial<C: Ciphersuite>(
    secret: Scalar<C>,
    threshold: usize,
    rng: &mut OsRng,
) -> Vec<Scalar<C>> {
    let mut coefficients = Vec::with_capacity(threshold);
    // insert the secret share
    coefficients.push(secret);
    for _ in 1..threshold {
        coefficients.push(<C::Group as Group>::Field::random(rng));
    }
    coefficients
}

/// Creates a commitment vector of coefficients * G
/// If the first coefficient is set to zero then skip it
fn generate_coefficient_commitment<C: Ciphersuite>(
    secret_coefficients: &[Scalar<C>],
) -> Vec<CoefficientCommitment<C>> {
    // we skip the zero share as neither zero scalar
    // nor identity group element are serializable
    let coeff_iter = secret_coefficients
        .iter()
        .skip((secret_coefficients.first() == Some(&<C::Group as Group>::Field::zero())) as usize);

    // Compute the multiplication of every coefficient of p with the generator G
    let coefficient_commitment: Vec<CoefficientCommitment<C>> = coeff_iter
        .map(|c| CoefficientCommitment::new(<C::Group as Group>::generator() * *c))
        .collect();

    coefficient_commitment
}

/// Generates the challenge for the proof of knowledge
/// H(id, context_string, g^{secret} , R)
fn challenge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: u32,
    id: Scalar<C>,
    vk_share: &CoefficientCommitment<C>,
    big_r: &Element<C>,
) -> Result<Challenge<C>, ProtocolError> {
    let mut preimage = vec![];
    let serialized_id = <C::Group as Group>::Field::serialize(&id);

    // Should not return Error
    // The function should not be called when the first coefficient is zero
    let serialized_vk_share = vk_share.serialize().map_err(|_| {
        ProtocolError::AssertionFailed(
            "The verification share
        could not be serialized as it is null"
                .to_string(),
        )
    })?;

    let serialized_big_r = <C::Group>::serialize(big_r).map_err(|_| {
        ProtocolError::AssertionFailed(
            "The group element R
        could not be serialized as it is the identity"
                .to_string(),
        )
    })?;

    preimage.extend_from_slice(&domain_separator.to_le_bytes());
    preimage.extend_from_slice(session_id.as_ref());
    preimage.extend_from_slice(serialized_id.as_ref());
    preimage.extend_from_slice(serialized_vk_share.as_ref());
    preimage.extend_from_slice(serialized_big_r.as_ref());

    let hash = C::HDKG(&preimage[..]).ok_or(ProtocolError::DKGNotSupported)?;
    Ok(Challenge::from_scalar(hash))
}

/// Computes the proof of knowledge of the secret coefficient a_0
/// used to generate the public polynomial.
/// generate a random k and compute R = g^k
/// Compute mu = k + a_0 * H(id, context_string, g^{a_0} , R)
/// Output (R, mu)
fn proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: u32,
    me: Participant,
    coefficients: &[Scalar<C>],
    coefficient_commitment: &[CoefficientCommitment<C>],
    rng: &mut OsRng,
) -> Result<Signature<C>, ProtocolError> {
    // creates an identifier for the participant
    let id = me.generic_scalar::<C>();
    let vk_share = coefficient_commitment[0];

    // pick a random k_i and compute R_id = g^{k_id},
    let (k, big_r) = <C>::generate_nonce(rng);

    // compute H(id, context_string, g^{a_0} , R_id) as a scalar
    let hash = challenge::<C>(session_id, domain_separator, id, &vk_share, &big_r)?;
    let a_0 = coefficients[0];
    let mu = k + a_0 * hash.to_scalar();
    Ok(Signature::new(big_r, mu))
}

/// Generates a proof of knowledge.
/// The proof of knowledge could be set to None in case the participant is new
/// and thus its secret share is known (set to zero)
fn compute_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: u32,
    me: Participant,
    old_participants: Option<ParticipantList>,
    coefficients: &[Scalar<C>],
    coefficient_commitment: &[CoefficientCommitment<C>],
    rng: &mut OsRng,
) -> Result<Option<Signature<C>>, ProtocolError> {
    // I am allowed to send none only if I am a new participant
    if old_participants.is_some() && !old_participants.unwrap().contains(me) {
        return Ok(None);
    };
    // generate a proof of knowledge if the participant me is not holding a secret that is zero
    let proof = proof_of_knowledge(
        session_id,
        domain_separator,
        me,
        coefficients,
        coefficient_commitment,
        rng,
    )?;
    Ok(Some(proof))
}

/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
fn internal_verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: u32,
    participant: Participant,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Signature<C>,
) -> Result<(), ProtocolError> {
    // creates an identifier for the participant
    let id = participant.generic_scalar::<C>();
    let vk_share = commitment.coefficients().first().unwrap();

    let big_r = proof_of_knowledge.R();
    let z = proof_of_knowledge.z();
    let c = challenge::<C>(session_id, domain_separator, id, vk_share, big_r)?;
    if *big_r != <C::Group>::generator() * *z - vk_share.value() * c.to_scalar() {
        return Err(ProtocolError::InvalidProofOfKnowledge(participant));
    }
    Ok(())
}

/// Verifies the proof of knowledge of the secret coefficients used to generate the
/// public secret sharing commitment.
/// if the proof of knowledge is none then make sure that the participant is
/// performing reshare and does not exist in the set of old participants
fn verify_proof_of_knowledge<C: Ciphersuite>(
    session_id: &HashOutput,
    domain_separator: u32,
    threshold: usize,
    participant: Participant,
    old_participants: Option<ParticipantList>,
    commitment: &VerifiableSecretSharingCommitment<C>,
    proof_of_knowledge: &Option<Signature<C>>,
) -> Result<(), ProtocolError> {
    // if participant did not send anything but he is actually an old participant
    if proof_of_knowledge.is_none() {
        // if basic dkg or participant is old
        if old_participants.is_none() || old_participants.unwrap().contains(participant) {
            return Err(ProtocolError::MaliciousParticipant(participant));
        }
        // since previous line did not abort, then we know participant is new indeed
        // check the commitment length is threshold - 1
        if commitment.coefficients().len() != threshold - 1 {
            return Err(ProtocolError::IncorrectNumberOfCommitments);
        }
        // nothing to verify
        return Ok(());
    } else {
        // if participant sent something but he is actually a new participant
        if old_participants.is_some() && !old_participants.unwrap().contains(participant) {
            return Err(ProtocolError::MaliciousParticipant(participant));
        }
        // since the previous did not abort, we know the participant is old or we are dealing with a dkg
        if commitment.coefficients().len() != threshold {
            return Err(ProtocolError::IncorrectNumberOfCommitments);
        };
    };

    // now we know the proof is not none
    let proof_of_knowledge = proof_of_knowledge.unwrap();
    // creating an identifier as required by the syntax of verify_proof_of_knowledge of frost_core
    internal_verify_proof_of_knowledge(
        session_id,
        domain_separator,
        participant,
        commitment,
        &proof_of_knowledge,
    )
}

/// Takes a commitment and a commitment hash and checks that
/// H(commitment) = commitment_hash
fn verify_commitment_hash<C: Ciphersuite>(
    session_id: &HashOutput,
    participant: Participant,
    domain_separator: u32,
    commitment: &VerifiableSecretSharingCommitment<C>,
    all_hash_commitments: &ParticipantMap<'_, HashOutput>,
) -> Result<(), ProtocolError> {
    let actual_commitment_hash = all_hash_commitments.index(participant);
    let commitment_hash =
        domain_separate_hash(domain_separator, &(&participant, &commitment, &session_id));
    if *actual_commitment_hash != commitment_hash {
        return Err(ProtocolError::InvalidCommitmentHash);
    }
    Ok(())
}

/// This function is called when the commitment length is threshold -1
/// i.e. when the new participant sent a polynomial with a non-existant constant term
/// such a participant would do so as the identity is not serializable
fn insert_identity_if_missing<C: Ciphersuite>(
    threshold: usize,
    commitment_i: &VerifiableSecretSharingCommitment<C>,
) -> VerifiableSecretSharingCommitment<C> {
    // in case the participant was new and it sent a polynomial of length
    // threshold -1 (because the zero term is not serializable)
    let mut commitment_i = commitment_i.clone();
    let mut coefficients_i = commitment_i.coefficients().to_vec();
    if coefficients_i.len() == threshold - 1 {
        let identity = CoefficientCommitment::new(<C::Group as Group>::identity());
        coefficients_i.insert(0, identity);
        commitment_i = VerifiableSecretSharingCommitment::new(coefficients_i);
    }
    commitment_i
}

// evaluates a polynomial on the identifier of the participant
fn evaluate_polynomial<C: Ciphersuite>(
    coefficients: &[Scalar<C>],
    participant: Participant,
) -> Result<SigningShare<C>, ProtocolError> {
    let id = participant.to_identifier::<C>();
    Ok(SigningShare::from_coefficients(coefficients, id))
}

// creates a signing share structure using my identifier, the received
// signing share and the received commitment
fn validate_received_share<C: Ciphersuite>(
    me: &Participant,
    from: &Participant,
    signing_share_from: &SigningShare<C>,
    commitment: &VerifiableSecretSharingCommitment<C>,
) -> Result<(), ProtocolError> {
    let id = me.to_identifier::<C>();

    // The verification is exactly the same as the regular SecretShare verification;
    // however the required components are in different places.
    // Build a temporary SecretShare so what we can call verify().
    let secret_share = SecretShare::new(id, *signing_share_from, commitment.clone());

    // Verify the share. We don't need the result.
    // Identify the culprit if an InvalidSecretShare error is returned.
    secret_share.verify().map_err(|e| {
        if let Error::InvalidSecretShare { .. } = e {
            ProtocolError::InvalidSecretShare(*from)
        } else {
            ProtocolError::AssertionFailed(format!(
                "could not
            extract the verification key matching the secret
            share sent by {from:?}"
            ))
        }
    })?;
    Ok(())
}

/// generates a verification key out of a public commited polynomial
fn public_key_from_commitments<C: Ciphersuite>(
    commitments: Vec<&VerifiableSecretSharingCommitment<C>>,
) -> Result<VerifyingKey<C>, ProtocolError> {
    let commitment = frost_core::keys::sum_commitments(&commitments)
        .map_err(|_| ProtocolError::IncorrectNumberOfCommitments)?;

    let vk = VerifyingKey::from_commitment(&commitment)
        .map_err(|_| ProtocolError::ErrorExtractVerificationKey)?;
    Ok(vk)
}

/// This function takes err as input.
/// If err is None then broadcast success
/// otherwise, broadcast failure
/// If during broadcast it receives an error then propagates it
/// This function is used in the final round of DKG
async fn broadcast_success(
    chan: &mut SharedChannel,
    participants: &ParticipantList,
    me: &Participant,
    session_id: HashOutput,
) -> Result<(), ProtocolError> {
    // broadcast node me succeded
    let vote_list = do_broadcast(chan, participants, me, (true, session_id)).await?;
    // unwrap here would never fail as the broadcast protocol ends only when the map is full
    let vote_list = vote_list.into_vec_or_none().unwrap();
    // go through all the list of votes and check if any is fail or some does not contain the session id

    if !vote_list.iter().all(|(_, ref sid)| sid == &session_id) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                broadcast the wrong session id. Aborting Protocol!"
                .to_string(),
        ));
    };

    if !vote_list.iter().all(|&(boolean, _)| boolean) {
        return Err(ProtocolError::AssertionFailed(
            "A participant
                seems to have failed its checks. Aborting Protocol!"
                .to_string(),
        ));
    };
    // Wait for all the tasks to complete
    Ok(())
}

/// Performs the heart of DKG, Reshare and Refresh protocols
async fn do_keyshare<C: Ciphersuite>(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    secret: Scalar<C>,
    old_reshare_package: Option<(VerifyingKey<C>, ParticipantList)>,
    mut rng: OsRng,
) -> Result<KeygenOutput<C>, ProtocolError> {
    let mut all_commitments = ParticipantMap::new(&participants);
    let mut domain_separator = 0;
    // Make sure you do not call do_keyshare with zero as secret on an old participant
    let (old_verification_key, old_participants) =
        assert_keyshare_inputs(me, &secret, old_reshare_package)?;

    // Start Round 0
    let mut my_session_id = [0u8; 32]; // 256 bits
    OsRng.fill_bytes(&mut my_session_id);
    let session_ids = do_broadcast(&mut chan, &participants, &me, my_session_id).await?;

    // Start Round 1
    // generate your secret polynomial p with the constant term set to the secret
    // and the rest of the coefficients are picked at random
    // because the library does not allow serializing the zero and identity term,
    // this function does not add the zero coefficient
    let session_id = domain_separate_hash(domain_separator, &session_ids);
    domain_separator += 1;
    let secret_coefficients = generate_secret_polynomial::<C>(secret, threshold, &mut rng);

    // Compute the multiplication of every coefficient of p with the generator G
    let coefficient_commitment = generate_coefficient_commitment::<C>(&secret_coefficients);
    // generate a proof of knowledge if the participant me is not holding a secret that is zero
    let proof_domain_separator = domain_separator;
    let proof_of_knowledge = compute_proof_of_knowledge(
        &session_id,
        domain_separator,
        me,
        old_participants.clone(),
        &secret_coefficients,
        &coefficient_commitment,
        &mut rng,
    )?;
    domain_separator += 1;

    // Create the public polynomial = secret coefficients times G
    let commitment = VerifiableSecretSharingCommitment::new(coefficient_commitment);

    // hash commitment and send it
    let commit_domain_separator = domain_separator;
    let commitment_hash = domain_separate_hash(domain_separator, &(&me, &commitment, &session_id));
    let wait_round_1 = chan.next_waitpoint();
    chan.send_many(wait_round_1, &commitment_hash);
    // receive commitment_hash
    let mut all_hash_commitments = ParticipantMap::new(&participants);
    all_hash_commitments.put(me, commitment_hash);
    while !all_hash_commitments.full() {
        let (from, their_commitment_hash) = chan.recv(wait_round_1).await?;
        all_hash_commitments.put(from, their_commitment_hash);
    }

    // Start Round 2
    // add my commitment and proof to the map
    all_commitments.put(me, commitment.clone());

    // Broadcast to all the commitment and the proof of knowledge
    let commitments_and_proofs_map = do_broadcast(
        &mut chan,
        &participants,
        &me,
        (commitment, proof_of_knowledge),
    )
    .await?;

    // Start Round 3
    let wait_round_3 = chan.next_waitpoint();
    for p in participants.others(me) {
        let (commitment_i, proof_i) = commitments_and_proofs_map.index(p);

        // verify the proof of knowledge
        // if proof is none then make sure the participant is new
        // and performing a resharing not a DKG
        verify_proof_of_knowledge(
            &session_id,
            proof_domain_separator,
            threshold,
            p,
            old_participants.clone(),
            commitment_i,
            proof_i,
        )?;

        // verify that the commitment sent hashes to the received commitment_hash in round 1
        verify_commitment_hash(
            &session_id,
            p,
            commit_domain_separator,
            commitment_i,
            &all_hash_commitments,
        )?;

        // add received commitment and proof to the map
        all_commitments.put(p, commitment_i.clone());

        // Securely send to each other participant a secret share
        // using the evaluation secret polynomial on the identifier of the recipient
        let signing_share_to_p = evaluate_polynomial::<C>(&secret_coefficients, p)?;
        // send the evaluation privately to participant p
        chan.send_private(wait_round_3, p, &signing_share_to_p);
    }

    // compute the my secret evaluation of my private polynomial
    let mut my_signing_share = evaluate_polynomial::<C>(&secret_coefficients, me)?.to_scalar();

    // recreate the commitments map with the proper commitment sizes = threshold
    let mut all_full_commitments = ParticipantMap::new(&participants);
    let my_full_commitment = insert_identity_if_missing(threshold, all_commitments.index(me));
    all_full_commitments.put(me, my_full_commitment);

    // Start Round 4
    // receive evaluations from all participants
    let mut seen = ParticipantCounter::new(&participants);
    seen.put(me);
    while !seen.full() {
        let (from, signing_share_from): (Participant, SigningShare<C>) =
            chan.recv(wait_round_3).await?;
        if !seen.put(from) {
            continue;
        }

        let commitment_from = all_commitments.index(from);

        // in case the participant was new and it sent a polynomial of length
        // threshold -1 (because the zero term is not serializable)
        let full_commitment_from = insert_identity_if_missing(threshold, commitment_from);

        // Verify the share
        // this deviates from the original FROST DKG paper
        // however it matches the FROST implementation of ZCash
        validate_received_share::<C>(&me, &from, &signing_share_from, &full_commitment_from)?;

        // add full commitment
        all_full_commitments.put(from, full_commitment_from);

        // Compute the sum of all the owned secret shares
        // At the end of this loop, I will be owning a valid secret signing share
        my_signing_share = my_signing_share + signing_share_from.to_scalar();
    }

    // cannot fail as all_commitments at least contains my commitment
    let all_commitments_vec = all_full_commitments.into_vec_or_none().unwrap();
    let all_commitments_refs = all_commitments_vec.iter().collect();

    let verifying_key = public_key_from_commitments(all_commitments_refs)?;

    // In the case of Resharing, check if the old public key is the same as the new one
    if let Some(old_vk) = old_verification_key {
        // check the equality between the old key and the new key without failing the unwrap
        if old_vk != verifying_key {
            return Err(ProtocolError::AssertionFailed(
                "new public key does not match old public key".to_string(),
            ));
        }
    };

    // Start Round 5
    broadcast_success(&mut chan, &participants, &me, session_id).await?;
    // will never panic as broadcast_success_failure would panic before it

    // unwrap cannot fail as round 4 ensures failing if verification_key is None
    Ok(KeygenOutput {
        private_share: SigningShare::new(my_signing_share),
        public_key: verifying_key,
    })
}

/// Represents the output of the key generation protocol.
///
/// This contains our share of the private key, along with the public key.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KeygenOutput<C: Ciphersuite> {
    pub private_share: SigningShare<C>,
    pub public_key: VerifyingKey<C>,
}

pub(crate) async fn do_keygen<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
) -> Result<KeygenOutput<C>, ProtocolError> {
    // pick share at random
    let mut rng = OsRng;
    let secret = SigningKey::<C>::new(&mut rng).to_scalar();
    // call keyshare
    let keygen_output =
        do_keyshare::<C>(chan, participants, me, threshold, secret, None, rng).await?;
    Ok(keygen_output)
}

/// This function is to be called before running DKG
/// It ensures that the input parameters are valid
pub(crate) fn assert_keygen_invariants(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
) -> Result<ParticipantList, InitializationError> {
    // need enough participants
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    // validate threshold
    if threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            "threshold must be <= participant count".to_string(),
        ));
    }

    // ensure uniqueness of participants in the participant list
    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters("participant list cannot contain duplicates".to_string())
    })?;

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            format!("participant list must contain {me:?}").to_string(),
        ));
    };
    Ok(participants)
}

/// reshares the keyshares between the parties and allows changing the threshold
pub(crate) async fn do_reshare<C: Ciphersuite>(
    chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    threshold: usize,
    old_signing_key: Option<SigningShare<C>>,
    old_public_key: VerifyingKey<C>,
    old_participants: ParticipantList,
) -> Result<KeygenOutput<C>, ProtocolError> {
    // prepare the random number generator
    let rng = OsRng;

    let intersection = old_participants.intersection(&participants);
    // either extract the share and linearize it or set it to zero
    let secret = old_signing_key
        .map(|x_i| intersection.generic_lagrange::<C>(me) * x_i.to_scalar())
        .unwrap_or(<C::Group as Group>::Field::zero());

    let old_reshare_package = Some((old_public_key, old_participants));
    let keygen_output = do_keyshare::<C>(
        chan,
        participants,
        me,
        threshold,
        secret,
        old_reshare_package,
        rng,
    )
    .await?;

    Ok(keygen_output)
}

pub(crate) fn reshare_assertions<C: Ciphersuite>(
    participants: &[Participant],
    me: Participant,
    threshold: usize,
    old_signing_key: Option<SigningShare<C>>,
    old_threshold: usize,
    old_participants: &[Participant],
) -> Result<(ParticipantList, ParticipantList), InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };
    if threshold > participants.len() {
        return Err(InitializationError::BadParameters(
            format!(
                "new threshold {threshold:?} must be <= participant count {}",
                participants.len()
            )
            .to_string(),
        ));
    }

    let participants = ParticipantList::new(participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "new participant list cannot contain duplicates".to_string(),
        )
    })?;

    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(
            format!("participant list must contain {me:?}").to_string(),
        ));
    }

    let old_participants = ParticipantList::new(old_participants).ok_or_else(|| {
        InitializationError::BadParameters(
            "old participant list cannot contain duplicates".to_string(),
        )
    })?;

    if old_participants.intersection(&participants).len() < old_threshold {
        return Err(InitializationError::BadParameters(
            format!("not enough intersecting old/new participants {:?} to reconstruct private key for resharing with threshold bigger than old threshold {}",
            old_participants.intersection(&participants),
            old_threshold).to_string(),
        ));
    }
    // if me is not in the old participant set then ensure that old_signing_key is None
    if old_participants.contains(me) && old_signing_key.is_none() {
        return Err(InitializationError::BadParameters(
            format!("party {me:?} is present in the old participant list but provided no share")
                .to_string(),
        ));
    }
    Ok((participants, old_participants))
}

#[test]
fn test_domain_separate_hash() {
    let cnt = 1;
    let participants_1 = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let participants_2 = vec![
        Participant::from(0u32),
        Participant::from(1u32),
        Participant::from(2u32),
    ];
    let hash_1 = domain_separate_hash(cnt, &participants_1);
    let hash_2 = domain_separate_hash(cnt, &participants_2);
    assert!(hash_1 == hash_2);
    let hash_2 = domain_separate_hash(cnt + 1, &participants_2);
    assert!(hash_1 != hash_2);
}
