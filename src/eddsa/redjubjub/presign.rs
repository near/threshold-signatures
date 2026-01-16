use super::{
    PresignArguments,
    PresignOutput,
};
use crate::{
    participants::{Participant, ParticipantList},
    errors::{InitializationError, ProtocolError},
    protocol::{
        helpers::recv_from_others,
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
};
use std::collections::BTreeMap;
use rand_core::CryptoRngCore;


use reddsa::frost::redjubjub::{
    Identifier,
    keys::SigningShare,
    round1::{SigningCommitments, commit},
};

pub fn presign(
    participants: &[Participant],
    me: Participant,
    args: PresignArguments,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = PresignOutput>, InitializationError> {
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    }

    let participants =
        ParticipantList::new(participants).ok_or(InitializationError::DuplicateParticipants)?;

    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    }

    let ctx = Comms::new();
    let fut = do_presign(ctx.shared_channel(), participants, me, args.keygen_out.private_share, rng);
    Ok(make_protocol(ctx, fut))
}

#[allow(clippy::too_many_lines)]
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    signing_share: SigningShare,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    // Round 1
    let mut commitments_map: BTreeMap<Identifier, SigningCommitments> =
        BTreeMap::new();

    // Creating two commitments and corresponding nonces
    let (nonces, commitments) = commit(&signing_share, &mut rng);
    // TODO decide: let nonces = Zeroizing::new(nonces);
    commitments_map.insert(me.to_identifier()?, commitments);

    let commit_waitpoint = chan.next_waitpoint();
    // Sending the commitments to all
    chan.send_many(commit_waitpoint, &commitments)?;
    
    // Collecting the commitments
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    Ok( PresignOutput{
            nonces,
            commitments_map,
    })
}

#[cfg(test)]
mod test {
    use crate::crypto::hash::hash;
    use crate::eddsa::redjubjub::{
        sign::sign,
        test::{build_key_packages_with_dealer, test_run_signature_presignature},
        KeygenOutput, SignatureOption, Signature,
    };
    use crate::participants::{Participant, ParticipantList};
    use crate::protocol::Protocol;
    use crate::test_utils::{
        assert_public_key_invariant, generate_participants, one_coordinator_output, run_keygen,
        run_refresh, run_reshare, MockCryptoRng,
    };
    use frost_core::{Field, Group};
    use reddsa::frost::redjubjub::{JubjubBlake2b512, JubjubScalarField, JubjubGroup};
    use rand::{Rng, RngCore, SeedableRng};

    fn assert_single_coordinator_result(
        data: &[(Participant, SignatureOption)],
    ) -> Signature {
        let mut signature = None;
        let count = data
            .iter()
            .filter(|(_, output)| {
                output.is_some_and(|s| {
                    signature = Some(s);
                    true
                })
            })
            .count();
        assert_eq!(count, 1);
        signature.unwrap()
    }

    #[test]
    fn basic_two_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 2;
        let threshold = 2;
        let actual_signers = 2;

        let key_packages = build_key_packages_with_dealer(max_signers, threshold, &mut rng);
        // add the presignatures here
        let data = test_run_signature_presignature(
            &key_packages,
            actual_signers,
        )
        .unwrap();
    }

    #[test]
    fn stress() {
        let mut rng = MockCryptoRng::seed_from_u64(42);

        let max_signers = 7;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        for min_signers in 2..max_signers {
            for actual_signers in min_signers..=max_signers {
                let key_packages =
                    build_key_packages_with_dealer(max_signers, min_signers, &mut rng);
                // add the presignatures here
                let coordinators = vec![key_packages[0].0];
                let data = test_run_signature_protocols(
                    &key_packages,
                    actual_signers.into(),
                    &coordinators,
                    min_signers.into(),
                    msg_hash,
                )
                .unwrap();
                assert_single_coordinator_result(&data);
            }
        }
    }

    #[test]
    fn dkg_sign_test() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = vec![
            Participant::from(0u32),
            Participant::from(31u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];
        let actual_signers = participants.len();
        let threshold = 2;
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        // test dkg
        let key_packages = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&key_packages);
        // add the presignatures here
        let coordinators = vec![key_packages[0].0];
        let data = test_run_signature_protocols(
            &key_packages,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        let signature = assert_single_coordinator_result(&data);

        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());

        // // test refresh
        let key_packages1 = run_refresh(&participants, &key_packages, threshold, &mut rng);
        assert_public_key_invariant(&key_packages1);
        let msg = "hello_near_2";
        let msg_hash = hash(&msg).unwrap();
        // add the presignatures here
        let data = test_run_signature_protocols(
            &key_packages1,
            actual_signers,
            &coordinators,
            threshold,
            msg_hash,
        )
        .unwrap();
        let signature = assert_single_coordinator_result(&data);
        let pub_key = key_packages1[2].1.public_key;
        assert!(key_packages1[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());

        // test reshare
        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(20u32));
        let new_threshold = 4;
        let key_packages2 = run_reshare(
            &participants,
            &pub_key,
            &key_packages1,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages2);
        let msg = "hello_near_3";
        let msg_hash = hash(&msg).unwrap();
        let coordinators = vec![key_packages2[0].0];
        // add the presignatures here
        let data = test_run_signature_protocols(
            &key_packages2,
            actual_signers,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = assert_single_coordinator_result(&data);
        assert!(key_packages2[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_reshare_sign_more_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(4);
        let threshold = 3;
        let result0 = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&result0);

        let pub_key = result0[2].1.public_key;

        // Run heavy reshare
        let new_threshold = 5;
        let mut new_participant = participants.clone();
        new_participant.push(Participant::from(31u32));
        new_participant.push(Participant::from(32u32));
        let key_packages = run_reshare(
            &participants,
            &pub_key,
            &result0,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages);

        let participants: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(val, _)| *val)
            .collect();
        let shares: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(_, keygen)| keygen.private_share.to_scalar())
            .collect();

        // Test public key
        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = JubjubScalarField::zero();
        for (p, share) in participants.iter().zip(shares.iter()) {
            x += p_list.lagrange::<JubjubBlake2b512>(*p).unwrap() * share;
        }
        assert_eq!(<JubjubGroup>::generator() * x, pub_key.to_element());

        // Sign
        let actual_signers = participants.len();
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        let coordinators = vec![key_packages[0].0];
        // add the presignatures here
        let data = test_run_signature_protocols(
            &key_packages,
            actual_signers,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = assert_single_coordinator_result(&data);
        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_reshare_sign_less_participants() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let participants = generate_participants(5);
        let threshold = 4;
        let result0 = run_keygen(&participants, threshold, &mut rng);
        assert_public_key_invariant(&result0);
        let coordinators = vec![result0[0].0];

        let pub_key = result0[2].1.public_key;

        // Run heavy reshare
        let new_threshold = 3;
        let mut new_participant = participants.clone();
        new_participant.pop();
        let key_packages = run_reshare(
            &participants,
            &pub_key,
            &result0,
            threshold,
            new_threshold,
            &new_participant,
            &mut rng,
        );
        assert_public_key_invariant(&key_packages);

        let participants: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(val, _)| *val)
            .collect();
        let shares: Vec<_> = key_packages
            .iter()
            .take(key_packages.len())
            .map(|(_, keygen)| keygen.private_share.to_scalar())
            .collect();

        // Test public key
        let p_list = ParticipantList::new(&participants).unwrap();
        let mut x = JubjubScalarField::zero();
        for (p, share) in participants.iter().zip(shares.iter()) {
            x += p_list.lagrange::<JubjubBlake2b512>(*p).unwrap() * share;
        }
        assert_eq!(<JubjubBlake2b512>::generator() * x, pub_key.to_element());

        // Sign
        let msg = "hello_near";
        let msg_hash = hash(&msg).unwrap();

        let data = test_run_signature_protocols(
            &key_packages,
            new_threshold,
            &coordinators,
            new_threshold,
            msg_hash,
        )
        .unwrap();
        let signature = assert_single_coordinator_result(&data);
        assert!(key_packages[0]
            .1
            .public_key
            .verify(msg_hash.as_ref(), &signature)
            .is_ok());
    }

    #[test]
    fn test_signature_correctness() {
        let mut rng = MockCryptoRng::seed_from_u64(42);
        let threshold = 6;
        let keys = build_key_packages_with_dealer(11, threshold, &mut rng);
        let public_key = keys[0].1.public_key.to_element();

        let msg = b"hello worldhello worldhello worlregerghwhrth".to_vec();
        let index = rng.gen_range(0..keys.len());
        let coordinator = keys[index as usize].0;

        let participants_sign_builder = keys
            .iter()
            .map(|(p, keygen_output)| {
                let rng_p = MockCryptoRng::seed_from_u64(rng.next_u64());
                (*p, (keygen_output.clone(), rng_p))
            })
            .collect();

        // This checks the output signature validity internally
        let result =
            crate::test_utils::run_sign::<JubjubBlake2b512, (KeygenOutput, MockCryptoRng), _, _>(
                participants_sign_builder,
                coordinator,
                public_key,
                JubjubScalarField::zero(),
                |participants, coordinator, me, _, (keygen_output, p_rng), _| {
                    sign(
                        participants,
                        threshold as usize,
                        me,
                        coordinator,
                        keygen_output,
                        presignatures,
                        msg.clone(),
                        p_rng,
                    )
                    .map(|sig| Box::new(sig) as Box<dyn Protocol<Output = SignatureOption>>)
                },
            )
            .unwrap();
        let signature = one_coordinator_output(result, coordinator).unwrap();

        insta::assert_json_snapshot!(signature);
    }
}
