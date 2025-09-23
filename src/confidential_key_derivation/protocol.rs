use std::ptr::null;

use crate::confidential_key_derivation::{
    from_secret_key_to_scalar, AppId, CKDCoordinatorOutput, CKDOutput, CoefficientCommitment,
    PublicKey, SecretKey,
};
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::{errors::InitializationError, errors::ProtocolError, Participant, Protocol};

use blst::min_pk::AggregatePublicKey;
use blst::{
    blst_hash_to_g1, blst_p1, blst_p1_add, blst_p1_affine, blst_p1_mult, blst_p1_to_affine,
    blst_scalar, blst_sk_inverse, blst_sk_mul_n_check, blst_sk_sub_n_check,
};
use rand_core::CryptoRngCore;

const DOMAIN: &[u8] = b"NEAR BLS12381G1_XMD:SHA-256_SSWU_RO_";

fn hash2curve(app_id: &AppId) -> PublicKey {
    let mut result = blst_p1::default();
    unsafe {
        blst_hash_to_g1(
            &mut result,
            app_id.as_ptr(),
            app_id.len(),
            DOMAIN.as_ptr(),
            DOMAIN.len(),
            null(),
            0,
        );
    }
    let mut result_affine = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut result_affine, &result);
    }
    result_affine.into()
}

fn bytes_to_scalar(input: &[u8]) -> blst_scalar {
    let mut output = [0u8; 32];
    output[0..input.len()].copy_from_slice(input);
    output[0] += 1;
    blst_scalar { b: output }
}

fn compute_lagrange_coefficient(points_set: &[blst_scalar], x_i: &blst_scalar) -> blst_scalar {
    let mut num = bytes_to_scalar(&[1]);
    let mut den = bytes_to_scalar(&[1]);
    let mut tmp = blst_scalar::default();

    for x_j in points_set.iter() {
        if *x_i == *x_j {
            continue;
        }
        // Both signs inverted just to avoid requiring an extra negation
        unsafe {
            blst_sk_mul_n_check(&mut num, &num, x_j);

            blst_sk_sub_n_check(&mut tmp, x_j, x_i);
            blst_sk_mul_n_check(&mut den, &den, &tmp);
        }
    }

    // denominator will never be 0 here, therefore it is safe to invert
    let mut result = blst_scalar::default();
    unsafe {
        blst_sk_inverse(&mut den, &den);
        blst_sk_mul_n_check(&mut result, &num, &den);
    }
    result
}

fn lagrange(p: Participant, participants: &ParticipantList) -> blst_scalar {
    let p = bytes_to_scalar(&p.bytes());
    let identifiers: Vec<blst_scalar> = participants
        .participants()
        .iter()
        .map(|p| bytes_to_scalar(&p.bytes()))
        .collect();
    compute_lagrange_coefficient(&identifiers, &p)
}

fn gen_random_key(rng: &mut impl CryptoRngCore) -> SecretKey {
    let mut ikm = [0u8; 32];
    rng.fill_bytes(&mut ikm);
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

fn ckd_crypto_helper(
    participants: &ParticipantList,
    me: Participant,
    private_share: SecretKey,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> (PublicKey, PublicKey) {
    // y <- ZZq* , Y <- y * G
    let y = gen_random_key(rng);
    let big_y = y.sk_to_pk();
    let big_y = AggregatePublicKey::from_public_key(&big_y).into();
    // H(app_id) when H is a random oracle
    let hash_point = hash2curve(app_id);
    let hash_point = AggregatePublicKey::from_public_key(&hash_point).into();
    // S <- x . H(app_id)
    let mut big_s = blst_p1::default();
    unsafe {
        blst_p1_mult(
            &mut big_s,
            &hash_point,
            from_secret_key_to_scalar(&private_share).b.as_ptr(),
            255,
        );
    }
    // C <- S + y . A
    let mut big_c = blst_p1::default();
    let app_pk = AggregatePublicKey::from_public_key(&app_pk).into();
    unsafe {
        blst_p1_mult(
            &mut big_c,
            &app_pk,
            from_secret_key_to_scalar(&y).b.as_ptr(),
            255,
        );
        blst_p1_add(&mut big_c, &big_c, &big_s);
    }
    // Compute λi := λi(0)
    let lambda_i = lagrange(me, participants);
    // Normalize Y and C into (λi . Y , λi . C)
    let mut norm_big_y = blst_p1::default();
    let mut norm_big_c = blst_p1::default();
    unsafe {
        blst_p1_mult(&mut norm_big_y, &big_y, lambda_i.b.as_ptr(), 255);
        blst_p1_mult(&mut norm_big_c, &big_c, lambda_i.b.as_ptr(), 255);
    }

    let mut norm_big_y_affine = blst_p1_affine::default();
    let mut norm_big_c_affine = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut norm_big_y_affine, &norm_big_y);
        blst_p1_to_affine(&mut norm_big_c_affine, &norm_big_c);
    }
    (norm_big_y_affine.into(), norm_big_c_affine.into())
}

#[allow(clippy::too_many_arguments)]
async fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: ParticipantList,
    coordinator: Participant,
    me: Participant,
    private_share: SecretKey,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        ckd_crypto_helper(&participants, me, private_share, app_id, app_pk, rng);

    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c))?;

    Ok(None)
}

async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    private_share: SecretKey,
    app_id: &AppId,
    app_pk: PublicKey,
    rng: &mut impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    let (norm_big_y, norm_big_c) =
        ckd_crypto_helper(&participants, me, private_share, app_id, app_pk, rng);
    let mut norm_big_y: blst_p1 = AggregatePublicKey::from_public_key(&norm_big_y).into();
    let mut norm_big_c: blst_p1 = AggregatePublicKey::from_public_key(&norm_big_c).into();

    // Receive everyone's inputs and add them together
    let mut seen = ParticipantCounter::new(&participants);
    let waitpoint = chan.next_waitpoint();

    seen.put(me);
    while !seen.full() {
        let (from, (big_y, big_c)): (_, (CoefficientCommitment, CoefficientCommitment)) =
            chan.recv(waitpoint).await?;
        if !seen.put(from) {
            continue;
        }
        let big_y = AggregatePublicKey::from_public_key(&big_y).into();
        let big_c = AggregatePublicKey::from_public_key(&big_c).into();
        unsafe {
            blst_p1_add(&mut norm_big_y, &norm_big_y, &big_y);
            blst_p1_add(&mut norm_big_c, &norm_big_c, &big_c);
        }
    }
    let mut norm_big_y_affine = blst_p1_affine::default();
    let mut norm_big_c_affine = blst_p1_affine::default();
    unsafe {
        blst_p1_to_affine(&mut norm_big_y_affine, &norm_big_y);
        blst_p1_to_affine(&mut norm_big_c_affine, &norm_big_c);
    }
    let ckd_output = CKDCoordinatorOutput::new(norm_big_y_affine.into(), norm_big_c_affine.into());
    Ok(Some(ckd_output))
}

/// Runs the confidential key derivation protocol
/// This exact same function is called for both
/// a coordinator and a normal participant.
/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn ckd(
    participants: &[Participant],
    coordinator: Participant,
    me: Participant,
    private_share: SecretKey,
    app_id: impl Into<AppId>,
    app_pk: PublicKey,
    rng: impl CryptoRngCore + Send + 'static,
) -> Result<impl Protocol<Output = CKDOutput>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::NotEnoughParticipants {
            participants: participants.len(),
        });
    };

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::DuplicateParticipants);
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::MissingParticipant {
            role: "self",
            participant: me,
        });
    };
    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::MissingParticipant {
            role: "coordinator",
            participant: coordinator,
        });
    };

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = run_ckd_protocol(
        chan,
        coordinator,
        me,
        participants,
        private_share,
        app_id.into(),
        app_pk,
        rng,
    );
    Ok(make_protocol(comms, fut))
}

/// Depending on whether the current participant is a coordinator or not,
/// runs the ckd protocol as either a participant or a coordinator.
#[allow(clippy::too_many_arguments)]
async fn run_ckd_protocol(
    chan: SharedChannel,
    coordinator: Participant,
    me: Participant,
    participants: ParticipantList,
    private_share: SecretKey,
    app_id: AppId,
    app_pk: PublicKey,
    mut rng: impl CryptoRngCore,
) -> Result<CKDOutput, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(
            chan,
            participants,
            me,
            private_share,
            &app_id,
            app_pk,
            &mut rng,
        )
        .await
    } else {
        do_ckd_participant(
            chan,
            participants,
            coordinator,
            me,
            private_share,
            &app_id,
            app_pk,
            &mut rng,
        )
        .await
    }
}

#[cfg(test)]
mod test {
    use blst::blst_sk_add_n_check;

    use super::*;
    use crate::confidential_key_derivation::from_secret_key_to_scalar;
    use crate::protocol::run_protocol;
    use std::error::Error;

    use rand_core::{OsRng, RngCore};

    #[test]
    fn test_hash2curve() -> Result<(), Box<dyn Error>> {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = hash2curve(&AppId::from(app_id));
        let pt2 = hash2curve(&AppId::from(app_id_same));
        assert!(pt1 == pt2);

        let app_id = b"Hello Near!";
        let pt2 = hash2curve(&AppId::from(app_id));
        assert!(pt1 != pt2);
        Ok(())
    }

    #[test]
    fn test_ckd() -> Result<(), Box<dyn Error>> {
        // Create the app necessary items
        let app_id = AppId::from(b"Near App");
        let app_sk = gen_random_key(&mut OsRng);
        let app_pk = app_sk.sk_to_pk();

        let participants = vec![
            Participant::from(0u32),
            Participant::from(1u32),
            Participant::from(2u32),
        ];

        // choose a coordinator at random
        let index = OsRng.next_u32() % participants.len() as u32;
        let coordinator = participants[index as usize];

        let mut protocols: Vec<(Participant, Box<dyn Protocol<Output = CKDOutput>>)> =
            Vec::with_capacity(participants.len());

        let mut private_shares = Vec::new();
        for p in &participants {
            let private_share = gen_random_key(&mut OsRng);
            private_shares.push(private_share.clone());

            let protocol = ckd(
                &participants,
                coordinator,
                *p,
                private_share,
                app_id.clone(),
                app_pk,
                OsRng,
            )?;

            protocols.push((*p, Box::new(protocol)));
        }

        let result = run_protocol(protocols)?;

        // test one single some for the coordinator
        let mut some_iter = result.into_iter().filter(|(_, ckd)| ckd.is_some());

        let ckd = some_iter
            .next()
            .map(|(_, c)| c.unwrap())
            .expect("Expected exactly one Some(CKDCoordinatorOutput)");
        assert!(
            some_iter.next().is_none(),
            "More than one Some(CKDCoordinatorOutput)"
        );

        // compute msk . H(app_id)
        let confidential_key = ckd.unmask(app_sk);

        let participants = ParticipantList::new(&participants).unwrap();
        let mut msk = blst_scalar::default();
        for (i, private_share) in private_shares.iter().enumerate() {
            let me = participants.get_participant(i).unwrap();
            let lambda_i = lagrange(me, &participants);
            let mut scalar: blst_scalar = from_secret_key_to_scalar(private_share);
            unsafe {
                blst_sk_mul_n_check(&mut scalar, &scalar, &lambda_i);
                blst_sk_add_n_check(&mut msk, &msk, &scalar);
            }
        }

        let mut expected_confidential_key = blst_p1::default();
        let mut expected_confidential_key_affine = blst_p1_affine::default();
        unsafe {
            let hash = AggregatePublicKey::from_public_key(&hash2curve(&app_id)).into();
            blst_p1_mult(&mut expected_confidential_key, &hash, msk.b.as_ptr(), 255);
            blst_p1_to_affine(
                &mut expected_confidential_key_affine,
                &expected_confidential_key,
            );
        }

        let expected_confidential_key: PublicKey = expected_confidential_key_affine.into();

        assert_eq!(
            confidential_key, expected_confidential_key,
            "Keys should be equal"
        );
        Ok(())
    }
}
