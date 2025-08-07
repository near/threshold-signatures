use super::{CoefficientCommitment, KeygenOutput, CKDOutput, CKDCommitments};
use crate::participants::{ParticipantCounter, ParticipantList};
use crate::protocol::internal::{make_protocol, Comms, SharedChannel};
use crate::protocol::{InitializationError, Participant, Protocol, ProtocolError};

use frost_core::Ciphersuite;
use rand_core::OsRng;

use frost_secp256k1::Secp256K1Sha256;

use k256::{
    elliptic_curve::hash2curve::{ExpandMsgXof, GroupDigest},
    Secp256k1,
};
use k256::ProjectivePoint;

const DOMAIN: &[u8] = b"NEAR CURVE_XOF:SHAKE-256_SSWU_RO_";

fn random_oracle_to_element(app_id: &[u8]) -> Result<ProjectivePoint,ProtocolError>{
    let hash = <Secp256k1 as GroupDigest>::hash_from_bytes
                    ::<ExpandMsgXof<sha3::Shake256>>(&[app_id], &[DOMAIN])
                    .map_err(|_| ProtocolError::ZeroScalar)?;
    Ok(hash)
}

async fn do_ckd_participant(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    coordinator: Participant,
    my_keygen: KeygenOutput,
    app_id: &[u8],
    app_pk: CoefficientCommitment,
) -> Result<CKDOutput,ProtocolError>{
    // y <- ZZq* , Y <- y * G
    let (y, big_y) = Secp256K1Sha256::generate_nonce(&mut OsRng);
    // H(app_id) when H is a random oracle
    let hash_point = random_oracle_to_element(app_id)?;
    // S <- x . H(app_id)
    let big_s =  hash_point * my_keygen.private_share.to_scalar();
    // C <- S + y . A
    let big_c = big_s + app_pk.value()* y;
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<Secp256K1Sha256>(me);
    // Normalize Y and C into  (λi . Y , λi . C)
    let norm_big_y = CoefficientCommitment::new(big_y * lambda_i);
    let norm_big_c = CoefficientCommitment::new(big_c * lambda_i);

    let waitpoint = chan.next_waitpoint();
    chan.send_private(waitpoint, coordinator, &(norm_big_y, norm_big_c));

    Ok(None)
}

async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    my_keygen: KeygenOutput,
    app_id: &[u8],
    app_pk: CoefficientCommitment,
) -> Result<CKDOutput, ProtocolError> {
    // y <- ZZq* , Y <- y * G
    let (y, big_y) = Secp256K1Sha256::generate_nonce(&mut OsRng);
    // H(app_id) when H is a random oracle
    let hash_point = random_oracle_to_element(app_id)?;
    // S <- x . H(app_id)
    let big_s =  hash_point * my_keygen.private_share.to_scalar();
    // C <- S + y . A
    let big_c = big_s + app_pk.value()* y;
    // Compute  λi := λi(0)
    let lambda_i = participants.lagrange::<Secp256K1Sha256>(me);
    // Normalize Y and C into  (λi . Y , λi . C)
    let mut norm_big_y = big_y * lambda_i;
    let mut norm_big_c = big_c * lambda_i;


    // Receive everyone's inputs and add them together
    let mut seen = ParticipantCounter::new(&participants);
    let waitpoint = chan.next_waitpoint();

    seen.put(me);
    while !seen.full() {
        let (from, (big_y, big_c)): (_, (CoefficientCommitment, CoefficientCommitment))
                                    = chan.recv(waitpoint).await?;
        if !seen.put(from) {
            continue;
        }
        norm_big_y = norm_big_y + big_y.value();
        norm_big_c = norm_big_c + big_c.value();
    };
    let ckdcommitments = CKDCommitments::new(norm_big_y, norm_big_c);
    Ok(Some(ckdcommitments))
}


/// Runs the confidential key derivation protocol
/// This exact same function is called for both
/// a coordinator and a normal participant.
/// Depending on whether the current participant is a coordinator or not,
/// runs the signature protocol as either a participant or a coordinator.
pub fn ckd(
    participants: &[Participant],
    me: Participant,
    coordinator: Participant,
    my_keygen: KeygenOutput,
    app_id:  Vec<u8>,
    app_pk: CoefficientCommitment,
) -> Result<impl Protocol<Output = CKDOutput>, InitializationError> {
    // not enough participants
    if participants.len() < 2 {
        return Err(InitializationError::BadParameters(format!(
            "participant count cannot be < 2, found: {}",
            participants.len()
        )));
    };

    // kick out duplicates
    let Some(participants) = ParticipantList::new(participants) else {
        return Err(InitializationError::BadParameters(
            "Participants list contains duplicates".to_string(),
        ));
    };

    // ensure my presence in the participant list
    if !participants.contains(me) {
        return Err(InitializationError::BadParameters(format!(
            "participant list must contain {me:?}"
        )));
    };
    // ensure the coordinator is a participant
    if !participants.contains(coordinator) {
        return Err(InitializationError::BadParameters(format!(
            "participant list must contain coordinator {coordinator:?}"
        )));
    };

    let comms = Comms::new();
    let chan = comms.shared_channel();

    let fut = fut_wrapper(
                chan,
                me,
                coordinator,
                participants,
                my_keygen,
                app_id,
                app_pk
            );
    Ok(make_protocol(comms, fut))
}


/// Depending on whether the current participant is a coordinator or not,
/// runs the ckd protocol as either a participant or a coordinator.
async fn fut_wrapper(
    chan: SharedChannel,
    me: Participant,
    coordinator: Participant,
    participants: ParticipantList,
    my_keygen: KeygenOutput,
    app_id: Vec<u8>,
    app_pk: CoefficientCommitment,
) -> Result<CKDOutput, ProtocolError> {
    if me == coordinator {
        do_ckd_coordinator(chan, participants, me, my_keygen, &app_id, app_pk).await
    } else {
        do_ckd_participant(chan, participants, me, coordinator, my_keygen, &app_id, app_pk).await
    }
}


#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_random_oracle() {
        let app_id = b"Hello Near";
        let app_id_same = b"Hello Near";
        let pt1 = random_oracle_to_element(app_id).unwrap();
        let pt2 = random_oracle_to_element(app_id_same).unwrap();
        assert!(pt1 == pt2);

        let app_id = b"Hello Near!";
        let pt2 = random_oracle_to_element(app_id).unwrap();
        assert!(pt1 != pt2);
    }
}
