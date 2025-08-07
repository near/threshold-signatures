use super::{CoefficientCommitment, KeygenOutput, CKDOutput};
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
    me: Participant,
    coordinator: Participant,
    participants: ParticipantList,
    my_keygen: KeygenOutput,
    app_id: &[u8],
    app_pk: CoefficientCommitment,
) -> Result<(),ProtocolError>{
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

    Ok(())
}

async fn do_ckd_coordinator(
    mut chan: SharedChannel,
    me: Participant,
    participants: ParticipantList,
    my_keygen: KeygenOutput,
    app_id: &[u8],
    app_pk: CoefficientCommitment,
) -> Result<CKDOutput,ProtocolError> {
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
    Ok(CKDOutput::new(norm_big_y, norm_big_c))
}

pub fn ckd(){

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
