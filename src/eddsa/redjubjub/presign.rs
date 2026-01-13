use super::{PresignArguments, PresignOutput, SigningShare};
use crate::{
    participants::{Participant, ParticipantList},
    errors::{InitializationError, ProtocolError},
    protocol::{
        internal::{make_protocol, Comms, SharedChannel},
        Protocol,
    },
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;
use rand_core::CryptoRngCore;
use frost_core::round1;


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

/// /!\ Warning: the threshold in this scheme is the exactly the
///              same as the max number of malicious parties.
#[allow(clippy::too_many_lines)]
async fn do_presign(
    mut chan: SharedChannel,
    participants: ParticipantList,
    me: Participant,
    signing_share: SigningShare,
    mut rng: impl CryptoRngCore,
) -> Result<PresignOutput, ProtocolError> {
    // Round 1
    let mut commitments_map: BTreeMap<frost_ed25519::Identifier, round1::SigningCommitments> =
        BTreeMap::new();


    // Step 1.1 (and implicitely 1.2)
    let (nonces, commitments) = round1::commit(&signing_share, rng);
    let nonces = Zeroizing::new(nonces);
    commitments_map.insert(me.to_identifier()?, commitments);

    // Step 1.3
    let commit_waitpoint = chan.next_waitpoint();

    // Step 1.4
    for (from, commitment) in recv_from_others(&chan, commit_waitpoint, &participants, me).await? {
        commitments_map.insert(from.to_identifier()?, commitment);
    }

    unimplemented!()
}