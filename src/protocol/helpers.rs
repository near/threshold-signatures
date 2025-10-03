//! Helper functions for the protocol.
use super::{internal::SharedChannel, Participant, ProtocolError};
use crate::participants::ParticipantList;

/// Gather exactly one message from each participant in a group before proceeding.
///
/// Note: Result vector order depends on the order messages arrive.
/// @dev If you ever need deterministic ordering (matching participant list), consider `BTreeMap`.
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut pending: std::collections::HashSet<Participant> = participants.others(me).collect();
    let mut messages = Vec::with_capacity(pending.len());

    while !pending.is_empty() {
        let (from, msg) = chan.recv(waitpoint).await?;
        // extra messages are silently ignored
        if pending.remove(&from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
}
