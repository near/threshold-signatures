//! Helper functions for the protocol.
use super::{internal::SharedChannel, Participant, ProtocolError};

/// Gather exactly one message from each participant in a group before proceeding.
///
/// Note: Result vector order depends on the order messages arrive.
/// @dev If you ever need deterministic ordering (matching participant list), consider `BTreeMap`.
pub async fn recv_from_others<T, P>(
    chan: &mut SharedChannel,
    wait: u64,
    participants: P,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
    P: IntoIterator<Item = Participant>,
{
    let mut pending: std::collections::HashSet<Participant> = participants.into_iter().collect();
    let mut messages = Vec::with_capacity(pending.len());

    while !pending.is_empty() {
        let (from, msg) = chan.recv(wait).await?;
        // extra messages are silently ignored
        if pending.remove(&from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
}
