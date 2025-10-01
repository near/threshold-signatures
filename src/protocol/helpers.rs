//! Helper functions for the protocol.

use super::{internal::SharedChannel, Participant, ProtocolError};

/// Receive a message from a specific participant.
pub async fn recv_from<T>(
    chan: &mut SharedChannel,
    from: Participant,
    wait: u64,
) -> Result<T, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    loop {
        match chan.recv(wait).await? {
            (p, msg) if p == from => return Ok(msg),
            _ => {}
        }
    }
}

/// Gather exactly one message from each participant in a group before proceeding.
/// TODO: how about adding a timeout in case some participants failed to send a message?
pub async fn recv_from_many<T>(
    chan: &mut SharedChannel,
    participants: &[Participant],
    wait: u64,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut messages = Vec::with_capacity(participants.len());
    let mut received_from = std::collections::HashSet::new();

    for &p in participants {
        received_from.insert(p);
    }

    loop {
        let (from, msg) = chan.recv(wait).await?;
        if received_from.remove(&from) {
            messages.push((from, msg));
            if received_from.is_empty() {
                return Ok(messages);
            }
        }
    }
}
