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
pub async fn recv_from_many<T>(
    chan: &mut SharedChannel,
    wait: u64,
    participants: &[Participant],
    already_received: Option<&[Participant]>,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let mut messages = Vec::with_capacity(participants.len());
    let mut pending: std::collections::HashSet<_> = participants.iter().copied().collect();

    // remove already-received participants if provided
    if let Some(already) = already_received {
        for p in already {
            pending.remove(p);
        }
    }
    while !pending.is_empty() {
        let (from, msg) = chan.recv(wait).await?;
        if pending.remove(&from) {
            messages.push((from, msg));
        }
    }

    Ok(messages)
}
