//! Helper functions for the protocol.
use super::{internal::SharedChannel, Participant, ProtocolError};
use crate::participants::{ParticipantList, ParticipantMap};

/// Gather exactly one message from each participant in a group before proceeding.
pub async fn recv_from_others<T>(
    chan: &SharedChannel,
    waitpoint: u64,
    participants: &ParticipantList,
    me: Participant,
) -> Result<Vec<(Participant, T)>, ProtocolError>
where
    T: serde::de::DeserializeOwned,
{
    let others_vec: Vec<Participant> = participants.others(me).collect();
    let others_list = ParticipantList::new(&others_vec)
        .ok_or_else(|| ProtocolError::Other("participant list has duplicates".to_string()))?;
    let mut messages_map = ParticipantMap::new(&others_list);

    while !messages_map.full() {
        let (from, msg) = chan.recv(waitpoint).await?;
        // `put` will ignore messages from unknown participants or duplicates
        messages_map.put(from, msg);
    }

    // `into_vec_or_none` consumes the map and returns `Option<Vec<T>>`.
    // If the map is full, this will be `Some`.
    let data_vec = messages_map.into_vec_or_none().unwrap();
    let messages = others_list
        .participants()
        .iter()
        .zip(data_vec.into_iter())
        .map(|(&p, d)| (p, d))
        .collect();

    Ok(messages)
}
