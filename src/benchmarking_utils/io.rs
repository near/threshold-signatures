use std::fs::{OpenOptions, create_dir_all};
use std::io::Write;
use fs2::FileExt; // for file locking
use std::path::Path;
use crate::Participant;
use crate::protocol::errors::BenchmarkError;

const DIR: &str = "snapshot_storage/";
const PARTICIPANT_LEN:usize = Participant::BYTES_LEN;

/// TODO
fn participant_to_str(participant: Participant) -> String{
    participant.bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

/// TODO
pub fn create_path(participant: Participant) -> String{
    let participant = participant_to_str(participant);
     format!("{}{}.txt", DIR, participant)
}

/// TODO
pub fn encode_send(from: Participant, to: Participant, message: &[u8]) -> Vec<u8> {
    let from = from.bytes();
    let to = to.bytes();
    let mut result = Vec::with_capacity(from.len() + to.len() + message.len());
    // Append all the items
    // No need for special characters as the participant bytes are of fixed size
    result.extend_from_slice(&from);
    result.extend_from_slice(&to);
    result.extend_from_slice(message);
    result
}

/// TODO
pub fn decode_send(encoding: &[u8]) -> Result<(Participant, Participant, Vec<u8>), BenchmarkError> {
    if encoding.len()<= 2 * PARTICIPANT_LEN {
        return Err(BenchmarkError::SendDecodingFailure(encoding.to_vec()));
    }

    // Split the data into sender, receiver, and payload
    let from = Participant::from_le_bytes(
        encoding[0..PARTICIPANT_LEN].try_into()
        .expect("The decoded data contains more than 9 bytes")
    );


    let to = Participant::from_le_bytes(
        encoding[PARTICIPANT_LEN..2 * PARTICIPANT_LEN].try_into()
        .expect("The decoded data contains more than 9 bytes")
    );

    let message = encoding[2 * PARTICIPANT_LEN..].to_vec();

    return Ok((from, to, message))
}

/// TODO
pub fn append_with_lock(path: &str, data: &[u8]) -> Result<(), BenchmarkError> {
    let path = Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        create_dir_all(parent).map_err(|_| BenchmarkError::DirCreationFailure)?;
    }

    // Open the file in append mode, create if it doesn't exist
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true) // Needed for locking on Unix
        .open(path)
        .map_err(|_| BenchmarkError::FileOpenFailure)?;

    // Lock the file exclusively using lock system
    file.lock_exclusive().map_err(|_| BenchmarkError::FileLockingFailure)?;
    // Write data
    file.write_all(&data).map_err(|_| BenchmarkError::FileWritingFailure)?;
    // Flush to ensure it's written
    file.flush().map_err(|_| BenchmarkError::FileFlushingFailure)?;
    // Unlock the file
    fs2::FileExt::unlock(&file).map_err(|_| BenchmarkError::FileUnlockingFailure)?;
    Ok(())
}