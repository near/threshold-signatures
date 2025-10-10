use crate::protocol::errors::BenchmarkError;
use crate::Participant;
use fs2::FileExt; // for file locking
use std::fs::{create_dir_all, read, OpenOptions};
use std::io::Write;
use std::path::Path;

const DIR: &str = "snapshot_storage/";
const PARTICIPANT_LEN: usize = Participant::BYTES_LEN;
const SIZEOF_USIZE: usize = std::mem::size_of::<usize>();

/// TODO
pub fn encode_send(to: Participant, message: &[u8]) -> Vec<u8> {
    // 4 bytes for the length of the message
    let mut result = Vec::with_capacity(PARTICIPANT_LEN + SIZEOF_USIZE + message.len());
    // Append all the items
    // No need for special characters as the participant bytes are of fixed size
    result.extend_from_slice(&to.bytes());
    result.extend_from_slice(&message.len().to_le_bytes());
    result.extend_from_slice(message);
    result
}

/// TODO
pub fn decode_send(encoding: &[u8]) -> Result<(Participant, Vec<u8>, usize), BenchmarkError> {
    let fixed_size = PARTICIPANT_LEN + SIZEOF_USIZE;
    if encoding.len() <= fixed_size {
        return Err(BenchmarkError::SendDecodingFailure(encoding.to_vec()));
    }

    // Split the data into receiver, payload_len and payload
    let to = Participant::from_le_bytes(
        encoding[..PARTICIPANT_LEN]
            .try_into()
            .expect("The decoded data contains enough bytes"),
    );

    let message_len = usize::from_le_bytes(
        encoding[PARTICIPANT_LEN..fixed_size]
            .try_into()
            .expect("The decoded data contains enough bytes"),
    );

    let decoded_size = fixed_size + message_len;
    // assumes that the addition does not overflow
    if encoding.len() < decoded_size {
        return Err(BenchmarkError::SendDecodingFailure(encoding.to_vec()));
    }

    let message = encoding[fixed_size..fixed_size + message_len].to_vec();

    Ok((to, message, decoded_size))
}

/// TODO
pub fn create_path(participant: Participant) -> String {
    // transforms a participant into a string
    let participant = u32::from_le_bytes(participant.bytes()).to_string();
    format!("{DIR}P{participant}.raw")
}

/// TODO
pub fn file_append_with_lock(path: &str, data: &[u8]) -> Result<(), BenchmarkError> {
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
    file.lock_exclusive()
        .map_err(|_| BenchmarkError::FileLockingFailure)?;
    // Write data
    file.write_all(data)
        .map_err(|_| BenchmarkError::FileWritingFailure)?;
    // Flush to ensure it's written
    file.flush()
        .map_err(|_| BenchmarkError::FileFlushingFailure)?;
    // Unlock the file
    fs2::FileExt::unlock(&file).map_err(|_| BenchmarkError::FileUnlockingFailure)?;
    Ok(())
}

pub fn file_decode(path: &str) -> Result<Vec<(Participant, Vec<u8>)>, BenchmarkError> {
    let path = Path::new(path);

    // Check if the directory exists
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            return Err(BenchmarkError::DirNotFound);
        }
    }

    // Check if the file exists
    if !path.exists() {
        return Err(BenchmarkError::FileNotFound);
    }

    // Read the file
    let encoded_contents = read(path).map_err(|_| BenchmarkError::FileReadingFailure)?;

    let mut index = 0;
    let mut decoding_db: Vec<(Participant, Vec<u8>)> = Vec::new();

    while index < encoded_contents.len() {
        let (to, message, decoded_size) = decode_send(&encoded_contents[index..])?;
        decoding_db.push((to, message));
        index += decoded_size;
    }

    Ok(decoding_db)
}
