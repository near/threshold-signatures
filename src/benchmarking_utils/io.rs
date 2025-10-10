use crate::protocol::errors::BenchmarkError;
use crate::Participant;
use fs2::FileExt; // for file locking
use std::fs::{create_dir_all, read, remove_dir, remove_file, OpenOptions};
use std::io::Write;
use std::path::Path;

const DIR: &str = "snapshot_storage/";
const PARTICIPANT_LEN: usize = Participant::BYTES_LEN;
const SIZEOF_USIZE: usize = std::mem::size_of::<usize>();

/// Encodes a `message` sent to a participant `to` in raw bytes
/// following the format <`to` `message.len()` `message`>
fn encode_send(to: Participant, message: &[u8]) -> Vec<u8> {
    // 4 bytes for the length of the message
    let mut result = Vec::with_capacity(PARTICIPANT_LEN + SIZEOF_USIZE + message.len());
    // Append all the items
    // No need for special characters as the participant bytes are of fixed size
    result.extend_from_slice(&to.bytes());
    result.extend_from_slice(&message.len().to_le_bytes());
    result.extend_from_slice(message);
    result
}

/// Decodes a sequence of encoded bytes `encoding` into a (participant, message)
/// The encoding could be much longer than just participant and a message
/// The function returns both participant and message and the size of the decoded data
fn decode_send(encoding: &[u8]) -> Result<(Participant, Vec<u8>, usize), BenchmarkError> {
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

/// Creates a file using a participant in a fixed directory
/// Example of file created: `snapshot_storage/P1.raw`
fn create_path(participant: Participant) -> String {
    // transforms a participant into a string
    let participant = u32::from_le_bytes(participant.bytes()).to_string();
    format!("{DIR}P{participant}.raw")
}

/// Appends to a given file into a sequence of (participant, message)
fn file_append_with_lock(path: &str, data: &[u8]) -> Result<(), BenchmarkError> {
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

/// Creates or opens in a file generated `from` the sender's information
/// and encodes a message sent by `from` as <`to` `message.len()` `message`> in raw bytes
pub fn encode_in_file(
    from: Participant,
    to: Participant,
    message: &[u8],
) -> Result<(), BenchmarkError> {
    let path = create_path(from);
    let message = encode_send(to, message);
    file_append_with_lock(&path, &message)
}

/// Decodes a given encoded file into a sequence of (participant, message)
fn decode_file(path: &str) -> Result<Vec<(Participant, Vec<u8>)>, BenchmarkError> {
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

/// The file is decoded into a sequence of (participant, message).
/// The file is consumed (deleted) then the directory is delete if empty
#[allow(dead_code)]
pub fn consume_file(
    participant: Participant,
) -> Result<Vec<(Participant, Vec<u8>)>, BenchmarkError> {
    let path = create_path(participant);
    let decoding = decode_file(&path)?;
    // consume the file
    let path = Path::new(&path);
    remove_file(path).map_err(|_| BenchmarkError::FileDeletionFailure)?;
    // remove the parent directory if empty
    if let Some(parent) = path.parent() {
        remove_dir(parent).map_err(|_| BenchmarkError::DirDeletionFailure)?;
    }
    Ok(decoding)
}
