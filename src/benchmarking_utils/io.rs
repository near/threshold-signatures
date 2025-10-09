use std::fs::{OpenOptions, create_dir_all};
use std::io::{Write, Result};
use fs2::FileExt; // for file locking
use std::path::Path;

pub fn append_with_lock(path: &str, data: Vec<u8>) -> Result<()> {
    let path = Path::new(path);

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    // Open the file in append mode, create if it doesn't exist
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .read(true) // Needed for locking on Unix
        .open(path)?;

    // Lock the file exclusively using lock system
    file.lock_exclusive()?;
    // Write data
    file.write_all(&data)?;
    // Flush to ensure it's written
    file.flush()?;
    // Unlock the file
    file.unlock()?;

    Ok(())
}