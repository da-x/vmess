use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::Error;
use log::debug;
use regex::Regex;

lazy_static::lazy_static! {
    static ref FROZEN_SUFFIX: Regex = Regex::new(r"@@[a-f0-9]+$").unwrap();
}

pub(crate) fn bash_stdout(cmd: String) -> Result<String, Error> {
    use std::process::Command;
    debug!("bash output: {:?}", cmd.trim());
    let out = Command::new("bash").arg("-c").arg(&cmd).output()?;
    if !out.status.success() {
        return Err(
            Error::CommandError(cmd, String::from_utf8_lossy(&out.stderr).into_owned()).into(),
        );
    }
    Ok(String::from_utf8(out.stdout)?)
}

pub(crate) fn adjust_path_by_env(path: PathBuf) -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        let path = path
            .into_os_string()
            .into_string()
            .unwrap()
            .replace("$HOME", &home.into_os_string().into_string().unwrap());
        PathBuf::try_from(path).expect("cannot convert path")
    } else {
        path
    }
}

pub(crate) trait AddExtension {
    fn add_extension(&self, extension: impl AsRef<std::path::Path>) -> PathBuf;
}

impl AddExtension for PathBuf {
    fn add_extension(&self, extension: impl AsRef<std::path::Path>) -> PathBuf {
        let mut path = self.clone();
        match path.extension() {
            Some(ext) => {
                let mut ext = ext.to_os_string();
                ext.push(".");
                ext.push(extension.as_ref());
                path.set_extension(ext)
            }
            None => path.set_extension(extension.as_ref()),
        };

        path
    }
}

pub(crate) fn calculate_hash<T: Hash>(t: &T) -> u64 {
    let mut s = DefaultHasher::new();
    t.hash(&mut s);
    s.finish()
}

pub(crate) fn is_version_at_least(version_str: &str, min_version: &[u32]) -> bool {
    let version_numbers: Vec<u32> = version_str
        .trim()
        .split('.')
        .map(|s| s.parse::<u32>().unwrap())
        .collect();

    version_numbers.as_slice() > min_version
}

#[macro_export]
macro_rules! ibash_stdout {
    ($($arg:tt)*) => { crate::utils::bash_stdout(f!($($arg)*)) }
}

pub(crate) fn read_qcow2_backing_file(qcow2_path: &Path) -> Result<Option<String>, Error> {
    let mut file = File::open(qcow2_path)?;

    // Read backing_file_offset at offset 8 (64-bit big-endian)
    file.seek(SeekFrom::Start(8))?;
    let mut buffer = [0u8; 8];
    file.read_exact(&mut buffer)?;
    let backing_file_offset = u64::from_be_bytes(buffer);

    // If offset is 0, there's no backing file
    if backing_file_offset == 0 {
        return Ok(None);
    }

    // Read backing_file_size at offset 16 (32-bit big-endian)
    file.seek(SeekFrom::Start(16))?;
    let mut buffer = [0u8; 4];
    file.read_exact(&mut buffer)?;
    let backing_file_size = u32::from_be_bytes(buffer);

    // If size is 0, there's no backing file
    if backing_file_size == 0 {
        return Ok(None);
    }

    // Read the backing file name
    file.seek(SeekFrom::Start(backing_file_offset))?;
    let mut name_buffer = vec![0u8; backing_file_size as usize];
    file.read_exact(&mut name_buffer)?;

    // Convert bytes to string
    let backing_file_name = String::from_utf8(name_buffer)
        .map_err(|_| Error::FreeText("Invalid UTF-8 in qcow2 backing file name".to_string()))?;

    Ok(Some(backing_file_name))
}

pub(crate) fn get_qcow2_backing_chain(qcow2_path: &Path) -> Result<Vec<PathBuf>, Error> {
    let mut chain = vec![];
    let mut current_path = qcow2_path.to_path_buf();
    let base_dir = qcow2_path.parent().unwrap_or_else(|| Path::new("."));

    loop {
        // Check if we've seen this path before (loop detection)
        if chain.contains(&current_path) {
            return Err(Error::FreeText(
                "Loop detected in qcow2 backing chain".to_string(),
            ));
        }

        // Check if current file exists
        if !current_path.exists() {
            return Err(Error::FreeText(format!(
                "Missing file in qcow2 backing chain: {}",
                current_path.display()
            )));
        }

        // Add current path to chain
        chain.push(current_path.clone());

        // Read backing store from current file
        match read_qcow2_backing_file(&current_path)? {
            Some(backing_name) => {
                let backing_path = if Path::new(&backing_name).is_absolute() {
                    PathBuf::from(backing_name)
                } else {
                    base_dir.join(backing_name)
                };

                // Stop if backing store points outside current directory
                if let Ok(canonical_backing) = backing_path.canonicalize() {
                    if let Ok(canonical_base) = base_dir.canonicalize() {
                        if !canonical_backing.starts_with(&canonical_base) {
                            return Err(Error::FreeText(format!(
                                "Backing store points outside current directory: {}",
                                backing_path.display()
                            )));
                        }
                    }
                } else {
                    return Err(Error::FreeText(format!(
                        "Cannot resolve backing store path: {}",
                        backing_path.display()
                    )));
                }

                // Continue with the backing file
                current_path = backing_path;
            }
            None => break, // No backing file
        }
    }

    Ok(chain)
}

pub(crate) fn is_frozen_snapshot(filename: &str) -> bool {
    FROZEN_SUFFIX.is_match(filename)
}

pub(crate) fn strip_frozen_suffix(filename: &str) -> String {
    FROZEN_SUFFIX.replace(filename, "").to_string()
}

pub(crate) fn write_qcow2_backing_file(
    qcow2_path: &Path,
    backing_file_name: Option<&str>,
) -> Result<(), Error> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(qcow2_path)?;

    // First, read the existing backing_file_offset to ensure it's non-zero
    file.seek(SeekFrom::Start(8))?;
    let mut buffer = [0u8; 8];
    file.read_exact(&mut buffer)?;
    let existing_backing_file_offset = u64::from_be_bytes(buffer);

    if existing_backing_file_offset == 0 {
        return Err(Error::FreeText("qcow2 file has no existing backing file offset - only files with existing backing stores are supported".to_string()));
    }

    match backing_file_name {
        Some(backing_name) => {
            // Ensure backing file name doesn't exceed our assumption of 1024 bytes
            if backing_name.len() > 1024 {
                return Err(Error::FreeText(format!(
                    "Backing file name too long: {} bytes (max 1024)",
                    backing_name.len()
                )));
            }

            let backing_name_bytes = backing_name.as_bytes();
            let backing_file_size = backing_name_bytes.len() as u32;

            // Use the existing backing file offset
            let backing_file_offset = existing_backing_file_offset;

            // Write backing_file_size at offset 16 (32-bit big-endian)
            file.seek(SeekFrom::Start(16))?;
            file.write_all(&backing_file_size.to_be_bytes())?;

            // Write the backing file name at the existing offset
            file.seek(SeekFrom::Start(backing_file_offset))?;
            file.write_all(backing_name_bytes)?;

            // Pad with zeros if the new name is shorter than the space available
            // (assuming we have at least 1024 bytes of space as specified)
            let remaining_space = 1024 - backing_name_bytes.len();
            if remaining_space > 0 {
                let padding = vec![0u8; remaining_space];
                file.write_all(&padding)?;
            }
        }
        None => {
            // Clear backing file by setting size to 0 (keep offset as-is)
            file.seek(SeekFrom::Start(16))?;
            file.write_all(&0u32.to_be_bytes())?;
        }
    }

    file.sync_all()?;
    Ok(())
}
