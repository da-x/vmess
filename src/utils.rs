use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use super::Error;
use log::debug;
use regex::Regex;
use serde::Deserialize;

lazy_static::lazy_static! {
    static ref FROZEN_SUFFIX: Regex = Regex::new(r"@@[a-f0-9]+$").unwrap();
}

#[derive(Debug)]
pub(crate) struct BackingChainInfo {
    // First layer is the image, second is backing for first, last layer is root.
    pub chain: Vec<StoredLayer>,
}

#[derive(Debug)]
pub(crate) struct StoredLayer {
    pub basename: PathBuf,      // Just the filename, `ubuntu-18%nfsrdma.qcow2`.
    pub real_location: PathBuf, // Directory in which the real filename is stored, i.e. not sylinks.
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

/// Starting from absolute qcow2_path which is under one of the lookup_paths (verify this!), we
/// read the backing image, finding the exactly singular lookup_path that contains it as a real
/// file and not a symlink. We do this until finding the root.
pub(crate) fn get_qcow2_backing_chain(
    qcow2_path: &Path,
    lookup_paths: &[PathBuf],
) -> Result<BackingChainInfo, Error> {
    let mut chain = vec![];
    let mut current_path = qcow2_path.to_path_buf();
    let mut visited_paths = std::collections::HashSet::new();

    // Verify that the initial qcow2_path is under one of the lookup_paths
    let initial_basename = current_path
        .file_name()
        .ok_or_else(|| Error::FreeText("Invalid qcow2 path - no filename".to_string()))?;

    let mut initial_real_location = None;
    for lookup_path in lookup_paths {
        let candidate_path = lookup_path.join(&initial_basename);
        if candidate_path == current_path {
            // Verify it's a real file, not a symlink
            if let Ok(symlink_metadata) = std::fs::symlink_metadata(&current_path) {
                if !symlink_metadata.file_type().is_symlink() {
                    initial_real_location = Some(lookup_path.clone());
                    break;
                }
            }
        }
    }

    initial_real_location.ok_or_else(|| {
        Error::FreeText(format!(
            "qcow2_path '{}' is not found as a real file under any lookup_path",
            current_path.display()
        ))
    })?;

    loop {
        // Check if we've seen this path before (loop detection)
        if visited_paths.contains(&current_path) {
            return Err(Error::FreeText(
                "Loop detected in qcow2 backing chain".to_string(),
            ));
        }
        visited_paths.insert(current_path.clone());

        // Check if current file exists
        if !current_path.exists() {
            return Err(Error::FreeText(format!(
                "Missing file in qcow2 backing chain: {}",
                current_path.display()
            )));
        }

        // Get basename and find the real location
        let basename = current_path.file_name().ok_or_else(|| {
            Error::FreeText(format!(
                "Invalid path in backing chain - no filename: {}",
                current_path.display()
            ))
        })?;
        let basename = PathBuf::from(basename);

        // Find exactly one lookup_path that contains this file as a real file (not symlink)
        let mut real_location = None;
        for lookup_path in lookup_paths {
            let candidate_path = lookup_path.join(&basename);
            if candidate_path.exists() {
                // Check if it's a real file, not a symlink
                if let Ok(symlink_metadata) = std::fs::symlink_metadata(&candidate_path) {
                    if !symlink_metadata.file_type().is_symlink() {
                        if real_location.is_some() {
                            return Err(Error::FreeText(format!(
                                "Multiple real locations found for file '{}' - expected exactly one",
                                basename.display()
                            )));
                        }
                        real_location = Some(lookup_path.clone());
                    }
                }
            }
        }

        let real_location = real_location.ok_or_else(|| {
            Error::FreeText(format!(
                "No real location found for file '{}' in any lookup directory",
                basename.display()
            ))
        })?;

        // Add to chain
        chain.push(StoredLayer {
            basename: basename.clone(),
            real_location,
        });

        // Read backing store from current file
        match read_qcow2_backing_file(&current_path)? {
            Some(backing_name) => {
                // Skip images with backing store names that contain paths
                if backing_name.contains('/')
                    || backing_name.contains('\\')
                    || Path::new(&backing_name).is_absolute()
                {
                    return Err(Error::FreeText(format!(
                        "Backing store filename contains path separators, skipping: '{}'",
                        backing_name
                    )));
                }

                // Simple filename - search for exactly one real file in lookup directories
                let mut found_backing_path = None;
                for lookup_path in lookup_paths {
                    let candidate_path = lookup_path.join(&backing_name);
                    if candidate_path.exists() {
                        // Check if it's a real file, not a symlink
                        if let Ok(symlink_metadata) = std::fs::symlink_metadata(&candidate_path) {
                            if symlink_metadata.file_type().is_file()
                                && !symlink_metadata.file_type().is_symlink()
                            {
                                if found_backing_path.is_some() {
                                    return Err(Error::FreeText(format!(
                                        "Multiple real locations found for backing file '{}' - expected exactly one",
                                        backing_name
                                    )));
                                }
                                found_backing_path = Some(candidate_path);
                            }
                        }
                    }
                }

                match found_backing_path {
                    Some(backing_path) => {
                        // Continue with the backing file
                        current_path = backing_path;
                    }
                    None => {
                        return Err(Error::FreeText(format!(
                            "Cannot find backing file '{}' as a real file in any lookup directory",
                            backing_name
                        )));
                    }
                }
            }
            None => break, // No backing file - reached root
        }
    }

    Ok(BackingChainInfo { chain })
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

pub(crate) fn read_json_path<T>(json_path: impl AsRef<Path>) -> Result<T, Error>
where
    T: for<'a> Deserialize<'a>,
{
    let mut file = std::fs::File::open(json_path.as_ref())?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(serde_json::de::from_str(&contents)?)
}
