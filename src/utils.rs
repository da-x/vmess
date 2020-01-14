use std::collections::hash_map::DefaultHasher;
use std::convert::TryFrom;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use super::Error;
use log::debug;

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

#[macro_export]
macro_rules! ibash_stdout {
    ($($arg:tt)*) => { crate::utils::bash_stdout(f!($($arg)*)) }
}
