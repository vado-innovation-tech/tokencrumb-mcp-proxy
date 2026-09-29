//! Atomic state replacement and inter-process locking (local POSIX filesystem).

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{Error, Result};

/// Absolute form of a path without resolving symlinks (Python `Path.absolute`).
pub fn absolute(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(path))
            .unwrap_or_else(|_| path.to_path_buf())
    }
}

/// Exclusive `flock` on `<path>.lock`, released on drop.
pub struct FileLock {
    file: File,
}

impl FileLock {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self> {
        let mut lock_path = absolute(path.as_ref()).into_os_string();
        lock_path.push(".lock");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?;
        // SAFETY: flock on a descriptor we own for the lifetime of `file`.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // SAFETY: same descriptor as above; unlocking is best effort, close follows.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn fsync_dir(dir: &Path) -> Result<()> {
    let handle = File::open(dir)?;
    handle.sync_all()?;
    Ok(())
}

/// Replace `path` atomically with `data`: a private temporary in the same directory,
/// fsync, rename, fsync the directory. A pre-existing symlink is replaced, not followed.
pub fn atomic_write(path: impl AsRef<Path>, data: &[u8], prefix: &str) -> Result<()> {
    let path = absolute(path.as_ref());
    let parent = path
        .parent()
        .ok_or_else(|| Error::io("path has no parent directory"))?;
    let mut temporary = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)?;
    temporary.write_all(data)?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    temporary.persist(&path).map_err(|e| Error::from(e.error))?;
    fsync_dir(parent)?;
    Ok(())
}

/// `json.dump(value)` to `path`, atomically (the stored bytes match the former format).
pub fn atomic_json(path: impl AsRef<Path>, value: &Value) -> Result<()> {
    atomic_write(path, crate::json::dumps(value).as_bytes(), ".state-")
}

/// Private file written atomically (tokens, keys, published policies).
pub fn write_secure(path: impl AsRef<Path>, data: &[u8]) -> Result<()> {
    atomic_write(path, data, ".secret-")
}

pub fn read_bytes(path: impl AsRef<Path>) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}
