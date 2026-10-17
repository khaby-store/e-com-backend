use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use fd_lock::RwLock;

/// On-disk persistence for the encrypted JSON store.
///
/// Guarantees:
///   * writes are atomic (temp file + fsync + rename) - readers never observe
///     a torn file
///   * every file/dir we create is `0600`/`0700`
///   * readers and writers coordinate through an advisory lock on a sidecar
///     `.lock` file (the store itself is renamed, so locking it directly would
///     lock a stale inode)
#[derive(Debug, Clone)]
pub struct Storage {
    path: PathBuf,
}

impl Storage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn lock_path(&self) -> PathBuf {
        let mut p = self.path.clone().into_os_string();
        p.push(".lock");
        PathBuf::from(p)
    }

    /// Ensures the parent directory exists with restrictive permissions.
    fn ensure_dir(&self) -> io::Result<PathBuf> {
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }
        // Best effort: tighten the directory regardless of who created it.
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
        Ok(dir)
    }

    fn open_lock(&self) -> io::Result<File> {
        if let Some(parent) = self.lock_path().parent()
            && !parent.as_os_str().is_empty()
        {
            let _ = fs::create_dir_all(parent);
        }
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(self.lock_path())
    }

    /// Reads the raw ciphertext blob. Returns `None` when the store has not
    /// been created yet.
    pub fn read(&self) -> io::Result<Option<Vec<u8>>> {
        if !self.path.exists() {
            return Ok(None);
        }
        let lock = self.open_lock()?;
        let rw = RwLock::new(lock);
        let _guard = rw.read().map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "failed to acquire db read lock")
        })?;

        let mut buf = Vec::new();
        File::open(&self.path)?.read_to_end(&mut buf)?;
        Ok(Some(buf))
    }

    /// Atomically replaces the store with `data` under an exclusive lock.
    pub fn write(&self, data: &[u8]) -> io::Result<u64> {
        let dir = self.ensure_dir()?;
        let lock = self.open_lock()?;
        let mut rw = RwLock::new(lock);
        let _guard = rw.write().map_err(|_| {
            io::Error::new(io::ErrorKind::TimedOut, "failed to acquire db write lock")
        })?;

        let name = self
            .path
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "store.ejson".into());
        let tmp = dir.join(format!(".{name}.tmp-{}", unique_suffix()));

        let result = (|| -> io::Result<()> {
            let mut f = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.flush()?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &self.path)?;
            // Persist the rename itself.
            if let Ok(d) = File::open(&dir) {
                let _ = d.sync_all();
            }
            Ok(())
        })();

        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        Ok(data.len() as u64)
    }

    /// Writes a `0600` copy of the current ciphertext next to the store.
    pub fn backup(&self) -> io::Result<PathBuf> {
        if !self.path.exists() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "nothing to back up",
            ));
        }
        let dir = self.ensure_dir()?;
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let target = dir.join(format!("backup-{stamp}.ejson"));
        fs::copy(&self.path, &target)?;
        let _ = fs::set_permissions(&target, fs::Permissions::from_mode(0o600));
        Ok(target)
    }

    pub fn size_on_disk(&self) -> u64 {
        fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0)
    }
}

fn unique_suffix() -> String {
    let mut buf = [0u8; 8];
    let _ = getrandom::fill(&mut buf);
    let mut s = String::with_capacity(16);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempdir::TempDir, Storage) {
        let dir = tempdir::TempDir::new().unwrap();
        let store = Storage::new(dir.path().join("sub/store.ejson"));
        (dir, store)
    }

    // Tiny stand-in so tests do not pull in an extra crate.
    mod tempdir {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new() -> std::io::Result<Self> {
                let mut buf = std::env::temp_dir();
                let mut name = [0u8; 8];
                let _ = getrandom::fill(&mut name);
                let mut hex = String::new();
                for b in name {
                    hex.push_str(&format!("{b:02x}"));
                }
                buf.push(format!("ecom-db-test-{hex}"));
                std::fs::create_dir_all(&buf)?;
                Ok(Self(buf))
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn write_then_read_roundtrip() {
        let (_d, store) = temp_store();
        assert!(store.read().unwrap().is_none());
        store.write(b"abc").unwrap();
        assert_eq!(store.read().unwrap().unwrap(), b"abc");
        store.write(b"defg").unwrap();
        assert_eq!(store.read().unwrap().unwrap(), b"defg");
    }

    #[test]
    fn permissions_are_restrictive() {
        let (_d, store) = temp_store();
        store.write(b"data").unwrap();
        let mode = fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let dir_mode = fs::metadata(store.path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(dir_mode & 0o777, 0o700);
    }

    #[test]
    fn backup_creates_readonly_copy() {
        let (_d, store) = temp_store();
        store.write(b"original").unwrap();
        let b = store.backup().unwrap();
        assert_eq!(fs::read(&b).unwrap(), b"original");
        let mode = fs::metadata(&b).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
