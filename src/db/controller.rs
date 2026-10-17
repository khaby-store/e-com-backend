use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use serde::Serialize;
use serde_json::Value;

use super::{Db, DbError};

/// Longest key we accept, in bytes.
pub const MAX_KEY_LEN: usize = 128;

/// Validates a record key before it touches memory or disk.
///
/// Keys are restricted to a conservative ASCII charset so a key can never be
/// confused with a path, smuggle control characters into logs, or blow up the
/// index with huge identifiers.
pub fn validate_key(key: &str) -> Result<(), DbError> {
    if key.is_empty() {
        return Err(DbError::InvalidKey("key must not be empty".into()));
    }
    check_shape(key)
}

/// A listing prefix may be empty (list everything) but must otherwise be a
/// valid partial key.
pub fn validate_prefix(prefix: &str) -> Result<(), DbError> {
    check_shape(prefix)
}

fn check_shape(key: &str) -> Result<(), DbError> {
    if key.len() > MAX_KEY_LEN {
        return Err(DbError::InvalidKey(format!(
            "key exceeds {MAX_KEY_LEN} bytes"
        )));
    }
    if key.contains("..") {
        return Err(DbError::InvalidKey("key must not contain '..'".into()));
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "-_.:/@+".contains(c))
    {
        return Err(DbError::InvalidKey(
            "key may only contain A-Z a-z 0-9 and - _ . : / @ +".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct WriteReceipt {
    pub key: String,
    pub created: bool,
    pub bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct KeysPage {
    pub prefix: String,
    pub offset: usize,
    pub returned: usize,
    pub keys: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Stats {
    pub records: usize,
    pub reads: u64,
    pub writes: u64,
    pub deletes: u64,
    pub cache_hits: u64,
    pub json_bytes: u64,
    pub on_disk_bytes: u64,
    pub compression_ratio: f64,
    pub zstd_level: i32,
    pub max_value_bytes: usize,
    pub cipher: &'static str,
    pub store_path: String,
}

/// The single entry point through which the API mutates and queries the store.
#[derive(Clone)]
pub struct DbController {
    db: Arc<Db>,
}

impl DbController {
    pub fn new(db: Arc<Db>) -> Self {
        Self { db }
    }

    pub async fn get(&self, key: &str) -> Result<Option<Value>, DbError> {
        self.db.get(key).await
    }

    pub async fn set(&self, key: &str, value: Value) -> Result<WriteReceipt, DbError> {
        validate_key(key)?;
        let bytes = serde_json::to_vec(&value)
            .map_err(|e| DbError::Serde(e.to_string()))?
            .len();
        let existed = self.db.get(key).await?.is_some();
        self.db.set(key, value).await?;
        Ok(WriteReceipt {
            key: key.to_owned(),
            created: !existed,
            bytes,
        })
    }

    pub async fn delete(&self, key: &str) -> Result<bool, DbError> {
        self.db.delete(key).await
    }

    pub async fn keys(&self, prefix: &str, limit: usize, offset: usize) -> KeysPage {
        if prefix.len() > MAX_KEY_LEN {
            return KeysPage {
                prefix: prefix.to_owned(),
                offset,
                returned: 0,
                keys: Vec::new(),
            };
        }
        let keys = self.db.keys(prefix, limit, offset).await;
        KeysPage {
            prefix: prefix.to_owned(),
            offset,
            returned: keys.len(),
            keys,
        }
    }

    pub async fn stats(&self) -> Stats {
        let m = self.db.metrics();
        let json_bytes = m.json_bytes.load(Ordering::Relaxed);
        let on_disk = self.db.on_disk_bytes();
        Stats {
            records: self.db.count().await,
            reads: m.reads.load(Ordering::Relaxed),
            writes: m.writes.load(Ordering::Relaxed),
            deletes: m.deletes.load(Ordering::Relaxed),
            cache_hits: m.hits.load(Ordering::Relaxed),
            json_bytes,
            on_disk_bytes: on_disk,
            compression_ratio: if on_disk > 0 {
                json_bytes as f64 / on_disk as f64
            } else {
                0.0
            },
            zstd_level: self.db.zstd_level(),
            max_value_bytes: self.db.max_value_bytes(),
            cipher: "AES-256-GCM",
            store_path: self.db.store_path().display().to_string(),
        }
    }

    pub async fn backup(&self) -> Result<PathBuf, DbError> {
        self.db.backup().await
    }

    pub async fn flush(&self) -> Result<u64, DbError> {
        self.db.flush().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_rules() {
        assert!(validate_key("user:42").is_ok());
        assert!(validate_key("orders/2024-01-01").is_ok());
        assert!(validate_key("").is_err());
        assert!(validate_key("../secrets").is_err());
        assert!(validate_key("a b").is_err());
        assert!(validate_key("key\nwith\nnewline").is_err());
        assert!(validate_key(&"k".repeat(MAX_KEY_LEN + 1)).is_err());
        assert!(validate_key(&"k".repeat(MAX_KEY_LEN)).is_ok());
    }
}
