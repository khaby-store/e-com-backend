pub mod controller;
pub mod crypto;
pub mod storage;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;
use thiserror::Error;
use tokio::sync::RwLock;

use controller::validate_key;
use crypto::{MasterKey, compress, decompress};
use storage::Storage;

/// Hard cap on the decompressed store so a hostile/corrupt file cannot make
/// the process allocate without bound.
pub const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum DbError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("value exceeds the {0} byte limit")]
    TooLarge(usize),
    #[error("storage/crypto failure")]
    Internal,
    #[error("corrupt store: {0}")]
    Corrupt(String),
    #[error("io error: {0}")]
    Io(String),
    #[error("serialization error: {0}")]
    Serde(String),
}

impl From<crypto::CryptoError> for DbError {
    fn from(e: crypto::CryptoError) -> Self {
        DbError::Corrupt(e.to_string())
    }
}

impl From<std::io::Error> for DbError {
    fn from(e: std::io::Error) -> Self {
        DbError::Io(e.to_string())
    }
}

#[derive(Debug, Default)]
pub struct Metrics {
    pub reads: AtomicU64,
    pub writes: AtomicU64,
    pub deletes: AtomicU64,
    pub hits: AtomicU64,
    pub bytes_written: AtomicU64,
    pub json_bytes: AtomicU64,
}

#[derive(Debug, Default)]
struct State {
    records: BTreeMap<String, Value>,
}

/// In-memory working set backed by an encrypted, compressed JSON file.
pub struct Db {
    storage: Storage,
    key: MasterKey,
    level: i32,
    max_value_bytes: usize,
    state: RwLock<State>,
    metrics: Metrics,
}

impl Db {
    /// Loads the store, decrypting and inflating it. Fails closed if the file
    /// exists but cannot be authenticated.
    pub async fn open(
        storage: Storage,
        key: MasterKey,
        level: i32,
        max_value_bytes: usize,
    ) -> Result<Arc<Db>, DbError> {
        let reader = storage.clone();
        let load_key = key.clone();
        let records =
            tokio::task::spawn_blocking(move || -> Result<BTreeMap<String, Value>, DbError> {
                let Some(blob) = reader.read()? else {
                    return Ok(BTreeMap::new());
                };
                if blob.len() > MAX_STORE_BYTES {
                    return Err(DbError::Corrupt("store exceeds size cap".into()));
                }
                let plain = load_key.open(&blob)?;
                let json = decompress(&plain)?;
                if json.len() > MAX_STORE_BYTES {
                    return Err(DbError::Corrupt("inflated store exceeds size cap".into()));
                }
                serde_json::from_slice::<BTreeMap<String, Value>>(&json)
                    .map_err(|e| DbError::Serde(e.to_string()))
            })
            .await
            .map_err(|_| DbError::Internal)??;

        let db = Arc::new(Self {
            storage,
            key,
            level,
            max_value_bytes,
            state: RwLock::new(State { records }),
            metrics: Metrics::default(),
        });

        let json_len = {
            let st = db.state.read().await;
            serde_json::to_vec(&st.records)
                .map(|v| v.len())
                .unwrap_or(0)
        };
        db.metrics
            .json_bytes
            .store(json_len as u64, Ordering::Relaxed);

        Ok(db)
    }

    pub fn max_value_bytes(&self) -> usize {
        self.max_value_bytes
    }

    pub async fn get(&self, key: &str) -> Result<Option<Value>, DbError> {
        validate_key(key)?;
        let st = self.state.read().await;
        let v = st.records.get(key).cloned();
        self.metrics.reads.fetch_add(1, Ordering::Relaxed);
        if v.is_some() {
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);
        }
        Ok(v)
    }

    pub async fn set(&self, key: &str, value: Value) -> Result<(), DbError> {
        validate_key(key)?;
        let encoded_len = serde_json::to_vec(&value)
            .map_err(|e| DbError::Serde(e.to_string()))?
            .len();
        if encoded_len > self.max_value_bytes {
            return Err(DbError::TooLarge(self.max_value_bytes));
        }

        let mut st = self.state.write().await;
        st.records.insert(key.to_owned(), value);
        self.metrics.writes.fetch_add(1, Ordering::Relaxed);
        self.persist(&st).await
    }

    pub async fn delete(&self, key: &str) -> Result<bool, DbError> {
        validate_key(key)?;
        let mut st = self.state.write().await;
        let removed = st.records.remove(key).is_some();
        if removed {
            self.metrics.deletes.fetch_add(1, Ordering::Relaxed);
            self.persist(&st).await?;
        }
        Ok(removed)
    }

    pub async fn keys(&self, prefix: &str, limit: usize, offset: usize) -> Vec<String> {
        let st = self.state.read().await;
        st.records
            .keys()
            .filter(|k| k.starts_with(prefix))
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    pub async fn count(&self) -> usize {
        self.state.read().await.records.len()
    }

    /// Serializes, compresses and re-encrypts the working set to disk.
    /// Callers must hold the state write lock.
    async fn persist(&self, st: &State) -> Result<(), DbError> {
        let json = serde_json::to_vec(&st.records).map_err(|e| DbError::Serde(e.to_string()))?;
        self.metrics
            .json_bytes
            .store(json.len() as u64, Ordering::Relaxed);

        let storage = self.storage.clone();
        let key = self.key.clone();
        let level = self.level;

        let written = tokio::task::spawn_blocking(move || -> Result<u64, DbError> {
            let packed = compress(&json, level)?;
            // The plaintext JSON must not outlive this closure.
            let mut scratch = json;
            scratch.iter_mut().for_each(|b| *b = 0);
            drop(scratch);

            let blob = key.seal(&packed)?;
            let n = storage.write(&blob)?;
            Ok(n)
        })
        .await
        .map_err(|_| DbError::Internal)??;

        self.metrics
            .bytes_written
            .fetch_add(written, Ordering::Relaxed);
        Ok(())
    }

    pub async fn backup(&self) -> Result<std::path::PathBuf, DbError> {
        let storage = self.storage.clone();
        tokio::task::spawn_blocking(move || storage.backup())
            .await
            .map_err(|_| DbError::Internal)?
            .map_err(Into::into)
    }

    /// Forces a rewrite of the current snapshot.
    pub async fn flush(&self) -> Result<u64, DbError> {
        let st = self.state.read().await;
        let json = serde_json::to_vec(&st.records).map_err(|e| DbError::Serde(e.to_string()))?;
        let storage = self.storage.clone();
        let key = self.key.clone();
        let level = self.level;
        tokio::task::spawn_blocking(move || -> Result<u64, DbError> {
            let packed = compress(&json, level)?;
            let blob = key.seal(&packed)?;
            Ok(storage.write(&blob)?)
        })
        .await
        .map_err(|_| DbError::Internal)?
    }

    pub fn store_path(&self) -> &std::path::Path {
        self.storage.path()
    }

    pub fn on_disk_bytes(&self) -> u64 {
        self.storage.size_on_disk()
    }

    pub fn zstd_level(&self) -> i32 {
        self.level
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    pub struct TempStore(PathBuf);

    impl TempStore {
        pub fn new() -> Self {
            let mut buf = std::env::temp_dir();
            let mut name = [0u8; 8];
            let _ = getrandom::fill(&mut name);
            let mut hex = String::new();
            for b in name {
                hex.push_str(&format!("{b:02x}"));
            }
            buf.push(format!("ecom-db-core-{hex}"));
            std::fs::create_dir_all(&buf).unwrap();
            Self(buf)
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    async fn open_db(dir: &std::path::Path) -> Arc<Db> {
        Db::open(
            Storage::new(dir.join("store.ejson")),
            master_key(),
            3,
            1024 * 64,
        )
        .await
        .unwrap()
    }

    fn master_key() -> MasterKey {
        MasterKey::from_hex("3f9a1c8e7b2d40f53f9a1c8e7b2d40f53f9a1c8e7b2d40f53f9a1c8e7b2d40f5")
            .unwrap()
    }

    fn other_key() -> MasterKey {
        MasterKey::from_hex("c47e21b0a9d63f18c47e21b0a9d63f18c47e21b0a9d63f18c47e21b0a9d63f18")
            .unwrap()
    }

    #[tokio::test]
    async fn set_get_delete_roundtrip() {
        let t = TempStore::new();
        let db = open_db(&t.0).await;

        db.set("user:1", serde_json::json!({"name": "ada"}))
            .await
            .unwrap();
        assert_eq!(
            db.get("user:1").await.unwrap().unwrap(),
            serde_json::json!({"name": "ada"})
        );
        assert!(db.get("user:missing").await.unwrap().is_none());
        assert!(db.delete("user:1").await.unwrap());
        assert!(!db.delete("user:1").await.unwrap());
        assert_eq!(db.count().await, 0);
    }

    #[tokio::test]
    async fn persists_across_reopen_and_stays_encrypted() {
        let t = TempStore::new();
        {
            let db = open_db(&t.0).await;
            db.set("k", serde_json::json!("v")).await.unwrap();
        }

        let raw = std::fs::read(t.0.join("store.ejson")).unwrap();
        assert!(!raw.windows(2).any(|w| w == b"vk"));
        assert!(!raw.windows(1).any(|w| w == b"{"));
        assert_eq!(&raw[..6], b"EJSDB1");

        let db = open_db(&t.0).await;
        assert_eq!(db.get("k").await.unwrap().unwrap(), serde_json::json!("v"));
    }

    #[tokio::test]
    async fn rejects_bad_key_and_oversized_value() {
        let t = TempStore::new();
        let db = open_db(&t.0).await;
        assert!(matches!(
            db.set("../etc/passwd", serde_json::json!(1)).await,
            Err(DbError::InvalidKey(_))
        ));
        assert!(matches!(
            db.set("", serde_json::json!(1)).await,
            Err(DbError::InvalidKey(_))
        ));
        let big = "x".repeat(1024 * 64 + 1);
        assert!(matches!(
            db.set("big", serde_json::json!(big)).await,
            Err(DbError::TooLarge(_))
        ));
    }

    #[tokio::test]
    async fn tampered_file_fails_to_open() {
        let t = TempStore::new();
        {
            let db = open_db(&t.0).await;
            db.set("k", serde_json::json!(1)).await.unwrap();
        }
        let path = t.0.join("store.ejson");
        let mut raw = std::fs::read(&path).unwrap();
        let n = raw.len() - 1;
        raw[n] ^= 0xFF;
        std::fs::write(&path, &raw).unwrap();

        let res = Db::open(Storage::new(&path), master_key(), 3, 1024).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn wrong_key_fails_to_open() {
        let t = TempStore::new();
        {
            let db = open_db(&t.0).await;
            db.set("k", serde_json::json!(1)).await.unwrap();
        }
        let res = Db::open(Storage::new(t.0.join("store.ejson")), other_key(), 3, 1024).await;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn prefix_listing_is_sorted_and_paginated() {
        let t = TempStore::new();
        let db = open_db(&t.0).await;
        for k in ["p:2", "p:1", "q:1", "p:3"] {
            db.set(k, serde_json::json!(k)).await.unwrap();
        }
        assert_eq!(db.keys("p:", 10, 0).await, vec!["p:1", "p:2", "p:3"]);
        assert_eq!(db.keys("p:", 10, 1).await, vec!["p:2", "p:3"]);
        assert_eq!(db.keys("p:", 1, 2).await, vec!["p:3"]);
        assert_eq!(db.keys("nothing", 10, 0).await, Vec::<String>::new());
    }
}
