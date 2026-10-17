use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};

use crate::db::crypto::MasterKey;

/// Minimum length for an admin API key.
pub const MIN_API_KEY_LEN: usize = 16;
/// Highest zstd level we allow (level 22 exists but is extremely slow).
pub const MAX_ZSTD_LEVEL: i32 = 19;

#[derive(Debug)]
pub struct Config {
    pub bind: SocketAddr,
    pub db_path: PathBuf,
    pub master_key: MasterKey,
    /// Parsed admin keys, compared in constant time on every request.
    pub api_keys: Vec<Vec<u8>>,
    pub zstd_level: i32,
    pub max_value_bytes: usize,
    pub max_body_bytes: usize,
    pub rate_limit_per_minute: u32,
    pub cors_origins: Vec<String>,
}

impl Config {
    pub fn from_env() -> Result<Arc<Self>> {
        let bind: SocketAddr = env_or("BIND_ADDR", "127.0.0.1:8080")?
            .parse()
            .context("BIND_ADDR must be a valid socket address, e.g. 127.0.0.1:8080")?;

        let db_path = PathBuf::from(env_or("DB_PATH", "./data/store.ejson")?);

        let master_key = match MasterKey::from_env() {
            Ok(k) => k,
            Err(e) => bail!(
                "{e}\n  generate one with:  openssl rand -hex 32\n  then export DB_MASTER_KEY=<hex>"
            ),
        };

        let api_keys = parse_api_keys()?;

        let zstd_level: i32 = parse_int("ZSTD_LEVEL", 12)?;
        if !(-7..=MAX_ZSTD_LEVEL).contains(&zstd_level) {
            bail!("ZSTD_LEVEL must be between -7 and {MAX_ZSTD_LEVEL}, got {zstd_level}");
        }

        let max_value_bytes: usize = parse_int("MAX_VALUE_BYTES", 1_048_576)?;
        if max_value_bytes == 0 {
            bail!("MAX_VALUE_BYTES must be greater than 0");
        }

        let max_body_bytes: usize = parse_int("MAX_BODY_BYTES", 2_097_152)?;
        if max_body_bytes < max_value_bytes {
            bail!("MAX_BODY_BYTES must be >= MAX_VALUE_BYTES");
        }

        let rate_limit_per_minute: u32 = parse_int("RATE_LIMIT_PER_MIN", 300)?;

        let cors_origins = std::env::var("CORS_ALLOW_ORIGIN")
            .ok()
            .map(|v| {
                v.split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty() && s != "*")
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        Ok(Arc::new(Self {
            bind,
            db_path,
            master_key,
            api_keys,
            zstd_level,
            max_value_bytes,
            max_body_bytes,
            rate_limit_per_minute,
            cors_origins,
        }))
    }
}

fn env_or(key: &str, default: &str) -> Result<String> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        _ => Ok(default.to_string()),
    }
}

fn parse_int<T: std::str::FromStr>(key: &str, default: T) -> Result<T> {
    match std::env::var(key) {
        Ok(v) if !v.trim().is_empty() => v
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("{key} must be a valid number")),
        _ => Ok(default),
    }
}

fn parse_api_keys() -> Result<Vec<Vec<u8>>> {
    let raw = std::env::var("ADMIN_API_KEYS")
        .context("ADMIN_API_KEYS is required (comma-separated list of >= 16 char keys)")?;

    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    for k in raw.split(',').map(str::trim).filter(|k| !k.is_empty()) {
        if k.len() < MIN_API_KEY_LEN {
            bail!("ADMIN_API_KEYS entries must be at least {MIN_API_KEY_LEN} characters");
        }
        if k.chars().any(|c| c.is_whitespace()) {
            bail!("ADMIN_API_KEYS entries must not contain whitespace");
        }
        if !seen.insert(k.to_string()) {
            continue;
        }
        keys.push(k.as_bytes().to_vec());
    }
    if keys.is_empty() {
        bail!("ADMIN_API_KEYS must contain at least one key");
    }
    Ok(keys)
}
