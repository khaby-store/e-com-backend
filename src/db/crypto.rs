use std::fmt;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Any additional authenticated data bound into every ciphertext. Changing it
/// makes every stored blob fail to decrypt, which is exactly what we want when
/// the on-disk format evolves.
pub const AAD: &[u8] = b"ecom-secure-db/aes-256-gcm/v1";

/// Ciphertext header: magic + version + nonce.
const MAGIC: &[u8; 6] = b"EJSDB1";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = MAGIC.len() + 1 + NONCE_LEN;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("master key is missing: set the DB_MASTER_KEY environment variable")]
    MissingKey,
    #[error(
        "DB_MASTER_KEY must be {KEY_LEN} bytes encoded as {expected} hex characters, got {got} characters"
    )]
    BadKeyLength { got: usize, expected: usize },
    #[error("DB_MASTER_KEY is not valid hex")]
    InvalidHex,
    #[error("DB_MASTER_KEY is a degenerate/known-weak key and was rejected")]
    WeakKey,
    #[error("stored blob is corrupt: header or magic bytes do not match")]
    BadHeader,
    #[error("decryption failed: wrong master key or tampered data")]
    Tampered,
    #[error("cipher error: {0}")]
    Cipher(String),
}

/// A 256-bit AES key that is wiped from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct MasterKey([u8; KEY_LEN]);

impl MasterKey {
    pub fn from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let trimmed = hex_str.trim();
        if trimmed.len() != KEY_LEN * 2 {
            return Err(CryptoError::BadKeyLength {
                got: trimmed.len(),
                expected: KEY_LEN * 2,
            });
        }
        let bytes = hex::decode(trimmed).map_err(|_| CryptoError::InvalidHex)?;
        let mut arr = [0u8; KEY_LEN];
        arr.copy_from_slice(&bytes);
        Self::new(arr)
    }

    pub fn new(bytes: [u8; KEY_LEN]) -> Result<Self, CryptoError> {
        if is_weak(&bytes) {
            return Err(CryptoError::WeakKey);
        }
        Ok(Self(bytes))
    }

    pub fn from_env() -> Result<Self, CryptoError> {
        match std::env::var("DB_MASTER_KEY") {
            Ok(v) if !v.trim().is_empty() => Self::from_hex(&v),
            _ => Err(CryptoError::MissingKey),
        }
    }

    fn cipher(&self) -> Result<Aes256Gcm, CryptoError> {
        Aes256Gcm::new_from_slice(&self.0).map_err(|e| CryptoError::Cipher(e.to_string()))
    }

    /// Encrypts `plaintext` with a fresh random nonce and returns
    /// `magic || version || nonce || ciphertext`.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let cipher = self.cipher()?;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce_bytes).map_err(|e| CryptoError::Cipher(e.to_string()))?;
        let nonce = Nonce::from(nonce_bytes);

        let ct = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: AAD,
                },
            )
            .map_err(|_| CryptoError::Cipher("encryption failed".into()))?;

        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypts a blob produced by [`MasterKey::seal`]. Fails closed on any
    /// mismatch: unknown magic, unexpected version, or AEAD tag failure.
    pub fn open(&self, blob: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if blob.len() < HEADER_LEN {
            return Err(CryptoError::BadHeader);
        }
        if &blob[..MAGIC.len()] != MAGIC {
            return Err(CryptoError::BadHeader);
        }
        if blob[MAGIC.len()] != VERSION {
            return Err(CryptoError::BadHeader);
        }
        let nonce = Nonce::try_from(&blob[MAGIC.len() + 1..HEADER_LEN])
            .map_err(|_| CryptoError::BadHeader)?;
        let ct = &blob[HEADER_LEN..];

        let cipher = self.cipher()?;
        cipher
            .decrypt(&nonce, Payload { msg: ct, aad: AAD })
            .map_err(|_| CryptoError::Tampered)
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("MasterKey([REDACTED])")
    }
}

/// Rejects obviously degenerate keys (all-zero, single repeated byte).
fn is_weak(key: &[u8; KEY_LEN]) -> bool {
    let first = key[0];
    key.iter().all(|&b| b == first)
}

/// Compress-then-encrypt: JSON -> zstd -> AES-256-GCM.
pub fn compress(plain: &[u8], level: i32) -> std::io::Result<Vec<u8>> {
    zstd::encode_all(plain, level)
}

/// Decrypt-then-decompress: AES-256-GCM -> zstd -> JSON.
pub fn decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    zstd::decode_all(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32 non-degenerate bytes (the weak-key guard rejects uniform keys).
    const KEY_A: &str = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
    const KEY_B: &str = "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0";

    fn key() -> MasterKey {
        MasterKey::from_hex(KEY_A).unwrap()
    }

    #[test]
    fn roundtrip() {
        let k = key();
        let blob = k.seal(b"hello world").unwrap();
        assert_eq!(k.open(&blob).unwrap(), b"hello world");
    }

    #[test]
    fn tampering_is_detected() {
        let k = key();
        let mut blob = k.seal(b"payload").unwrap();
        let last = blob.len() - 1;
        blob[last] ^= 0xFF;
        assert!(matches!(k.open(&blob), Err(CryptoError::Tampered)));
    }

    #[test]
    fn wrong_key_fails() {
        let a = key();
        let b = MasterKey::from_hex(KEY_B).unwrap();
        let blob = a.seal(b"secret").unwrap();
        assert!(matches!(b.open(&blob), Err(CryptoError::Tampered)));
    }

    #[test]
    fn header_mutation_is_detected() {
        let k = key();
        let mut blob = k.seal(b"x").unwrap();
        blob[0] = b'X';
        assert!(matches!(k.open(&blob), Err(CryptoError::BadHeader)));
    }

    #[test]
    fn weak_key_rejected() {
        assert!(matches!(
            MasterKey::from_hex(&"00".repeat(32)),
            Err(CryptoError::WeakKey)
        ));
        assert!(matches!(
            MasterKey::from_hex("deadbeef"),
            Err(CryptoError::BadKeyLength { .. })
        ));
        assert!(matches!(
            MasterKey::from_hex(&"zz".repeat(32)),
            Err(CryptoError::InvalidHex)
        ));
    }

    #[test]
    fn compress_shrinks_repetitive_json() {
        let json = br#"{"a":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        let c = compress(json, 3).unwrap();
        assert!(c.len() < json.len());
        assert_eq!(decompress(&c).unwrap(), json);
    }
}
