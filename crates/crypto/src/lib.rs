//! Brankas Cryptographic Library
//!
//! High-performance, secure cryptographic primitives and protocols
//! with comprehensive RustCrypto integration and transit engine support.

use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

pub mod encryption;
pub mod error;
pub mod hashing;
pub mod key_derivation;
pub mod kv_engine;
pub mod transit_simple;

pub use encryption::*;
pub use error::*;
pub use hashing::*;
pub use key_derivation::*;
pub use kv_engine::*;
pub use transit_simple::*;

// Re-export transit_simple as transit for compatibility
pub mod transit {
    pub use super::transit_simple::*;
}

/// Cryptographic error types (legacy)
#[derive(Error, Debug, Clone, PartialEq)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Encryption failed: {reason}")]
    EncryptionFailed { reason: String },

    #[error("Decryption failed: {reason}")]
    DecryptionFailed { reason: String },

    #[error("Key generation failed: {reason}")]
    KeyGenerationFailed { reason: String },

    #[error("Hash operation failed: {reason}")]
    HashFailed { reason: String },

    #[error("Invalid nonce/IV length")]
    InvalidNonceLength,

    #[error("Random generation failed")]
    RandomGenerationFailed,
}

/// Type alias for Results with CryptoError (legacy)
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmId {
    // Symmetric encryption
    Aes256Gcm,
    ChaCha20Poly1305,

    // Hash functions
    Sha256,
    Sha3_256,
    Blake3,

    // Key derivation
    Pbkdf2,
    Argon2id,
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            AlgorithmId::Aes256Gcm => "AES-256-GCM",
            AlgorithmId::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AlgorithmId::Sha256 => "SHA-256",
            AlgorithmId::Sha3_256 => "SHA3-256",
            AlgorithmId::Blake3 => "BLAKE3",
            AlgorithmId::Pbkdf2 => "PBKDF2",
            AlgorithmId::Argon2id => "Argon2id",
        };
        write!(f, "{}", name)
    }
}

/// Security parameters for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    pub algorithm: AlgorithmId,
    pub key_size: usize,
    pub iterations: Option<u32>,
    pub salt_size: Option<usize>,
}

impl SecurityParams {
    /// Create security parameters for a given algorithm
    pub fn new(algorithm: AlgorithmId) -> Self {
        let (key_size, iterations, salt_size) = match algorithm {
            AlgorithmId::Aes256Gcm => (32, None, Some(12)),
            AlgorithmId::ChaCha20Poly1305 => (32, None, Some(12)),
            AlgorithmId::Sha256 => (32, None, None),
            AlgorithmId::Sha3_256 => (32, None, None),
            AlgorithmId::Blake3 => (32, None, None),
            AlgorithmId::Pbkdf2 => (32, Some(100_000), Some(16)),
            AlgorithmId::Argon2id => (32, Some(3), Some(16)),
        };

        Self {
            algorithm,
            key_size,
            iterations,
            salt_size,
        }
    }

    /// Check if parameters are secure for production use
    pub fn is_secure(&self) -> bool {
        match self.algorithm {
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => self.key_size >= 32,
            AlgorithmId::Pbkdf2 => self.iterations.unwrap_or(0) >= 100_000 && self.key_size >= 32,
            AlgorithmId::Argon2id => self.iterations.unwrap_or(0) >= 3 && self.key_size >= 32,
            _ => true,
        }
    }
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(bytes)
}

/// Generate a random key for the specified algorithm
pub fn generate_key(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);
    generate_random_bytes(params.key_size)
}

/// Generate a random nonce/IV for the specified algorithm
pub fn generate_nonce(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);
    if let Some(nonce_size) = params.salt_size {
        generate_random_bytes(nonce_size)
    } else {
        Err(CryptoError::InvalidNonceLength)
    }
}
