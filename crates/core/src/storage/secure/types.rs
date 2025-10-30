//! Secure storage types and data structures
//!
//! This module contains the core data structures used throughout the secure storage system.

use base64::{Engine as _};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a cryptographic key and its metadata in the key store
///
/// Each `KeyEntry` contains the actual encryption key along with metadata
/// that controls its lifecycle and usage. The key material is stored in
/// base64-encoded format for safe serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Unique identifier for this key
    pub id: String,
    /// Base64-encoded encryption key
    pub key: String,
    /// Base64-encoded salt used for key derivation
    pub salt: String,
    /// Creation timestamp
    pub created_at: u64,
    /// Last rotation timestamp
    pub rotated_at: u64,
    /// Expiration timestamp (0 means no expiration)
    pub expires_at: u64,
    /// Whether this key is currently active
    pub active: bool,
    /// Key version for ordering
    pub version: u32,
    /// Additional metadata associated with the key
    pub metadata: std::collections::HashMap<String, String>,
}

impl KeyEntry {
    /// Create a new key entry with the given key material
    pub fn new(key: &[u8], salt: &[u8]) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            key: base64::engine::general_purpose::STANDARD.encode(key),
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
            created_at: now,
            rotated_at: now,
            expires_at: 0,
            active: true,
            version: 1,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Get the raw key bytes
    pub fn key_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.key)
            .map_err(|e| anyhow::anyhow!("Failed to decode key: {}", e))
    }

    /// Get the raw salt bytes
    pub fn salt_bytes(&self) -> Result<Vec<u8>, anyhow::Error> {
        base64::engine::general_purpose::STANDARD
            .decode(&self.salt)
            .map_err(|e| anyhow::anyhow!("Failed to decode salt: {}", e))
    }

    /// Check if the key is expired
    pub fn is_expired(&self) -> bool {
        if self.expires_at == 0 {
            return false;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.expires_at
    }
}

/// Configuration for key rotation and lifecycle management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyConfig {
    /// How often to rotate keys (in seconds)
    pub rotation_interval: u64,
    /// How long to retain old keys after rotation (in seconds)
    pub key_retention_period: u64,
    /// Minimum time between key rotations (in seconds)
    pub min_key_lifetime: u64,
    /// Maximum time a key can live before forced rotation (in seconds)
    pub max_key_lifetime: u64,
}

impl Default for KeyConfig {
    fn default() -> Self {
        Self {
            rotation_interval: 30 * 24 * 3600, // 30 days
            key_retention_period: 90 * 24 * 3600, // 90 days
            min_key_lifetime: 7 * 24 * 3600, // 1 week
            max_key_lifetime: 365 * 24 * 3600, // 1 year
        }
    }
}