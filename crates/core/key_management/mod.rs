//! Cryptographic key management for Brankas Adhyaksa

use aes_gcm::{Aes256Gcm, KeyInit, aead::{Aead, OsRng, generic_array::GenericArray}};
use anyhow::Context;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use uuid::Uuid;

mod key_store;
mod key_types;

pub use key_store::*;
pub use key_types::*;

/// Key management errors
#[derive(Error, Debug)]
pub enum KeyError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("Key already exists: {0}")]
    KeyExists(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("Crypto error: {0}")]
    CryptoError(String),
    
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Key manager for cryptographic operations
#[derive(Clone, Default)]
pub struct KeyManager {
    store: Arc<RwLock<KeyStore>>,
    config: KeyManagerConfig,
}

impl KeyManager {
    /// Create a new key manager with default config
    pub fn new() -> Self {
        Self::with_config(KeyManagerConfig::default())
    }
    
    /// Create with custom config
    pub fn with_config(config: KeyManagerConfig) -> Self {
        Self {
            store: Arc::new(RwLock::new(KeyStore::new())),
            config,
        }
    }
    
    /// Generate a new symmetric key
    pub fn generate_symmetric_key(&self, key_type: KeyType) -> Result<Key> {
        let key = match key_type {
            KeyType::Aes256Gcm => {
                let mut key = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                Key::new(KeyData::Aes256Gcm(key))
            }
            KeyType::HmacSha256 => {
                let mut key = vec![0u8; 32];
                rand::thread_rng().fill_bytes(&mut key);
                Key::new(KeyData::HmacSha256(key))
            }
        };
        
        self.store.write()?.add_key(key)
    }
    
    /// Get a key by ID
    pub fn get_key(&self, key_id: &Uuid) -> Result<Key> {
        self.store.read()?.get_key(key_id).cloned()
            .ok_or_else(|| KeyError::KeyNotFound(key_id.to_string()))
    }
    
    /// Encrypt data with AES-256-GCM
    pub fn encrypt(&self, key_id: &Uuid, plaintext: &[u8]) -> Result<Vec<u8>> {
        let key = self.get_key(key_id)?;
        
        match &key.data {
            KeyData::Aes256Gcm(key_bytes) => {
                let key = GenericArray::from_slice(key_bytes);
                let cipher = Aes256Gcm::new(key);
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                
                let ciphertext = cipher.encrypt(&nonce, plaintext)
                    .map_err(|e| KeyError::CryptoError(e.to_string()))?;
                
                // Combine nonce + ciphertext
                let mut result = nonce.to_vec();
                result.extend(ciphertext);
                Ok(result)
            }
            _ => Err(KeyError::InvalidKey("Key type does not support encryption".to_string())),
        }
    }
    
    /// Decrypt data with AES-256-GCM
    pub fn decrypt(&self, key_id: &Uuid, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let key = self.get_key(key_id)?;
        
        match &key.data {
            KeyData::Aes256Gcm(key_bytes) => {
                if ciphertext.len() < 12 { // Nonce size for GCM
                    return Err(KeyError::InvalidKey("Ciphertext too short".to_string()));
                }
                
                let key = GenericArray::from_slice(key_bytes);
                let cipher = Aes256Gcm::new(key);
                
                let (nonce, ciphertext) = ciphertext.split_at(12);
                let nonce = GenericArray::from_slice(nonce);
                
                cipher.decrypt(nonce, ciphertext)
                    .map_err(|e| KeyError::CryptoError(e.to_string()))
            }
            _ => Err(KeyError::InvalidKey("Key type does not support decryption".to_string())),
        }
    }
}

/// Key manager configuration
#[derive(Debug, Clone)]
pub struct KeyManagerConfig {
    pub default_key_ttl: Duration,
    pub max_key_versions: usize,
}

impl Default for KeyManagerConfig {
    fn default() -> Self {
        Self {
            default_key_ttl: Duration::from_secs(365 * 24 * 60 * 60), // 1 year
            max_key_versions: 3,
        }
    }
}
