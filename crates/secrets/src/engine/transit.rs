//! Transit secret engine for encryption/decryption as a service

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use serde_json::Value;
use std::collections::HashMap;

/// Transit secret engine for cryptographic operations
pub struct TransitEngine {
    config: TransitConfig,
    enabled: bool,
    keys: HashMap<String, Vec<u8>>, // Store encryption keys by name
}

impl TransitEngine {
    pub fn new(config: TransitConfig) -> Self {
        Self {
            config,
            enabled: false,
            keys: HashMap::new(),
        }
    }

    /// Generate a new key
    async fn generate_key(&mut self, name: &str, key_type: KeyType) -> SecretResult<()> {
        use rand::RngCore;

        let key_size = match key_type {
            KeyType::Aes128Gcm96 => 16,
            KeyType::Aes256Gcm96 => 32,
            KeyType::ChaCha20Poly1305 => 32,
            _ => {
                return Err(SecretError::InvalidConfiguration(format!(
                    "Unsupported key type: {:?}",
                    key_type
                )));
            }
        };

        let mut key = vec![0u8; key_size];
        rand::thread_rng().fill_bytes(&mut key);

        self.keys.insert(name.to_string(), key);
        Ok(())
    }

    /// Encrypt data using a named key
    async fn encrypt_data(&self, key_name: &str, plaintext: &[u8]) -> SecretResult<String> {
        let key = self
            .keys
            .get(key_name)
            .ok_or_else(|| {
                SecretError::InvalidConfiguration(format!("Key '{}' not found", key_name))
            })?
            .clone();

        // Use AES-256-GCM for encryption
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let key_array: [u8; 32] = key.as_slice().try_into().unwrap();
        let cipher_key = Key::<Aes256Gcm>::from(key_array);
        let cipher = Aes256Gcm::new(&cipher_key);

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| SecretError::EncryptionFailed(format!("Encryption failed: {}", e)))?;

        // Combine nonce and ciphertext, then base64 encode
        let mut combined = nonce_bytes.to_vec();
        combined.extend(ciphertext);

        Ok(general_purpose::STANDARD.encode(&combined))
    }

    /// Decrypt data using a named key
    async fn decrypt_data(&self, key_name: &str, ciphertext: &str) -> SecretResult<Vec<u8>> {
        let key = self
            .keys
            .get(key_name)
            .ok_or_else(|| {
                SecretError::InvalidConfiguration(format!("Key '{}' not found", key_name))
            })?
            .clone();

        // Decode from base64
        let combined = general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| SecretError::InvalidSecretData(format!("Invalid base64: {}", e)))?;

        if combined.len() < 12 {
            return Err(SecretError::InvalidSecretData(
                "Ciphertext too short".to_string(),
            ));
        }

        // Use AES-256-GCM for decryption
        use aes_gcm::aead::{Aead, KeyInit};
        use aes_gcm::{Aes256Gcm, Key, Nonce};

        let key_array: [u8; 32] = key.as_slice().try_into().unwrap();
        let cipher_key = Key::<Aes256Gcm>::from(key_array);
        let cipher = Aes256Gcm::new(&cipher_key);

        let (nonce_bytes, ciphertext) = combined.split_at(12);
        let nonce_array: [u8; 12] = nonce_bytes.try_into().unwrap();
        let nonce = Nonce::from(nonce_array);

        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| SecretError::DecryptionFailed(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

#[async_trait]
impl SecretEngine for TransitEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Transit
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        if let Some(transit_config) = config.config.get("transit") {
            if let Ok(transit_config) = serde_json::from_value(transit_config.clone()) {
                self.config = transit_config;
            }
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("transit".to_string()));
        }

        // Handle decryption requests
        if path.starts_with("decrypt/") {
            let _key_name = &path[8..]; // Remove "decrypt/" prefix

            // For decryption, we need the ciphertext from query parameters or body
            // This is a simplified implementation - in practice, this would come from request body
            return Err(SecretError::InvalidKeyOperation(
                "Decryption requires ciphertext parameter".to_string(),
            ));
        }

        // Transit engine doesn't store secrets directly, only keys
        // This could return key metadata if needed
        Ok(None)
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("transit".to_string()));
        }

        // Handle key generation
        if path.starts_with("keys/") {
            let key_name = &path[5..]; // Remove "keys/" prefix

            let key_type = data
                .get("type")
                .and_then(|v| v.as_str())
                .and_then(|s| match s {
                    "aes128-gcm96" => Some(KeyType::Aes128Gcm96),
                    "aes256-gcm96" => Some(KeyType::Aes256Gcm96),
                    "chacha20-poly1305" => Some(KeyType::ChaCha20Poly1305),
                    _ => None,
                })
                .unwrap_or(self.config.default_key_type.clone());

            self.generate_key(key_name, key_type).await?;

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: HashMap::new(), // Don't expose key material
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(secret)
        }
        // Handle encryption requests
        else if path.starts_with("encrypt/") {
            let key_name = &path[8..]; // Remove "encrypt/" prefix

            let plaintext = data
                .get("plaintext")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SecretError::InvalidKeyOperation("Missing plaintext parameter".to_string())
                })?;

            let plaintext_bytes = general_purpose::STANDARD.decode(plaintext).map_err(|e| {
                SecretError::InvalidSecretData(format!("Invalid base64 plaintext: {}", e))
            })?;

            let ciphertext = self.encrypt_data(key_name, &plaintext_bytes).await?;

            let mut result_data = HashMap::new();
            result_data.insert("ciphertext".to_string(), Value::String(ciphertext));

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: result_data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(secret)
        }
        // Handle decryption requests
        else if path.starts_with("decrypt/") {
            let key_name = &path[8..]; // Remove "decrypt/" prefix

            let ciphertext = data
                .get("ciphertext")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    SecretError::InvalidKeyOperation("Missing ciphertext parameter".to_string())
                })?;

            let plaintext_bytes = self.decrypt_data(key_name, ciphertext).await?;

            let mut result_data = HashMap::new();
            result_data.insert(
                "plaintext".to_string(),
                Value::String(general_purpose::STANDARD.encode(&plaintext_bytes)),
            );

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: result_data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: None,
                    lease_duration: None,
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(secret)
        } else {
            Err(SecretError::InvalidKeyOperation(
                "Invalid transit path".to_string(),
            ))
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("transit".to_string()));
        }

        if path.starts_with("keys/") {
            let key_name = &path[5..]; // Remove "keys/" prefix
            self.keys.remove(key_name);
            Ok(())
        } else {
            Err(SecretError::InvalidKeyOperation(
                "Invalid transit path".to_string(),
            ))
        }
    }

    async fn list(&self, path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("transit".to_string()));
        }

        if path == "keys" || path == "keys/" {
            Ok(self.keys.keys().cloned().collect())
        } else {
            Ok(vec![])
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}
