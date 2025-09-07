//! Transit Secrets Engine - Encryption-as-a-Service
//!
//! This engine provides encryption/decryption services using AES-GCM,
//! key derivation, HMAC operations, and secure key management.

use crate::secrets::engine::{
    BoxedSecretsEngine, Secret, SecretMetadata, SecretsEngine, SecretsError,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

// Import macros
use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

/// Transit engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitConfig {
    pub min_decryption_version: u32,
    pub min_encryption_version: u32,
    pub max_versions: u32,
    pub allow_plaintext_backup: bool,
    pub convergent_encryption: bool,
}

impl Default for TransitConfig {
    fn default() -> Self {
        Self {
            min_decryption_version: 1,
            min_encryption_version: 1,
            max_versions: 10,
            allow_plaintext_backup: false,
            convergent_encryption: false,
        }
    }
}

/// Key configuration for a transit key
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitKeyConfig {
    pub min_decryption_version: u32,
    pub min_encryption_version: u32,
    pub max_versions: u32,
    pub allow_plaintext_backup: bool,
    pub convergent_encryption: bool,
    pub deletion_allowed: bool,
    pub exportable: bool,
    pub auto_rotate_period: Option<u64>,
}

/// Transit key with version management
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitKey {
    pub name: String,
    pub cipher_mode: String,
    pub key_ring: Vec<KeyVersion>,
    pub config: TransitKeyConfig,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Individual key version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    pub version: u32,
    pub key: Vec<u8>,
    pub creation_time: i64,
    pub derived: bool,
}

/// Encryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,
    pub context: Option<String>,
    pub key_version: Option<u32>,
    pub nonce: Option<String>,
    pub associated_data: Option<String>,
    pub batch_input: Option<Vec<BatchRequestItem>>,
}

/// Encryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub key_version: u32,
    pub batch_results: Option<Vec<BatchResponseItem>>,
}

/// Decryption request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub context: Option<String>,
    pub nonce: Option<String>,
    pub associated_data: Option<String>,
    pub batch_input: Option<Vec<BatchRequestItem>>,
}

/// Decryption response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecryptResponse {
    pub plaintext: String,
    pub key_version: u32,
    pub batch_results: Option<Vec<BatchResponseItem>>,
}

/// Batch request item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchRequestItem {
    pub context: Option<String>,
    pub plaintext: Option<String>,
    pub ciphertext: Option<String>,
    pub key_version: Option<u32>,
    pub nonce: Option<String>,
    pub associated_data: Option<String>,
}

/// Batch response item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchResponseItem {
    pub ciphertext: Option<String>,
    pub plaintext: Option<String>,
    pub key_version: u32,
    pub error: Option<String>,
}

/// HMAC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacRequest {
    pub input: String,
    pub key_version: Option<u32>,
    pub algorithm: Option<String>,
}

/// HMAC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HmacResponse {
    pub hmac: String,
    pub key_version: u32,
}

/// Key creation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub convergent_encryption: Option<bool>,
    pub derived: Option<bool>,
    pub exportable: Option<bool>,
    pub allow_plaintext_backup: Option<bool>,
    pub key_size: Option<u32>,
    pub key_type: Option<String>,
}

/// Key rotation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateKeyRequest {
    pub key_size: Option<u32>,
}

/// Main Transit Secrets Engine
pub struct TransitSecretsEngine {
    storage: Arc<dyn crate::storage::StorageEngine>,
    keys: Arc<RwLock<HashMap<String, TransitKey>>>,
}

// Re-export request types for external use
// Types are already available in this module

impl TransitSecretsEngine {
    pub fn new(storage: Arc<dyn crate::storage::StorageEngine>) -> Self {
        Self {
            storage,
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Load a key from storage
    async fn load_key(&self, key_name: &str) -> Result<TransitKey, SecretsError> {
        let key_path = format!("transit/keys/{}", key_name);
        match self.storage.get(&key_path).await {
            Ok(Some(data)) => {
                let key: TransitKey = serde_json::from_slice(&data.value).map_err(|e| {
                    SecretsError::InvalidData(format!("Failed to deserialize key: {}", e))
                })?;
                Ok(key)
            }
            Ok(None) => Err(SecretsError::NotFound(format!(
                "Key '{}' not found",
                key_name
            ))),
            Err(e) => Err(SecretsError::Storage(e.to_string())),
        }
    }

    /// Save a key to storage
    async fn save_key(&self, key: &TransitKey) -> Result<(), SecretsError> {
        let key_path = format!("transit/keys/{}", key.name);
        let data = serde_json::to_vec(key)
            .map_err(|e| SecretsError::InvalidData(format!("Failed to serialize key: {}", e)))?;
        let entry = crate::storage::StorageEntry {
            key: key_path.clone(),
            value: data,
            metadata: HashMap::new(),
        };
        self.storage
            .put(entry)
            .await
            .map_err(|e| SecretsError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Generate a new key
    fn generate_key(&self, key_size: u32) -> Vec<u8> {
        let mut key = vec![0u8; (key_size / 8) as usize];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Derive a key from context
    fn derive_key(&self, master_key: &[u8], context: &[u8]) -> Result<Vec<u8>, SecretsError> {
        let hkdf = Hkdf::<Sha256>::new(None, master_key);
        let mut derived_key = [0u8; 32];
        hkdf.expand(context, &mut derived_key)
            .map_err(|_| SecretsError::InvalidData("Key derivation failed".to_string()))?;
        Ok(derived_key.to_vec())
    }

    /// Encrypt data using AES-GCM
    fn encrypt_data(
        &self,
        key: &[u8],
        plaintext: &[u8],
        nonce: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, SecretsError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid key: {:?}", e)))?;

        let nonce = Nonce::from_slice(nonce);
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| SecretsError::InvalidData(format!("Encryption failed: {:?}", e)))?;

        Ok(ciphertext)
    }

    /// Decrypt data using AES-GCM
    fn decrypt_data(
        &self,
        key: &[u8],
        ciphertext: &[u8],
        nonce: &[u8],
        _aad: Option<&[u8]>,
    ) -> Result<Vec<u8>, SecretsError> {
        let cipher = Aes256Gcm::new_from_slice(key)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid key: {:?}", e)))?;

        let nonce = Nonce::from_slice(nonce);
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| SecretsError::InvalidData(format!("Decryption failed: {:?}", e)))?;

        Ok(plaintext)
    }

    /// Generate random nonce
    fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Create a new transit key
    pub async fn create_key(&self, name: &str, req: CreateKeyRequest) -> Result<(), SecretsError> {
        let mut keys = self.keys.write().await;

        if keys.contains_key(name) {
            return Err(SecretsError::InvalidData("Key already exists".to_string()));
        }

        let key_size = req.key_size.unwrap_or(256);
        let master_key = self.generate_key(key_size);

        let key_version = KeyVersion {
            version: 1,
            key: master_key,
            creation_time: Utc::now().timestamp(),
            derived: req.derived.unwrap_or(false),
        };

        let config = TransitKeyConfig {
            min_decryption_version: 1,
            min_encryption_version: 1,
            max_versions: 10,
            allow_plaintext_backup: req.allow_plaintext_backup.unwrap_or(false),
            convergent_encryption: req.convergent_encryption.unwrap_or(false),
            deletion_allowed: true,
            exportable: req.exportable.unwrap_or(false),
            auto_rotate_period: None,
        };

        let transit_key = TransitKey {
            name: name.to_string(),
            cipher_mode: "aes256-gcm96".to_string(),
            key_ring: vec![key_version],
            config,
            created_at: Utc::now().timestamp(),
            updated_at: Utc::now().timestamp(),
        };

        keys.insert(name.to_string(), transit_key.clone());
        self.save_key(&transit_key).await?;

        Ok(())
    }

    /// Encrypt data
    pub async fn encrypt(
        &self,
        key_name: &str,
        req: EncryptRequest,
    ) -> Result<EncryptResponse, SecretsError> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_name)
            .ok_or_else(|| SecretsError::NotFound(format!("Key '{}' not found", key_name)))?;

        let key_version = req.key_version.unwrap_or(key.config.min_encryption_version);
        let key_version_data = key
            .key_ring
            .iter()
            .find(|kv| kv.version == key_version)
            .ok_or_else(|| SecretsError::InvalidData("Key version not found".to_string()))?;

        let nonce = if let Some(nonce_str) = &req.nonce {
            general_purpose::STANDARD
                .decode(nonce_str)
                .map_err(|e| SecretsError::InvalidData(format!("Invalid nonce: {}", e)))?
        } else {
            self.generate_nonce().to_vec()
        };

        let plaintext = general_purpose::STANDARD
            .decode(&req.plaintext)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid plaintext: {}", e)))?;

        let encryption_key = if key_version_data.derived {
            if let Some(context_str) = &req.context {
                let context = general_purpose::STANDARD
                    .decode(context_str)
                    .map_err(|e| SecretsError::InvalidData(format!("Invalid context: {}", e)))?;
                self.derive_key(&key_version_data.key, &context)?
            } else {
                return Err(SecretsError::InvalidData(
                    "Context required for derived keys".to_string(),
                ));
            }
        } else {
            key_version_data.key.clone()
        };

        let associated_data = req
            .associated_data
            .as_ref()
            .map(|aad| general_purpose::STANDARD.decode(aad))
            .transpose()
            .map_err(|e| SecretsError::InvalidData(format!("Invalid associated data: {}", e)))?;

        let ciphertext = self.encrypt_data(
            &encryption_key,
            &plaintext,
            &nonce,
            associated_data.as_deref(),
        )?;

        let mut combined_ciphertext = nonce;
        combined_ciphertext.extend_from_slice(&ciphertext);

        Ok(EncryptResponse {
            ciphertext: general_purpose::STANDARD.encode(&combined_ciphertext),
            key_version,
            batch_results: None,
        })
    }

    /// Decrypt data
    pub async fn decrypt(
        &self,
        key_name: &str,
        req: DecryptRequest,
    ) -> Result<DecryptResponse, SecretsError> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_name)
            .ok_or_else(|| SecretsError::NotFound(format!("Key '{}' not found", key_name)))?;

        let ciphertext = general_purpose::STANDARD
            .decode(&req.ciphertext)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid ciphertext: {}", e)))?;

        if ciphertext.len() < 12 {
            return Err(SecretsError::InvalidData(
                "Ciphertext too short".to_string(),
            ));
        }

        let nonce = &ciphertext[..12];
        let encrypted_data = &ciphertext[12..];

        // Try to find the correct key version by attempting decryption
        let mut last_error = None;
        for key_version_data in &key.key_ring {
            if key_version_data.version < key.config.min_decryption_version {
                continue;
            }

            let decryption_key = if key_version_data.derived {
                if let Some(context_str) = &req.context {
                    let context = general_purpose::STANDARD.decode(context_str).map_err(|e| {
                        SecretsError::InvalidData(format!("Invalid context: {}", e))
                    })?;
                    self.derive_key(&key_version_data.key, &context)?
                } else {
                    return Err(SecretsError::InvalidData(
                        "Context required for derived keys".to_string(),
                    ));
                }
            } else {
                key_version_data.key.clone()
            };

            let associated_data = req
                .associated_data
                .as_ref()
                .map(|aad| general_purpose::STANDARD.decode(aad))
                .transpose()
                .map_err(|e| {
                    SecretsError::InvalidData(format!("Invalid associated data: {}", e))
                })?;

            match self.decrypt_data(
                &decryption_key,
                encrypted_data,
                nonce,
                associated_data.as_deref(),
            ) {
                Ok(plaintext) => {
                    return Ok(DecryptResponse {
                        plaintext: general_purpose::STANDARD.encode(&plaintext),
                        key_version: key_version_data.version,
                        batch_results: None,
                    });
                }
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        Err(last_error
            .unwrap_or_else(|| SecretsError::InvalidData("Decryption failed".to_string())))
    }

    /// Rotate a key
    pub async fn rotate_key(
        &self,
        key_name: &str,
        req: RotateKeyRequest,
    ) -> Result<u32, SecretsError> {
        let mut keys = self.keys.write().await;
        let key = keys
            .get_mut(key_name)
            .ok_or_else(|| SecretsError::NotFound(format!("Key '{}' not found", key_name)))?;

        let key_size = req.key_size.unwrap_or(256);
        let new_key = self.generate_key(key_size);

        let new_version = key.key_ring.len() as u32 + 1;
        let key_version = KeyVersion {
            version: new_version,
            key: new_key,
            creation_time: Utc::now().timestamp(),
            derived: key.key_ring[0].derived,
        };

        key.key_ring.push(key_version);
        key.updated_at = Utc::now().timestamp();

        // Remove old versions if we exceed max_versions
        while key.key_ring.len() > key.config.max_versions as usize {
            key.key_ring.remove(0);
        }

        self.save_key(key).await?;
        Ok(new_version)
    }

    /// Generate HMAC
    pub async fn hmac(
        &self,
        key_name: &str,
        req: HmacRequest,
    ) -> Result<HmacResponse, SecretsError> {
        let keys = self.keys.read().await;
        let key = keys
            .get(key_name)
            .ok_or_else(|| SecretsError::NotFound(format!("Key '{}' not found", key_name)))?;

        let key_version = req.key_version.unwrap_or(key.config.min_encryption_version);
        let key_version_data = key
            .key_ring
            .iter()
            .find(|kv| kv.version == key_version)
            .ok_or_else(|| SecretsError::InvalidData("Key version not found".to_string()))?;

        let input = general_purpose::STANDARD
            .decode(&req.input)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid input: {}", e)))?;

        use hmac::{Hmac, Mac};
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key_version_data.key)
            .map_err(|e| SecretsError::InvalidData(format!("Invalid key for HMAC: {:?}", e)))?;

        mac.update(&input);
        let result = mac.finalize();
        let hmac_bytes = result.into_bytes();

        Ok(HmacResponse {
            hmac: general_purpose::STANDARD.encode(hmac_bytes),
            key_version,
        })
    }

    /// Generate random bytes
    pub async fn random(&self, num_bytes: usize) -> Result<String, SecretsError> {
        if num_bytes == 0 || num_bytes > 1024 {
            return Err(SecretsError::InvalidData(
                "Invalid number of bytes".to_string(),
            ));
        }

        let mut random_bytes = vec![0u8; num_bytes];
        OsRng.fill_bytes(&mut random_bytes);

        Ok(general_purpose::STANDARD.encode(&random_bytes))
    }
}

#[async_trait]
impl SecretsEngine for TransitSecretsEngine {
    fn engine_type(&self) -> &'static str {
        "transit"
    }

    async fn create_secret(
        &self,
        path: &str,
        data: Value,
        _options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For transit engine, create operations are handled via the put method
        // This is a simplified implementation - in practice you'd want more sophisticated routing
        match path {
            "keys" => {
                if let Some(key_name) = data.get("name").and_then(|v| v.as_str()) {
                    let req = CreateKeyRequest {
                        convergent_encryption: data
                            .get("convergent_encryption")
                            .and_then(|v| v.as_bool()),
                        derived: data.get("derived").and_then(|v| v.as_bool()),
                        exportable: data.get("exportable").and_then(|v| v.as_bool()),
                        allow_plaintext_backup: data
                            .get("allow_plaintext_backup")
                            .and_then(|v| v.as_bool()),
                        key_size: data
                            .get("key_size")
                            .and_then(|v| v.as_u64())
                            .map(|v| v as u32),
                        key_type: data
                            .get("type")
                            .and_then(|v| v.as_str())
                            .map(|v| v.to_string()),
                    };
                    self.create_key(key_name, req).await?;
                    let now = Utc::now();
                    Ok(Secret {
                        id: Uuid::new_v4(),
                        path: path.to_string(),
                        data: serde_json::json!({"name": key_name, "created": true}),
                        metadata: SecretMetadata {
                            created_at: now,
                            updated_at: now,
                            version: 1,
                            ttl: None,
                            expired_at: None,
                            custom_metadata: None,
                        },
                    })
                } else {
                    Err(SecretsError::InvalidData("Key name required".to_string()))
                }
            }
            _ => Err(SecretsError::InvalidData(
                "Unsupported path for create".to_string(),
            )),
        }
    }

    async fn read_secret(&self, path: &str) -> Result<Secret, SecretsError> {
        if let Some(key_name) = path.strip_prefix("keys/") {
            let key = self.load_key(key_name).await?;
            let _now = Utc::now();
            Ok(Secret {
                id: Uuid::new_v4(),
                path: path.to_string(),
                data: serde_json::to_value(&key).unwrap(),
                metadata: SecretMetadata {
                    created_at: chrono::DateTime::from_timestamp(key.created_at, 0)
                        .unwrap_or_else(Utc::now),
                    updated_at: chrono::DateTime::from_timestamp(key.updated_at, 0)
                        .unwrap_or_else(Utc::now),
                    version: 1,
                    ttl: None,
                    expired_at: None,
                    custom_metadata: None,
                },
            })
        } else {
            Err(SecretsError::NotFound(format!("Key not found: {}", path)))
        }
    }

    async fn update_secret(
        &self,
        path: &str,
        data: Value,
        options: Option<Value>,
    ) -> Result<Secret, SecretsError> {
        // For transit, updates are similar to creates
        self.create_secret(path, data, options).await
    }

    async fn delete_secret(&self, path: &str) -> Result<(), SecretsError> {
        if let Some(key_name) = path.strip_prefix("keys/") {
            let mut keys = self.keys.write().await;
            if let Some(key) = keys.remove(key_name) {
                if !key.config.deletion_allowed {
                    keys.insert(key_name.to_string(), key);
                    return Err(SecretsError::PermissionDenied(format!(
                        "Deletion not allowed for key: {}",
                        key_name
                    )));
                }
                let key_path = format!("transit/keys/{}", key_name);
                self.storage
                    .delete(&key_path)
                    .await
                    .map_err(|e| SecretsError::Storage(e.to_string()))?;
            }
        }
        Ok(())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>, SecretsError> {
        match path {
            "keys" => {
                let keys = self.keys.read().await;
                Ok(keys.keys().cloned().collect())
            }
            _ => Ok(vec![]),
        }
    }
}

/// Create a new Transit secrets engine
pub fn new_transit_engine(storage: Arc<dyn crate::storage::StorageEngine>) -> BoxedSecretsEngine {
    Box::new(TransitSecretsEngine::new(storage))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageEntry;
    use crate::test_utils::create_test_storage;

    async fn setup_engine() -> TransitSecretsEngine {
        let storage = create_test_storage().await;
        TransitSecretsEngine::new(storage)
    }

    #[tokio::test]
    async fn test_create_key() {
        let engine = setup_engine().await;

        let req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(false),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };

        let result = engine.create_key("test-key", req).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let engine = setup_engine().await;

        // Create key
        let create_req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(false),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };
        engine.create_key("test-key", create_req).await.unwrap();

        // Encrypt
        let plaintext = general_purpose::STANDARD.encode("Hello, World!");
        let encrypt_req = EncryptRequest {
            plaintext,
            context: None,
            key_version: None,
            nonce: None,
            associated_data: None,
            batch_input: None,
        };

        let encrypt_result = engine.encrypt("test-key", encrypt_req).await;
        assert!(encrypt_result.is_ok());
        let encrypt_resp = encrypt_result.unwrap();

        // Decrypt
        let decrypt_req = DecryptRequest {
            ciphertext: encrypt_resp.ciphertext,
            context: None,
            nonce: None,
            associated_data: None,
            batch_input: None,
        };

        let decrypt_result = engine.decrypt("test-key", decrypt_req).await;
        assert!(decrypt_result.is_ok());
        let decrypt_resp = decrypt_result.unwrap();

        let decrypted_plaintext = general_purpose::STANDARD
            .decode(&decrypt_resp.plaintext)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_plaintext).unwrap(),
            "Hello, World!"
        );
    }

    #[tokio::test]
    async fn test_key_rotation() {
        let engine = setup_engine().await;

        // Create key
        let create_req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(false),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };
        engine.create_key("test-key", create_req).await.unwrap();

        // Rotate key
        let rotate_req = RotateKeyRequest {
            key_size: Some(256),
        };

        let rotate_result = engine.rotate_key("test-key", rotate_req).await;
        assert!(rotate_result.is_ok());
        assert_eq!(rotate_result.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_hmac() {
        let engine = setup_engine().await;

        // Create key
        let create_req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(false),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };
        engine.create_key("test-key", create_req).await.unwrap();

        // Generate HMAC
        let input = general_purpose::STANDARD.encode("test input");
        let hmac_req = HmacRequest {
            input,
            key_version: None,
            algorithm: Some("sha256".to_string()),
        };

        let hmac_result = engine.hmac("test-key", hmac_req).await;
        assert!(hmac_result.is_ok());
        let hmac_resp = hmac_result.unwrap();

        // HMAC should be base64 encoded
        let hmac_bytes = general_purpose::STANDARD.decode(&hmac_resp.hmac);
        assert!(hmac_bytes.is_ok());
        assert_eq!(hmac_bytes.unwrap().len(), 32); // SHA256 produces 32 bytes
    }

    #[tokio::test]
    async fn test_random_generation() {
        let engine = setup_engine().await;

        let random_result = engine.random(32).await;
        assert!(random_result.is_ok());

        let random_data = general_purpose::STANDARD.decode(&random_result.unwrap());
        assert!(random_data.is_ok());
        assert_eq!(random_data.unwrap().len(), 32);
    }

    #[tokio::test]
    async fn test_derived_keys() {
        let engine = setup_engine().await;

        // Create derived key
        let create_req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(true),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };
        engine.create_key("derived-key", create_req).await.unwrap();

        // Encrypt with context
        let plaintext = general_purpose::STANDARD.encode("Hello, Derived World!");
        let context = general_purpose::STANDARD.encode("test-context");
        let encrypt_req = EncryptRequest {
            plaintext,
            context: Some(context.clone()),
            key_version: None,
            nonce: None,
            associated_data: None,
            batch_input: None,
        };

        let encrypt_result = engine.encrypt("derived-key", encrypt_req).await;
        assert!(encrypt_result.is_ok());
        let encrypt_resp = encrypt_result.unwrap();

        // Decrypt with same context
        let decrypt_req = DecryptRequest {
            ciphertext: encrypt_resp.ciphertext,
            context: Some(context),
            nonce: None,
            associated_data: None,
            batch_input: None,
        };

        let decrypt_result = engine.decrypt("derived-key", decrypt_req).await;
        assert!(decrypt_result.is_ok());
        let decrypt_resp = decrypt_result.unwrap();

        let decrypted_plaintext = general_purpose::STANDARD
            .decode(&decrypt_resp.plaintext)
            .unwrap();
        assert_eq!(
            String::from_utf8(decrypted_plaintext).unwrap(),
            "Hello, Derived World!"
        );
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let engine = setup_engine().await;

        let encrypt_req = EncryptRequest {
            plaintext: general_purpose::STANDARD.encode("test"),
            context: None,
            key_version: None,
            nonce: None,
            associated_data: None,
            batch_input: None,
        };

        let result = engine.encrypt("nonexistent-key", encrypt_req).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SecretsError::NotFound(_)));
    }

    #[tokio::test]
    async fn test_secrets_engine_interface() {
        let engine = setup_engine().await;

        // Setup initial config for testing
        let config = TransitConfig::default();
        let config_entry = StorageEntry {
            key: "config".to_string(),
            value: serde_json::to_vec(&config).unwrap(),
            metadata: HashMap::new(),
        };
        engine.storage.put(config_entry).await.unwrap();

        // Test get config
        let config_result = engine.storage.get("config").await;
        assert!(config_result.is_ok());
        assert!(config_result.unwrap().is_some());

        // Test list keys (should be empty initially)
        let list_result = engine.storage.list("keys").await;
        assert!(list_result.is_ok());
        assert_eq!(list_result.unwrap().len(), 0);

        // Create a key via put
        let create_req = CreateKeyRequest {
            convergent_encryption: Some(false),
            derived: Some(false),
            exportable: Some(false),
            allow_plaintext_backup: Some(false),
            key_size: Some(256),
            key_type: Some("aes256-gcm96".to_string()),
        };

        let entry = StorageEntry {
            key: "keys/test-key".to_string(),
            value: serde_json::to_vec(&create_req).unwrap(),
            metadata: HashMap::new(),
        };
        let put_result = engine.storage.put(entry).await;
        assert!(put_result.is_ok());

        // Test list keys again
        let list_result = engine.storage.list("keys").await;
        assert!(list_result.is_ok());
        assert_eq!(list_result.unwrap().len(), 1);

        // Test get key
        let get_result = engine.storage.get("keys/test-key").await;
        assert!(get_result.is_ok());
        assert!(get_result.unwrap().is_some());

        // Test delete key
        let delete_result = engine.storage.delete("keys/test-key").await;
        assert!(delete_result.is_ok());

        // Test list keys after delete
        let list_result = engine.storage.list("keys").await;
        assert!(list_result.is_ok());
        assert_eq!(list_result.unwrap().len(), 0);
    }
}
