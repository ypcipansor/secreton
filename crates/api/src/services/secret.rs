//! Secret service for business logic operations.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use secreton_core::audit::AuditLogger;
use secreton_crypto::CryptoService;
use secreton_storage::StorageBackend;

/// Secret service errors
#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found: {path}")]
    SecretNotFound { path: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Policy not found: {name}")]
    PolicyNotFound { name: String },

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Crypto error: {0}")]
    Crypto(#[from] secreton_crypto::CryptoError),

    #[error("Storage error: {0}")]
    Storage(#[from] secreton_storage::StorageError),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Secret service for business logic operations
pub struct SecretService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    audit: Arc<AuditLogger>,
}

impl SecretService {
    /// Create new secret service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            crypto,
            audit,
        })
    }

    /// Get secret by path
    pub async fn get_secret(&self, path: &str, user_id: &str) -> Result<SecretData, SecretError> {
        // Check permissions via storage backend
        let has_permission = self.storage.check_policy(user_id, path, "read").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied(format!("No read permission for path: {}", path)));
        }

        // Get encrypted secret from storage
        let encrypted_data = self.storage.retrieve(path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::SecretNotFound { path: path.to_string() })?;

        // Decrypt the secret data
        let decrypted_data = self.crypto.decrypt_data(&encrypted_data)
            .map_err(|e| SecretError::Crypto(e))?;

        // Parse the decrypted data as JSON (assuming it's stored as JSON)
        let secret_map: HashMap<String, String> = serde_json::from_slice(&decrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to parse secret data: {}", e)))?;

        // Get metadata from storage (version, timestamps)
        let entry = self.storage.get_by_path(&format!("secrets/{}", path)).await
            .map_err(|e| SecretError::Storage(e))?;

        let (version, created_at, updated_at) = match entry {
            Some(entry) => (entry.version, entry.created_at, entry.updated_at),
            None => return Err(SecretError::SecretNotFound(path.to_string())),
        };

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::SecretAccess {
                secret_path: path.to_string(),
                user: user_id.to_string(),
                action: "read".to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok(SecretData {
            path: path.to_string(),
            data: secret_map,
            version,
            created_at,
            updated_at,
        })
    }

    /// Create or update secret
    pub async fn put_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
        user_id: &str,
    ) -> Result<SecretData, SecretError> {
        // Check permissions via storage backend
        let has_permission = self.storage.check_policy(user_id, path, "write").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied(format!("No write permission for path: {}", path)));
        }

        // Serialize data to JSON for storage
        let json_data = serde_json::to_vec(&data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize secret data: {}", e)))?;

        // Encrypt the data
        let encrypted_data = self.crypto.encrypt_data(&json_data)
            .map_err(|e| SecretError::Crypto(e))?;

        // Store encrypted data
        self.storage.store(path, &encrypted_data).await
            .map_err(|e| SecretError::Storage(e))?;

        // Get version info (increment version for updates)
        let existing_entry = self.storage.get_by_path(&format!("secrets/{}", path)).await
            .map_err(|e| SecretError::Storage(e))?;

        let (version, created_at) = match existing_entry {
            Some(entry) => (entry.version + 1, entry.created_at),
            None => (1, chrono::Utc::now()),
        };
        let updated_at = chrono::Utc::now();

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::SecretCreation {
                secret_path: path.to_string(),
                user: user_id.to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok(SecretData {
            path: path.to_string(),
            data,
            version,
            created_at,
            updated_at,
        })
    }

    /// Delete secret
    pub async fn delete_secret(&self, path: &str, user_id: &str) -> Result<(), SecretError> {
        // Check permissions via storage backend
        let has_permission = self.storage.check_policy(user_id, path, "delete").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied(format!("No delete permission for path: {}", path)));
        }

        // Check if secret exists before deletion
        let exists = self.storage.retrieve(path).await
            .map_err(|e| SecretError::Storage(e))?
            .is_some();

        if !exists {
            return Err(SecretError::SecretNotFound { path: path.to_string() });
        }

        // Delete from storage
        self.storage.delete(path).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::SecretDeletion {
                secret_path: path.to_string(),
                user: user_id.to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok(())
    }

    /// List secrets with metadata
    pub async fn list_secrets(
        &self,
        prefix: Option<&str>,
        user_id: &str,
    ) -> Result<Vec<SecretData>, SecretError> {
        // Get all secrets from storage (in production, this would be filtered by permissions)
        let all_secrets = self.storage.list(prefix).await
            .map_err(|e| SecretError::Storage(e))?;

        // Filter secrets based on user permissions and retrieve metadata
        let mut accessible_secrets = Vec::new();
        for secret_path in all_secrets {
            let has_permission = self.storage.check_policy(user_id, &secret_path, "read").await
                .map_err(|e| SecretError::Storage(e))?;

            if has_permission {
                // Get full secret data including metadata
                match self.get_secret(&secret_path, user_id).await {
                    Ok(secret_data) => accessible_secrets.push(secret_data),
                    Err(e) => {
                        warn!("Failed to get secret data for {}: {}", secret_path, e);
                        // Continue - don't fail the whole list if one secret has issues
                    }
                }
            }
        }

        Ok(accessible_secrets)
    }

    /// Create encryption key
    pub async fn create_key(
        &self,
        key_name: &str,
        key_type: &str,
        user_id: &str,
    ) -> Result<KeyInfo, SecretError> {
        // Check permissions for key creation
        let has_permission = self.storage.check_policy(user_id, "keys", "create").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to create keys".to_string()));
        }

        // Map key type to algorithm
        let algorithm = match key_type {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => return Err(SecretError::InvalidOperation(format!("Unsupported key type: {}", key_type))),
        };

        // Generate key using crypto service
        let key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Crypto(e))?;

        // Generate unique key ID
        let key_id = format!("key_{}", uuid::Uuid::new_v4().simple());

        // Store key metadata in storage backend
        let key_path = format!("keys/{}/{}", user_id, key_name);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": key_type,
            "algorithm": algorithm,
            "created_by": user_id,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": 1
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e)))?;

        self.storage.store(&key_path, &metadata_bytes).await
            .map_err(|e| SecretError::Storage(e))?;

        // Encrypt the key data before storing
        let encrypted_key_data = self.crypto.encrypt_data(&key_data)
            .map_err(|e| SecretError::Crypto(e))?;
        
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        self.storage.store(&key_data_path, &encrypted_key_data).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::KeyGeneration {
                key_id: key_id.clone(),
                key_type: key_type.to_string(),
                user: user_id.to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok(KeyInfo {
            id: key_id,
            name: key_name.to_string(),
            key_type: key_type.to_string(),
            version: 1,
            created_at: chrono::Utc::now(),
        })
    }

    /// Get key information
    pub async fn get_key(&self, key_id: &str, user_id: &str) -> Result<KeyInfo, SecretError> {
        // Check permissions for key access
        let has_permission = self.storage.check_policy(user_id, &format!("keys/{}", key_id), "read").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to access key".to_string()));
        }

        // Retrieve key metadata from storage
        let key_path = format!("keys/{}/{}", user_id, key_id);
        let metadata_bytes = self.storage.retrieve(&key_path).await
            .map_err(|e| SecretError::Storage(e))?;

        let metadata: serde_json::Value = serde_json::from_slice(&metadata_bytes)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to deserialize key metadata: {}", e)))?;

        // Extract key information
        let name = metadata.get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or(key_id)
            .to_string();

        let key_type = metadata.get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = metadata.get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;

        let created_at_str = metadata.get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&chrono::Utc::now().to_rfc3339());

        let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        Ok(KeyInfo {
            id: key_id.to_string(),
            name,
            key_type,
            version,
            created_at,
        })
    }

    /// List keys for a user
    pub async fn list_keys(&self, user_id: &str, filter: Option<&str>) -> Result<Vec<KeyInfo>, SecretError> {
        // Check permissions for key listing
        let has_permission = self.storage.check_policy(user_id, "keys", "read").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to list keys".to_string()));
        }

        // List key metadata from storage
        let keys_prefix = format!("keys/{}/", user_id);
        let key_paths = self.storage.list(&keys_prefix).await
            .map_err(|e| SecretError::Storage(e))?;

        let mut keys = Vec::new();
        for path in key_paths {
            // Extract key name from path
            if let Some(key_name) = path.strip_prefix(&keys_prefix) {
                // Apply filter if provided
                if let Some(filter_str) = filter {
                    if !key_name.contains(filter_str) {
                        continue;
                    }
                }

                // Retrieve key metadata
                match self.storage.retrieve(&path).await {
                    Ok(metadata_bytes) => {
                        match serde_json::from_slice::<serde_json::Value>(&metadata_bytes) {
                            Ok(metadata) => {
                                let key_id = metadata.get("key_id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(key_name)
                                    .to_string();

                                let key_type = metadata.get("key_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();

                                let version = metadata.get("version")
                                    .and_then(|v| v.as_u64())
                                    .unwrap_or(1) as u32;

                                let created_at_str = metadata.get("created_at")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or(&chrono::Utc::now().to_rfc3339());

                                let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
                                    .map(|dt| dt.with_timezone(&chrono::Utc))
                                    .unwrap_or_else(|_| chrono::Utc::now());

                                keys.push(KeyInfo {
                                    id: key_id,
                                    name: key_name.to_string(),
                                    key_type,
                                    version,
                                    created_at,
                                });
                            }
                            Err(e) => {
                                warn!("Failed to deserialize key metadata for {}: {}", path, e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to retrieve key metadata for {}: {}", path, e);
                        continue;
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Rotate a key (create new version)
    pub async fn rotate_key(&self, key_id: &str, user_id: &str) -> Result<KeyInfo, SecretError> {
        // Check permissions for key rotation
        let has_permission = self.storage.check_policy(user_id, &format!("keys/{}", key_id), "update").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to rotate key".to_string()));
        }

        // Get current key metadata
        let current_key = self.get_key(key_id, user_id).await?;

        // Generate new key with same type
        let algorithm = match current_key.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => return Err(SecretError::InvalidOperation(format!("Unsupported key type: {}", current_key.key_type))),
        };

        // Generate new key data
        let new_key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Crypto(e))?;

        // Update metadata with new version
        let new_version = current_key.version + 1;
        let key_path = format!("keys/{}/{}", user_id, key_id);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": current_key.key_type,
            "algorithm": algorithm,
            "created_by": user_id,
            "created_at": current_key.created_at.to_rfc3339(),
            "version": new_version,
            "rotated_at": chrono::Utc::now().to_rfc3339()
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e)))?;

        self.storage.store(&key_path, &metadata_bytes).await
            .map_err(|e| SecretError::Storage(e))?;

        // Store new key data with version
        let new_key_data_path = format!("key_data/{}/{}_v{}", user_id, key_id, new_version);
        self.storage.store(&new_key_data_path, &new_key_data).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::KeyRotation {
                old_key_id: key_id.to_string(),
                new_key_id: format!("{}_v{}", key_id, new_version),
                algorithm: current_key.key_type,
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok(KeyInfo {
            id: key_id.to_string(),
            name: current_key.name,
            key_type: current_key.key_type,
            version: new_version,
            created_at: chrono::Utc::now(),
        })
    }

    /// Encrypt data using a key
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        user_id: &str,
    ) -> Result<(EncryptedData, u32), SecretError> {
        // Check permissions for encryption
        let has_permission = self.storage.check_policy(user_id, "keys", "encrypt").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to encrypt data".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_data = self.storage.retrieve(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?;

        // Generate nonce/IV
        let nonce = secreton_crypto::generate_random_bytes(12)
            .map_err(|e| SecretError::Crypto(e))?;

        // Encrypt data
        let ciphertext = secreton_crypto::encrypt(&key_data, &nonce, plaintext, None)
            .map_err(|e| SecretError::Crypto(e))?;

        // Create key ID for audit
        let key_id = format!("{}/{}", user_id, key_name);

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::Encryption {
                key_id: key_id.clone(),
                data_size: plaintext.len(),
                user: user_id.to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok((EncryptedData {
            ciphertext: ciphertext,
            nonce: nonce,
            key_id: key_id,
        }, key_info.version))
    }

    /// Decrypt data using a key
    pub async fn decrypt(
        &self,
        key_name: &str,
        encrypted_data: &EncryptedData,
        user_id: &str,
    ) -> Result<(Vec<u8>, u32), SecretError> {
        // Check permissions for decryption
        let has_permission = self.storage.check_policy(user_id, "keys", "decrypt").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to decrypt data".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Verify key ownership
        let expected_key_id = format!("{}/{}", user_id, key_name);
        if encrypted_data.key_id != expected_key_id {
            return Err(SecretError::InvalidOperation("Key ID mismatch".to_string()));
        }

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_data = self.storage.retrieve(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?;

        // Decrypt data
        let plaintext = secreton_crypto::decrypt(&key_data, &encrypted_data.nonce, &encrypted_data.ciphertext, None)
            .map_err(|e| SecretError::Crypto(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            secreton_core::audit::SecurityEventType::Decryption {
                key_id: encrypted_data.key_id.clone(),
                data_size: plaintext.len(),
                user: user_id.to_string(),
            },
            Some(user_id.to_string()),
            None,
            None,
            Default::default(),
        ).await;

        Ok((plaintext, key_info.version))
    }

    /// Verify signature using a key
    pub async fn verify_data(
        &self,
        key_name: &str,
        data: &[u8],
        signature: &[u8],
        user_id: &str,
    ) -> Result<(bool, u32), SecretError> {
        // Check permissions for signature verification
        let has_permission = self.storage.check_policy(user_id, "keys", "read").await
            .map_err(|e| SecretError::Storage(e))?;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to verify signatures".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_data = self.storage.retrieve(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?;

        // Verify signature
        let is_valid = secreton_crypto::verify_signature(&key_data, data, signature)
            .map_err(|e| SecretError::Crypto(e))?;

        Ok((is_valid, key_info.version))
    }
}

/// Secret data structure
#[derive(Debug, Serialize)]
pub struct SecretData {
    pub path: String,
    pub data: HashMap<String, String>,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Key information
#[derive(Debug, Serialize)]
pub struct KeyInfo {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Encryption result
#[derive(Debug, Serialize)]
pub struct EncryptResult {
    pub ciphertext: String,
    pub key_version: u32,
}

/// Decryption result
#[derive(Debug, Serialize)]
pub struct DecryptResult {
    pub plaintext: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_crypto::SecurityParams;
    use secreton_storage::MockStorageBackend;
    use crate::config::AuthConfig;
    use crate::services::auth::AuthService;
    use secreton_core::audit::AuditLogger;

    #[tokio::test]
    async fn test_secreton_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());

        let secreton_service = SecretService::new(storage, crypto, audit).await;
        assert!(secreton_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_secret_placeholder() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = SecretService::new(storage, crypto, audit).await.unwrap();

        let secret = service.get_secret("app/config", "user1").await.unwrap();
        assert_eq!(secret.path, "app/config");
        assert!(secret.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_put_secret_placeholder() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = SecretService::new(storage, crypto, audit).await.unwrap();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        let secret = service.put_secret("app/admin", data, "user1").await.unwrap();
        assert_eq!(secret.path, "app/admin");
        assert!(secret.data.contains_key("username"));
    }

    #[tokio::test]
    async fn test_encrypt_placeholder_response() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(SecurityParams::default()).unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = SecretService::new(storage, crypto, audit).await.unwrap();

        let result = service.encrypt("key1", "plaintext", "user1").await.unwrap();
        assert_eq!(result.ciphertext, "encrypted_data");
        assert_eq!(result.key_version, 1);
    }
}
