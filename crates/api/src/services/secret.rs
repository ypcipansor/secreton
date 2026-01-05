//! Secret service for business logic operations.

use std::collections::HashMap;
use std::sync::Arc;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::warn;
use thiserror::Error;

use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::crypto::CryptoService;
use secreton_auth::policies::service::PolicyService;
use secreton_auth::policies::model::EvaluationContext;
use secreton_crypto::EncryptedData;
use secreton_storage::StorageBackend;
use secreton_core::User;

/// Policy metadata
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PolicyMetadata {
    pub description: Option<String>,
    pub created_by: String,
    pub owner: Option<String>,
    pub tags: std::collections::HashMap<String, String>,
}

/// Signing result
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SignResult {
    pub signature: String,
    pub key_version: u32,
}

/// Policy definition
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Policy {
    pub name: String,
    pub rules: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: PolicyMetadata,
}

/// Secret service errors
#[derive(Error, Debug)]
pub enum SecretError {
    #[error("Secret not found: {path}")]
    SecretNotFound { path: String },

    #[error("Key not found: {key_id}")]
    KeyNotFound { key_id: String },

    #[error("Policy not found: {name}")]
    PolicyNotFound { name: String },

    #[error("Backup not found: {id}")]
    BackupNotFound { id: String },

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
    policy_service: Arc<PolicyService>,
}

impl SecretService {
    /// Create new secret service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
        policy_service: Arc<PolicyService>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            crypto,
            audit,
            policy_service,
        })
    }

    /// Check permission for an action on a resource
    async fn check_permission(&self, user_id: &str, action: &str, path: &str) -> Result<bool, SecretError> {
        let mut subject = HashMap::new();
        subject.insert("id".to_string(), user_id.to_string());

        let mut resource = HashMap::new();
        resource.insert("path".to_string(), path.to_string());

        let context = EvaluationContext {
            subject,
            resource,
            action: action.to_string(),
            environment: HashMap::new(),
        };

        // TODO: Pass actual user roles once IdentityService is integrated
        let result = self.policy_service.evaluate_access(&context, &[])
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Policy evaluation error: {}", e)))?;

        Ok(result.allowed)
    }

    /// Get secret by path
    pub async fn get_secret(&self, path: &str, user_id: &str) -> Result<SecretData, SecretError> {
        // Check permissions - temporarily allow all reads for development
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied(format!("No read permission for path: {}", path)));
        }

        // Get encrypted secret from storage
        let encrypted_entry = self.storage.get_by_path(path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::SecretNotFound { path: path.to_string() })?;

        // Decrypt the secret data
        let decrypted_data = self.crypto.decrypt(&encrypted_entry.encrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse the decrypted data as JSON
        let secret_map: HashMap<String, String> = serde_json::from_slice(&decrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to parse secret data: {}", e)))?;

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::SecretAccess {
                secret_path: path.to_string(),
                user: user_id.to_string(),
                action: "read".to_string(),
            },
        ).await;

        Ok(SecretData {
            path: path.to_string(),
            data: secret_map,
            version: encrypted_entry.version,
            created_at: encrypted_entry.created_at,
            updated_at: encrypted_entry.updated_at,
        })
    }

    /// Create or update secret
    pub async fn put_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
        user_id: &str,
    ) -> Result<SecretData, SecretError> {
        // Check permissions - temporarily allow all writes for development
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied(format!("No write permission for path: {}", path)));
        }

        // Serialize data to JSON for storage
        let json_data = serde_json::to_vec(&data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize secret data: {}", e)))?;

        // Encrypt the data
        let encrypted_data = self.crypto.encrypt_data(&json_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = uuid::Uuid::parse_str(user_id)
            .unwrap_or_else(|_| uuid::Uuid::new_v4());

        // Create SecretEntry
        let entry = secreton_storage::SecretEntry::new(
            path.to_string(),
            encrypted_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Confidential,
            owner_id,
        );

        // Store encrypted data
        self.storage.store(&entry).await
            .map_err(|e| SecretError::Storage(e))?;

        let _now = chrono::Utc::now();

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::SecretCreation {
                secret_path: path.to_string(),
                user: user_id.to_string(),
            },
        ).await;

        Ok(SecretData {
            path: path.to_string(),
            data,
            version: entry.version,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }

    /// Delete secret
    pub async fn delete_secret(&self, path: &str, user_id: &str) -> Result<(), SecretError> {
        // Check permissions
        if !self.check_permission(user_id, "delete", path).await? {
            return Err(SecretError::PermissionDenied(format!("No delete permission for path: {}", path)));
        }

        // Check if secret exists before deletion
        let exists = self.storage.get_by_path(path).await
            .map_err(|e| SecretError::Storage(e))?
            .is_some();

        if !exists {
            return Err(SecretError::SecretNotFound { path: path.to_string() });
        }

        // Delete from storage using delete_by_path
        self.storage.delete_by_path(path).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::SecretDeletion {
                secret_path: path.to_string(),
                user: user_id.to_string(),
            },
        ).await;

        Ok(())
    }

    /// Create a new policy
    pub async fn create_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
        user_id: &str,
    ) -> Result<Policy, SecretError> {
        self.update_policy(name, rules, metadata, user_id).await
    }

    /// Get policy by name
    pub async fn get_policy(&self, name: &str) -> Result<Policy, SecretError> {
        // Placeholder
        Ok(Policy {
            name: name.to_string(),
            rules: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: PolicyMetadata {
                description: None,
                created_by: "system".to_string(),
                owner: None,
                tags: std::collections::HashMap::new(),
            },
        })
    }

    /// Delete policy
    pub async fn delete_policy(&self, _name: &str, _user_id: &str) -> Result<bool, SecretError> {
        // Placeholder
        Ok(true)
    }

    /// List secrets with metadata
    pub async fn list_secrets(
        &self,
        prefix: Option<&str>,
        user: &User,
    ) -> Result<Vec<SecretData>, SecretError> {
        // Parse user_id as UUID for ownership check
        let user_uuid = uuid::Uuid::parse_str(&user.id).unwrap_or_default();
        let is_admin = user.roles.iter().any(|r| r == "admin" || r == "superuser");

        // Build query params
        // Optimize: Use storage-level filtering for owner_id if not admin
        let mut query = secreton_storage::QueryParams::new();

        if let Some(p) = prefix {
            query = query.with_path_prefix(p.to_string());
        }

        if !is_admin {
            query = query.with_owner(user_uuid);
        }

        // Get secrets from storage
        // The storage backend handles filtering by owner_id if set in query
        let entries = self.storage.list(&query).await
            .map_err(|e| SecretError::Storage(e))?;

        // Convert entries to SecretData
        let mut accessible_secrets = Vec::new();
        for entry in entries {
            // Decrypt the secret data
            match self.crypto.decrypt(&entry.encrypted_data) {
                Ok(decrypted_data) => {
                    // Parse the decrypted data as JSON
                    match serde_json::from_slice::<HashMap<String, String>>(&decrypted_data) {
                        Ok(secret_map) => {
                            accessible_secrets.push(SecretData {
                                path: entry.path.clone(),
                                data: secret_map,
                                version: entry.version,
                                created_at: entry.created_at,
                                updated_at: entry.updated_at,
                            });
                        }
                        Err(e) => {
                            warn!("Failed to parse secret data for {}: {}", entry.path, e);
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to decrypt secret data for {}: {}", entry.path, e);
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
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

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
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Generate unique key ID
        let key_id = format!("key_{}", uuid::Uuid::new_v4().simple());

        // Parse user_id as UUID
        let owner_id = uuid::Uuid::parse_str(user_id)
            .unwrap_or_else(|_| uuid::Uuid::new_v4());

        // Store key metadata as SecretEntry
        let key_path = format!("keys/{}/{}", user_id, key_name);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": key_type,
            "algorithm": format!("{:?}", algorithm),
            "created_by": user_id,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": 1
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e)))?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path.clone(),
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        self.storage.store(&metadata_entry).await
            .map_err(|e| SecretError::Storage(e))?;

        // Encrypt the key data before storing
        let encrypted_key_data = self.crypto.encrypt_data(&key_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;
        
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_data_entry = secreton_storage::SecretEntry::new(
            key_data_path,
            encrypted_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage.store(&key_data_entry).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::KeyGeneration {
                key_id: key_id.clone(),
                key_type: key_type.to_string(),
                algorithm: key_type.to_string(),
                user: user_id.to_string(),
            },
        ).await;

        Ok(KeyInfo {
            id: key_id,
            name: key_name.to_string(),
            key_type: key_type.to_string(),
            version: 1,
            status: "active".to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    /// Get key information
    pub async fn get_key(&self, key_id: &str, user_id: &str) -> Result<KeyInfo, SecretError> {
        // Check permissions for key access
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to access key".to_string()));
        }

        // Retrieve key metadata from storage
        let key_path = format!("keys/{}/{}", user_id, key_id);
        let entry = self.storage.get_by_path(&key_path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::KeyNotFound { key_id: key_id.to_string() })?;

        let metadata: serde_json::Value = serde_json::from_slice(&entry.encrypted_data)
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

        let default_time = chrono::Utc::now().to_rfc3339();
        let created_at_str = metadata.get("created_at")
            .and_then(|v| v.as_str())
            .unwrap_or(&default_time);

        let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
            .map(|dt| dt.with_timezone(&chrono::Utc))
            .unwrap_or_else(|_| chrono::Utc::now());

        Ok(KeyInfo {
            id: key_id.to_string(),
            name,
            key_type,
            version,
            status: "active".to_string(),
            created_at,
        })
    }

    /// List keys for a user
    pub async fn list_keys(&self, user_id: &str, filter: Option<&str>) -> Result<Vec<KeyInfo>, SecretError> {
        // Check permissions for key listing
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to list keys".to_string()));
        }

        // Build query params for keys
        let keys_prefix = format!("keys/{}/", user_id);
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(keys_prefix.clone());

        let entries = self.storage.list(&query).await
            .map_err(|e| SecretError::Storage(e))?;

        let mut keys = Vec::new();
        for entry in entries {
            // Extract key name from path
            if let Some(key_name) = entry.path.strip_prefix(&keys_prefix) {
                // Apply filter if provided
                if let Some(filter_str) = filter {
                    if !key_name.contains(filter_str) {
                        continue;
                    }
                }

                // Parse key metadata
                match serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data) {
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

                        let default_time = chrono::Utc::now().to_rfc3339();
                        let created_at_str = metadata.get("created_at")
                            .and_then(|v| v.as_str())
                            .unwrap_or(&default_time);

                        let created_at = chrono::DateTime::parse_from_rfc3339(created_at_str)
                            .map(|dt| dt.with_timezone(&chrono::Utc))
                            .unwrap_or_else(|_| chrono::Utc::now());

                        keys.push(KeyInfo {
                            id: key_id,
                            name: key_name.to_string(),
                            key_type,
                            version,
                            status: "active".to_string(),
                            created_at,
                        });
                    }
                    Err(e) => {
                        warn!("Failed to deserialize key metadata for {}: {}", entry.path, e);
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
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

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
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = uuid::Uuid::parse_str(user_id)
            .unwrap_or_else(|_| uuid::Uuid::new_v4());

        // Update metadata with new version
        let new_version = current_key.version + 1;
        let key_path = format!("keys/{}/{}", user_id, key_id);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": current_key.key_type,
            "algorithm": format!("{:?}", algorithm),
            "created_by": user_id,
            "created_at": current_key.created_at.to_rfc3339(),
            "version": new_version,
            "rotated_at": chrono::Utc::now().to_rfc3339()
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e)))?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path,
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        self.storage.store(&metadata_entry).await
            .map_err(|e| SecretError::Storage(e))?;

        // Store new key data with version
        let new_key_data_path = format!("key_data/{}/{}_v{}", user_id, key_id, new_version);
        let key_data_entry = secreton_storage::SecretEntry::new(
            new_key_data_path,
            new_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage.store(&key_data_entry).await
            .map_err(|e| SecretError::Storage(e))?;

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::KeyRotation {
                old_key_id: key_id.to_string(),
                new_key_id: format!("{}_v{}", key_id, new_version),
                algorithm: current_key.key_type.clone(),
                user: user_id.to_string(),
            },
        ).await;

        Ok(KeyInfo {
            id: key_id.to_string(),
            name: current_key.name,
            key_type: current_key.key_type,
            version: new_version,
            status: "active".to_string(),
            created_at: chrono::Utc::now(),
        })
    }

    /// Update key metadata
    pub async fn update_key_metadata(
        &self,
        key_id: &str,
        _metadata: &HashMap<String, String>,
        user_id: &str,
    ) -> Result<KeyInfo, SecretError> {
        // Retrieve current key info
        let key_info = self.get_key(key_id, user_id).await?;

        // In a real implementation we would update the metadata in storage
        // For now, we just return the existing key info since we can't easily modify the mock storage
        
        Ok(key_info)
    }

    /// Update policy
    pub async fn update_policy(
        &self,
        name: &str,
        _rules: Vec<String>,
        _metadata: PolicyMetadata,
        _user_id: &str,
    ) -> Result<Policy, SecretError> {
        // Placeholder implementation
        Ok(Policy {
            name: name.to_string(),
            rules: vec![],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: PolicyMetadata {
                description: None,
                created_by: "system".to_string(),
                owner: None,
                tags: std::collections::HashMap::new(),
            },
        })
    }

    pub async fn list_policies(
        &self,
        _filter: Option<&str>,
    ) -> Result<Vec<Policy>, SecretError> {
        Ok(vec![])
    }

    /// List key versions
    pub async fn list_key_versions(
        &self,
        key_id: &str,
        user_id: &str,
    ) -> Result<Vec<KeyInfo>, SecretError> {
        // Placeholder implementation
        // Check if key exists
        self.get_key(key_id, user_id).await?;
        
        // Return just the current version for now
        self.get_key(key_id, user_id).await.map(|k| vec![k])
    }

    /// Delete a key
    pub async fn delete_key(&self, _key_id: &str, _user_id: &str) -> Result<bool, SecretError> {
        // Placeholder
        Ok(true)
    }

    /// Delete a backup
    pub async fn delete_backup(&self, _backup_id: &str, _user_id: &str) -> Result<bool, SecretError> {
        // Placeholder
        Ok(true)
    }

    /// Encrypt data using a key
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        user_id: &str,
    ) -> Result<(EncryptedData, u32), SecretError> {
        // Check permissions for encryption
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to encrypt data".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_entry = self.storage.get_by_path(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::KeyNotFound { key_id: key_name.to_string() })?;

        // Decrypt the stored key data
        let key_data = self.crypto.decrypt(&key_entry.encrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Generate nonce/IV
        let nonce = secreton_crypto::generate_random_bytes(12)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Encrypt data using crypto engine
        let ciphertext = self.crypto.encrypt(&key_data, plaintext, None)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;
        
        let encrypted_data = EncryptedData {
            algorithm: secreton_crypto::AlgorithmId::Aes256Gcm,
            nonce: nonce.clone(),
            ciphertext: ciphertext.ciphertext,
            tag: ciphertext.tag,
        };

        // Create key ID for audit
        let key_id = format!("{}/{}", user_id, key_name);

        // Log audit trail
        let _ = self.audit.log_event(
            SecurityEventType::EncryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user_id.to_string(),
            },
        ).await;

        Ok((encrypted_data, key_info.version))
    }

    /// Decrypt data using a key
    pub async fn decrypt(
        &self,
        key_name: &str,
        encrypted_data: &EncryptedData,
        user_id: &str,
    ) -> Result<(Vec<u8>, u32), SecretError> {
        // Check permissions for decryption
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to decrypt data".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_entry = self.storage.get_by_path(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::KeyNotFound { key_id: key_name.to_string() })?;

        // Decrypt the stored key data
        let key_data = self.crypto.decrypt(&key_entry.encrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Decrypt the user data using the key
        let plaintext = self.crypto.decrypt_full(&key_data, &encrypted_data.nonce, &encrypted_data.ciphertext, None)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Log audit trail
        let key_id = format!("{}/{}", user_id, key_name);
        let _ = self.audit.log_event(
            SecurityEventType::DecryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user_id.to_string(),
            },
        ).await;

        Ok((plaintext, key_info.version))
    }



    /// Sign data using a key
    pub async fn sign_data(
        &self,
        key_name: &str,
        _data: &[u8],
        user_id: &str,
    ) -> Result<SignResult, SecretError> {
        // Check permissions
        // TODO: RBAC
        
        let key_info = self.get_key(key_name, user_id).await?;
        
        // In real implementation: get key -> decrypt -> sign
        // Placeholder:
        Ok(SignResult {
            signature: "placeholder_signature".to_string(),
            key_version: key_info.version,
        })
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
        // TODO: Implement proper RBAC policy check
        let has_permission = true;

        if !has_permission {
            return Err(SecretError::PermissionDenied("No permission to verify signatures".to_string()));
        }

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user_id).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user_id, key_name);
        let key_entry = self.storage.get_by_path(&key_data_path).await
            .map_err(|e| SecretError::Storage(e))?
            .ok_or_else(|| SecretError::KeyNotFound { key_id: key_name.to_string() })?;

        // Decrypt the stored key data
        let key_data = self.crypto.decrypt(&key_entry.encrypted_data)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Verify signature
        let is_valid = self.crypto.verify_signature(&key_data, data, signature)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

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
    pub status: String,
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
    use secreton_storage::{MockStorageBackend, StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
    use crate::config::AuthConfig;
    use uuid::Uuid;
    use crate::services::auth::AuthenticationService;
    use crate::services::audit::AuditLogger;
    use secreton_core::storage::secure::types::KeyEntry;
    use base64::Engine; // Import Engine trait for encoding

    #[tokio::test]
    async fn test_secreton_service_creation() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let policy_service = Arc::new(PolicyService::new());

        let secreton_service = SecretService::new(storage, crypto, audit, policy_service).await;
        assert!(secreton_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_secret_placeholder() {
        let storage = Arc::new(MockStorageBackend::new());
        // Seed secret
        let mut data = HashMap::new();
        data.insert("key1".to_string(), "value1".to_string());
        
        let secret_entry = SecretEntry::new(
            "app/config".to_string(),
            serde_json::to_vec(&data).unwrap(), // Storing map as json bytes
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&secret_entry).await;

        let crypto = Arc::new(CryptoService::new());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let policy_service = Arc::new(PolicyService::new());
        let service = SecretService::new(storage, crypto, audit, policy_service).await.unwrap();

        let secret = service.get_secret("app/config", "user1").await.unwrap();
        assert_eq!(secret.path, "app/config");
        assert!(secret.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_put_secret_placeholder() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let policy_service = Arc::new(PolicyService::new());
        let service = SecretService::new(storage, crypto, audit, policy_service).await.unwrap();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        let secret = service.put_secret("app/admin", data, "user1").await.unwrap();
        assert_eq!(secret.path, "app/admin");
        assert!(secret.data.contains_key("username"));
    }

    #[tokio::test]
    async fn test_encrypt_placeholder_response() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new());
        
        // Define key entry structure matching secreton_core model for JSON serialization
        let key_entry = KeyEntry {
            id: "key1".to_string(),
            key: base64::engine::general_purpose::STANDARD.encode(vec![1, 2, 3]),
            salt: base64::engine::general_purpose::STANDARD.encode(vec![4, 5, 6]),
            version: 1,
            created_at: chrono::Utc::now().timestamp() as u64,
            rotated_at: chrono::Utc::now().timestamp() as u64,
            active: true,
            metadata: Default::default(),
            expires_at: 0,
        };

        // Encrypt the key entry using CryptoService
        let key_json = serde_json::to_vec(&key_entry).unwrap();
        let encrypted_key = crypto.encrypt_data(&key_json).expect("failed to encrypt key data");

        // Seed Key Metadata (required by get_key)
        let key_metadata_entry = SecretEntry::new(
            "keys/user1/key1".to_string(), // Assumed path for get_key
            serde_json::to_vec(&key_entry).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_metadata_entry).await;

        // keys also stored as SecretEntry in backend
        // So keys must be stored as SecretEntry with path "keys/..."
        let key_storage_entry = SecretEntry::new(
            "key_data/user1/key1".to_string(),
            encrypted_key,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_storage_entry).await;

        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let policy_service = Arc::new(PolicyService::new());
        let service = SecretService::new(storage, crypto, audit, policy_service).await.unwrap();

        let (result, key_version) = service.encrypt("key1", "plaintext".as_bytes(), "user1").await.unwrap();
        assert!(!result.ciphertext.is_empty());
        assert_eq!(key_version, 1);
    }
}

#[cfg(test)]
mod list_secrets_tests {
    use super::*;
    use secreton_storage::{MockStorageBackend, StorageBackend, SecretEntry, EncryptionMetadata, SecurityLevel};
    use crate::services::audit::AuditLogger;
    use secreton_core::User;
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_mock_user(id: &str, roles: Vec<String>) -> User {
        User {
            id: id.to_string(),
            username: format!("user_{}", id),
            email: Some(format!("user_{}@example.com", id)),
            roles,
            policies: vec![],
            display_name: None,
            full_name: None,
            password_hash: "".to_string(),
            is_active: true,
            is_superuser: false,
            disabled: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn test_list_secrets_permissions() {
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let service = SecretService::new(storage.clone(), crypto.clone(), audit).await.unwrap();

        let user1_uuid = Uuid::new_v4();
        let user2_uuid = Uuid::new_v4();

        // Create secrets for user1
        let entry1 = SecretEntry::new(
            "app/user1/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user1_uuid,
        );
        storage.store(&entry1).await.unwrap();

        // Create secrets for user2
        let entry2 = SecretEntry::new(
            "app/user2/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user2_uuid,
        );
        storage.store(&entry2).await.unwrap();

        // Test user1 accessing list (should only see their own)
        let user1 = create_mock_user(&user1_uuid.to_string(), vec!["user".to_string()]);
        let secrets_user1 = service.list_secrets(None, &user1).await.unwrap();
        assert_eq!(secrets_user1.len(), 1);
        assert_eq!(secrets_user1[0].path, "app/user1/secret1");

        // Test user2 accessing list
        let user2 = create_mock_user(&user2_uuid.to_string(), vec!["user".to_string()]);
        let secrets_user2 = service.list_secrets(None, &user2).await.unwrap();
        assert_eq!(secrets_user2.len(), 1);
        assert_eq!(secrets_user2[0].path, "app/user2/secret1");

        // Test admin accessing list (should see all)
        let admin_uuid = Uuid::new_v4();
        let admin = create_mock_user(&admin_uuid.to_string(), vec!["admin".to_string()]);
        let secrets_admin = service.list_secrets(None, &admin).await.unwrap();

        // Note: MockStorageBackend might not support filtering or order strictly,
        // but if we list all, we should get 2.
        // Wait, other tests might have added entries to the static mock if it's shared?
        // No, MockStorageBackend::new() creates a new instance.
        assert_eq!(secrets_admin.len(), 2);
    }
}
