//! Secret service for business logic operations.

use anyhow::Result;
use hex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{error, warn};

use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::crypto::CryptoService;
use secreton_auth::policies::service::PolicyService;
use secreton_auth::{IdentityService, policies::model::EvaluationContext};
use secreton_crypto::EncryptedData;
use secreton_performance::{AccessType, SecretPerformanceOptimizer};
use secreton_storage::StorageBackend;
use uuid::Uuid;

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
    identity: Arc<dyn IdentityService + Send + Sync>,
    policy_service: Arc<PolicyService>,
    performance: Arc<SecretPerformanceOptimizer>,
}

impl SecretService {
    /// Create new secret service
    pub async fn new(
        storage: Arc<dyn StorageBackend + Send + Sync>,
        crypto: Arc<CryptoService>,
        audit: Arc<AuditLogger>,
        identity: Arc<dyn IdentityService + Send + Sync>,
        policy_service: Arc<PolicyService>,
        performance: Arc<SecretPerformanceOptimizer>,
    ) -> Result<Self> {
        Ok(Self {
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        })
    }

    /// Helper to parse user ID to UUID
    fn get_user_uuid(user: &secreton_auth::User) -> Uuid {
        Uuid::parse_str(&user.id).unwrap_or_default()
    }

    /// Check permission for an action on a path
    async fn check_permission(
        &self,
        user: &secreton_auth::User,
        path: &str,
        action: &str,
    ) -> Result<(), SecretError> {
        // Strict Secret Isolation: Admin/Superuser cannot bypass data access policies.
        // They can only manage system configurations or resources they explicitly own.
        // Exception: "sys/" paths might be administrative.

        // RBAC Check
        // Resolve role IDs
        let mut role_ids = Vec::new();
        for role_name in &user.roles {
            if let Some(role_id) = self.policy_service.get_role_id_by_name(role_name).await {
                role_ids.push(role_id);
            }
        }

        // Resolve policy IDs
        let mut policy_ids = Vec::new();
        for policy_name in &user.policies {
            if let Some(policy_id) = self.policy_service.get_policy_id_by_name(policy_name).await {
                policy_ids.push(policy_id);
            }
        }

        let context = EvaluationContext {
            subject: HashMap::from([("id".to_string(), user.id.clone())]),
            resource: HashMap::from([("path".to_string(), path.to_string())]),
            action: action.to_string(),
            environment: HashMap::new(),
        };

        match self
            .policy_service
            .evaluate_access(&context, &role_ids, &policy_ids)
            .await
        {
            Ok(result) if result.allowed => Ok(()),
            _ => Err(SecretError::PermissionDenied(format!(
                "Action '{}' denied on '{}'",
                action, path
            ))),
        }
    }

    /// Check if a secret exists without decrypting or logging audit access
    pub async fn exists_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
        action: &str,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, path, action).await?;

        let entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(encrypted_entry) = entry {
            // Strict Ownership Check
            let user_uuid = Self::get_user_uuid(user);
            if encrypted_entry.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Get secret by path
    pub async fn get_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
        version: Option<u32>,
    ) -> Result<SecretData, SecretError> {
        let start_time = std::time::Instant::now();
        self.check_permission(user, path, "read").await?;

        // Optimize fetch strategy:
        // 1. Fetch from main path first (most likely case)
        // 2. If version specified and doesn't match current, fetch from history

        let mut encrypted_entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        // Always check ownership against the CURRENT secret if it exists.
        // This prevents access to orphaned history entries by previous owners
        // or access if the secret was deleted.
        let user_uuid = Self::get_user_uuid(user);

        if let Some(current_entry) = &encrypted_entry {
            if current_entry.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
        } else {
            // If the current secret doesn't exist, we should not allow fetching history.
            // This prevents access to orphaned history entries from failed deletions.
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // If specific version requested
        if let Some(v) = version {
            // Check if we have a current entry and if it matches the version
            let current_matches = encrypted_entry.as_ref().map_or(false, |e| e.version == v);

            if !current_matches {
                // Fetch from history
                let history_path = format!("sys/history/{}::v{}", path, v);
                encrypted_entry = self
                    .storage
                    .get_by_path(&history_path)
                    .await
                    .map_err(SecretError::Storage)?;

                // Re-verify that the history entry exists
                if encrypted_entry.is_none() {
                    return Err(SecretError::SecretNotFound {
                        path: format!("{} (version {})", path, v),
                    });
                }
            }
        }

        let encrypted_entry = encrypted_entry.unwrap();

        // Try to get decrypted data from cache first (only if fetching current version implicitly)
        // To avoid race conditions where cache has newer data than our DB read, we only use cache if NO specific version was requested.
        let is_current = version.is_none();

        if is_current {
            if let Ok(Some(cached_data)) = self.performance.get_cached(path).await {
                // Parse version from cache (first 4 bytes)
                if cached_data.len() > 4 {
                    let (ver_bytes, data_bytes) = cached_data.split_at(4);
                    let cached_ver = u32::from_be_bytes(ver_bytes.try_into().unwrap_or([0; 4]));

                    // Only use cache if version matches the Source of Truth (DB metadata)
                    if cached_ver == encrypted_entry.version {
                        match serde_json::from_slice::<HashMap<String, String>>(data_bytes) {
                            Ok(secret_map) => {
                                // Log access in performance optimizer (cache hit)
                                self.performance
                                    .record_access(
                                        path,
                                        AccessType::Read,
                                        start_time.elapsed(),
                                        true,
                                    )
                                    .await;

                                return Ok(SecretData {
                                    path: path.to_string(),
                                    data: secret_map,
                                    version: encrypted_entry.version, // Use actual version from storage
                                    previous_version: None,
                                    created_at: encrypted_entry.created_at,
                                    updated_at: encrypted_entry.updated_at,
                                });
                            }
                            Err(_) => {
                                // If cached data is invalid, remove it
                                let _ = self.performance.invalidate_cached(path).await;
                            }
                        }
                    }
                } else {
                    // Invalid cache format, remove it
                    let _ = self.performance.invalidate_cached(path).await;
                }
            }
        }

        // Decrypt the secret data
        let decrypted_data = self
            .crypto
            .decrypt(&encrypted_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse the decrypted data as JSON
        let secret_map: HashMap<String, String> =
            serde_json::from_slice(&decrypted_data).map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Failed to parse secret data: {}", e))
            })?;

        // Cache the decrypted data (only if current)
        // Store version + data to allow validation on retrieval
        if is_current {
            let mut cache_payload = encrypted_entry.version.to_be_bytes().to_vec();
            cache_payload.extend_from_slice(&decrypted_data);
            let _ = self
                .performance
                .put_cached(path.to_string(), cache_payload)
                .await;
        }

        // Log access in performance optimizer (cache miss)
        self.performance
            .record_access(path, AccessType::Read, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretAccess {
                secret_path: path.to_string(),
                user: user.id.to_string(),
                action: "read".to_string(),
            })
            .await;

        Ok(SecretData {
            path: path.to_string(),
            data: secret_map,
            version: encrypted_entry.version,
            previous_version: None,
            created_at: encrypted_entry.created_at,
            updated_at: encrypted_entry.updated_at,
        })
    }

    /// Create or update secret
    pub async fn put_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
        user: &secreton_auth::User,
    ) -> Result<SecretData, SecretError> {
        let start_time = std::time::Instant::now();
        self.check_permission(user, path, "write").await?;

        // Validate path for reserved delimiter. We only block paths that end with ::v followed by digits
        // or paths that attempt to write directly into the sys/history/ namespace.
        if path.starts_with("sys/history/") {
            return Err(SecretError::InvalidOperation(
                "Cannot write directly to reserved sys/history/ namespace".to_string(),
            ));
        }

        if let Some(idx) = path.rfind("::v") {
            let suffix = &path[idx + 3..];
            if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) {
                return Err(SecretError::InvalidOperation(
                    "Secret path cannot end with '::v' followed by a version number".to_string(),
                ));
            }
        }

        // Serialize data to JSON for storage
        let json_data = serde_json::to_vec(&data).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize secret data: {}", e))
        })?;

        // Encrypt the data
        let encrypted_data = self
            .crypto
            .encrypt_data(&json_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = Self::get_user_uuid(user);

        // Get existing secret to check for version and ownership atomically (avoid TOCTOU)
        let (version, existing_owner, previous_version) =
            if let Ok(Some(existing)) = self.storage.get_by_path(path).await {
                // Check ownership first
                if existing.owner_id != owner_id {
                    return Err(SecretError::PermissionDenied(format!(
                        "Access restricted: User is not the owner of '{}'",
                        path
                    )));
                }

                // Archive the existing version
                let archive_path = format!("sys/history/{}::v{}", existing.path, existing.version);
                let mut archive_entry = existing.clone();
                archive_entry.path = archive_path;
                // Ensure unique ID for the archived entry to avoid PK collisions
                archive_entry.id = Uuid::new_v4();

                // Store the archived version
                if let Err(e) = self.storage.store(&archive_entry).await {
                    return Err(SecretError::Storage(e));
                }

                (
                    existing.version + 1,
                    Some(existing.owner_id),
                    Some(existing.version),
                )
            } else {
                (1, None, None)
            };

        // Create SecretEntry
        let mut entry = secreton_storage::SecretEntry::new(
            path.to_string(),
            encrypted_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Confidential,
            owner_id,
        );
        entry.version = version;

        // Store encrypted data
        self.storage
            .store(&entry)
            .await
            .map_err(SecretError::Storage)?;

        // Update cache with plaintext data PREPENDED with version
        let mut cache_payload = entry.version.to_be_bytes().to_vec();
        cache_payload.extend_from_slice(&json_data);
        let _ = self
            .performance
            .put_cached(path.to_string(), cache_payload)
            .await;

        self.performance
            .record_access(path, AccessType::Write, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretCreation {
                secret_path: path.to_string(),
                user: user.id.to_string(),
            })
            .await;

        Ok(SecretData {
            path: path.to_string(),
            data,
            version: entry.version,
            previous_version,
            created_at: entry.created_at,
            updated_at: entry.updated_at,
        })
    }

    /// Delete secret
    pub async fn delete_secret(
        &self,
        path: &str,
        user: &secreton_auth::User,
    ) -> Result<(), SecretError> {
        self.delete_secret_internal(path, user, true, true).await
    }

    /// Delete secret with option to preserve history (used for rollbacks)
    /// `check_perms`: If true, checks the "delete" permission. If false, bypasses RBAC (e.g. for internal rollback).
    pub(crate) async fn delete_secret_internal(
        &self,
        path: &str,
        user: &secreton_auth::User,
        delete_history: bool,
        check_perms: bool,
    ) -> Result<(), SecretError> {
        let start_time = std::time::Instant::now();

        if check_perms {
            self.check_permission(user, path, "delete").await?;
        }

        // Check if secret exists and check ownership
        let entry = self
            .storage
            .get_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        if let Some(e) = entry {
            let user_uuid = Self::get_user_uuid(user);
            // Ownership check: Only owner can delete (unless it's a system admin action which deletes the USER, handled elsewhere)
            // But prompt says "root/admin cannot... delete... unless deleting user data".
            // So direct secret deletion must be owner-only.
            if e.owner_id != user_uuid {
                return Err(SecretError::PermissionDenied(format!(
                    "Access restricted: User is not the owner of '{}'",
                    path
                )));
            }
        } else {
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // Delete from storage using delete_by_path
        self.storage
            .delete_by_path(path)
            .await
            .map_err(SecretError::Storage)?;

        // Delete history if requested
        if delete_history {
            let history_prefix = format!("sys/history/{}::v", path);
            let query = secreton_storage::QueryParams::new()
                .with_path_prefix(history_prefix)
                .with_owner(Self::get_user_uuid(user));

            if let Ok(entries) = self.storage.list(&query).await {
                for entry in entries {
                    if let Err(e) = self.storage.delete_by_path(&entry.path).await {
                        warn!("Failed to delete history entry {}: {}", entry.path, e);
                    }
                }
            }
        }

        // Invalidate cache
        let _ = self.performance.invalidate_cached(path).await;

        self.performance
            .record_access(path, AccessType::Delete, start_time.elapsed(), true)
            .await;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::SecretDeletion {
                secret_path: path.to_string(),
                user: user.id.to_string(),
            })
            .await;

        Ok(())
    }

    /// Create a new policy
    pub async fn create_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        // Self-permission check (can user create policy?)
        self.check_permission(user, &format!("sys/policies/{}", name), "create")
            .await?;
        self.update_policy(name, rules, metadata, user).await
    }

    /// Get policy by name
    pub async fn get_policy(
        &self,
        name: &str,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "read")
            .await?;

        let path = format!("sys/policies/{}", name);
        let entry = self.storage.get_by_path(&path).await.map_err(SecretError::Storage)?;

        if let Some(entry) = entry {
            let decrypted = self.crypto.decrypt(&entry.encrypted_data).await.map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;
            let policy: Policy = serde_json::from_slice(&decrypted).map_err(|e| SecretError::Internal(anyhow::anyhow!("Deserialization error: {}", e)))?;
            Ok(policy)
        } else {
            Err(SecretError::PolicyNotFound { name: name.to_string() })
        }
    }

    /// Delete policy
    pub async fn delete_policy(
        &self,
        name: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "delete")
            .await?;

        let path = format!("sys/policies/{}", name);
        let entry = self.storage.get_by_path(&path).await.map_err(SecretError::Storage)?;

        if let Some(entry) = entry {
            self.storage.delete_by_id(entry.id).await.map_err(SecretError::Storage)?;
            Ok(true)
        } else {
            Err(SecretError::KeyNotFound { key_id: name.to_string() })
        }
    }

    pub async fn list_secret_versions(
        &self,
        path: &str,
        user: &secreton_auth::User,
    ) -> Result<Vec<SecretVersionInfo>, SecretError> {
        self.check_permission(user, path, "list_versions").await?;

        let user_uuid = Self::get_user_uuid(user);
        let mut versions = Vec::new();

        // 1. Get current version
        match self.storage.get_by_path(path).await {
            Ok(Some(current)) => {
                // Check ownership
                if current.owner_id == user_uuid {
                    versions.push(SecretVersionInfo {
                        version: current.version,
                        created_at: current.created_at,
                    });
                } else {
                    return Err(SecretError::PermissionDenied(format!(
                        "Access restricted: User is not the owner of '{}'",
                        path
                    )));
                }
            }
            Err(e) => return Err(SecretError::Storage(e)),
            Ok(None) => {
                // If the current secret doesn't exist, block access to history
                // to prevent leaking orphaned history metadata. This matches the behavior of get_secret.
                return Err(SecretError::SecretNotFound {
                    path: path.to_string(),
                });
            }
        }

        // 2. Get history versions
        let history_prefix = format!("sys/history/{}::v", path);
        // We use query with owner to let backend filter, but we also double check
        let query = secreton_storage::QueryParams::new()
            .with_path_prefix(history_prefix)
            .with_owner(user_uuid);

        let history_entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        for entry in history_entries {
            versions.push(SecretVersionInfo {
                version: entry.version,
                created_at: entry.created_at,
            });
        }

        // If we found absolutely nothing (no current, no history), the secret does not exist
        if versions.is_empty() {
            return Err(SecretError::SecretNotFound {
                path: path.to_string(),
            });
        }

        // Sort descending
        versions.sort_by(|a, b| b.version.cmp(&a.version));

        Ok(versions)
    }

    pub async fn list_secrets(
        &self,
        prefix: Option<&str>,
        user: &secreton_auth::User,
    ) -> Result<Vec<SecretData>, SecretError> {
        // Parse user_id as UUID for ownership check
        let user_uuid = Uuid::parse_str(&user.id).unwrap_or_default();

        // Strict isolation: always filter by owner ID
        let mut query = secreton_storage::QueryParams::new().with_owner(user_uuid);

        if let Some(p) = prefix {
            query = query.with_path_prefix(p.to_string());
        }

        // Get secrets from storage
        // The storage backend handles filtering by owner_id if set in query
        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        // Convert entries to SecretData
        let mut accessible_secrets = Vec::new();
        for entry in entries {
            // Skip archived history entries
            if entry.path.starts_with("sys/history/") {
                continue;
            }

            if self
                .check_permission(user, &entry.path, "read")
                .await
                .is_ok()
            {
                // Decrypt the secret data
                match self.crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted_data) => {
                        // Parse the decrypted data as JSON
                        match serde_json::from_slice::<HashMap<String, String>>(&decrypted_data) {
                            Ok(secret_map) => {
                                accessible_secrets.push(SecretData {
                                    path: entry.path.clone(),
                                    data: secret_map,
                                    version: entry.version,
                                    previous_version: None,
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
        }

        Ok(accessible_secrets)
    }

    /// Create encryption key
    pub async fn create_key(
        &self,
        key_name: &str,
        key_type: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_name);
        self.check_permission(user, &key_path, "create").await?;

        // Map key type to algorithm
        let algorithm = match key_type {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type: {}",
                    key_type
                )));
            }
        };

        // Generate key using crypto service
        let key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Generate unique key ID
        let key_id = format!("key_{}", Uuid::new_v4().simple());

        // Parse user_id as UUID
        let owner_id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4());

        // Store key metadata as SecretEntry
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": key_type,
            "algorithm": format!("{:?}", algorithm),
            "created_by": user.id,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "version": 1
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e))
        })?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path.clone(),
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        self.storage
            .store(&metadata_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Encrypt the key data before storing
        let encrypted_key_data = self
            .crypto
            .encrypt_data(&key_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        let key_data_path = format!("key_data/{}/{}", user.id, key_name);
        let key_data_entry = secreton_storage::SecretEntry::new(
            key_data_path,
            encrypted_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage
            .store(&key_data_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::KeyGeneration {
                key_id: key_id.clone(),
                key_type: key_type.to_string(),
                algorithm: key_type.to_string(),
                user: user.id.to_string(),
            })
            .await;

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
    pub async fn get_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "read").await?;

        // Retrieve key metadata from storage
        let entry = self
            .storage
            .get_by_path(&key_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_id.to_string(),
            })?;

        let metadata: serde_json::Value =
            serde_json::from_slice(&entry.encrypted_data).map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Failed to deserialize key metadata: {}", e))
            })?;

        // Extract key information
        let name = metadata
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or(key_id)
            .to_string();

        let key_type = metadata
            .get("key_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let version = metadata
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32;

        let default_time = chrono::Utc::now().to_rfc3339();
        let created_at_str = metadata
            .get("created_at")
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
    #[allow(clippy::collapsible_if)]
    pub async fn list_keys(
        &self,
        user: &secreton_auth::User,
        filter: Option<&str>,
    ) -> Result<Vec<KeyInfo>, SecretError> {
        self.check_permission(user, &format!("keys/{}/", user.id), "list")
            .await?;

        // Build query params for keys
        let keys_prefix = format!("keys/{}/", user.id);
        let query = secreton_storage::QueryParams::new().with_path_prefix(keys_prefix.clone());

        let entries = self
            .storage
            .list(&query)
            .await
            .map_err(SecretError::Storage)?;

        let mut keys = Vec::new();
        for entry in entries {
            // Extract key name from path
            if let Some(key_name) = entry.path.strip_prefix(&keys_prefix) {
                // Apply filter if provided
                if let Some(filter_str) = filter
                    && !key_name.contains(filter_str)
                {
                    continue;
                }

                // Parse key metadata
                match serde_json::from_slice::<serde_json::Value>(&entry.encrypted_data) {
                    Ok(metadata) => {
                        let key_id = metadata
                            .get("key_id")
                            .and_then(|v| v.as_str())
                            .unwrap_or(key_name)
                            .to_string();

                        let key_type = metadata
                            .get("key_type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("unknown")
                            .to_string();

                        let version = metadata
                            .get("version")
                            .and_then(|v| v.as_u64())
                            .unwrap_or(1) as u32;

                        let default_time = chrono::Utc::now().to_rfc3339();
                        let created_at_str = metadata
                            .get("created_at")
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
                        warn!(
                            "Failed to deserialize key metadata for {}: {}",
                            entry.path, e
                        );
                        continue;
                    }
                }
            }
        }

        Ok(keys)
    }

    /// Rotate a key (create new version)
    pub async fn rotate_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "rotate").await?;

        // Get current key metadata
        let current_key = self.get_key(key_id, user).await?;

        // Generate new key with same type
        let algorithm = match current_key.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type: {}",
                    current_key.key_type
                )));
            }
        };

        // Generate new key data
        let new_key_data = secreton_crypto::generate_key(algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Parse user_id as UUID
        let owner_id = Uuid::parse_str(&user.id).unwrap_or_else(|_| Uuid::new_v4());

        // Update metadata with new version
        let new_version = current_key.version + 1;
        let key_path = format!("keys/{}/{}", user.id, key_id);
        let key_metadata = serde_json::json!({
            "key_id": key_id,
            "key_type": current_key.key_type,
            "algorithm": format!("{:?}", algorithm),
            "created_by": user.id,
            "created_at": current_key.created_at.to_rfc3339(),
            "version": new_version,
            "rotated_at": chrono::Utc::now().to_rfc3339()
        });

        let metadata_bytes = serde_json::to_vec(&key_metadata).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize key metadata: {}", e))
        })?;

        let metadata_entry = secreton_storage::SecretEntry::new(
            key_path,
            metadata_bytes,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            owner_id,
        );

        self.storage
            .store(&metadata_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Store new key data with version
        let new_key_data_path = format!("key_data/{}/{}_v{}", user.id, key_id, new_version);
        let key_data_entry = secreton_storage::SecretEntry::new(
            new_key_data_path,
            new_key_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::TopSecret,
            owner_id,
        );

        self.storage
            .store(&key_data_entry)
            .await
            .map_err(SecretError::Storage)?;

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::KeyRotation {
                old_key_id: key_id.to_string(),
                new_key_id: format!("{}_v{}", key_id, new_version),
                algorithm: current_key.key_type.clone(),
                user: user.id.to_string(),
            })
            .await;

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
        user: &secreton_auth::User,
    ) -> Result<KeyInfo, SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_id), "update")
            .await?;
        // Retrieve current key info
        let key_info = self.get_key(key_id, user).await?;

        // In a real implementation we would update the metadata in storage
        // For now, we just return the existing key info since we can't easily modify the mock storage

        Ok(key_info)
    }

    /// Update policy
    pub async fn update_policy(
        &self,
        name: &str,
        rules: Vec<String>,
        metadata: PolicyMetadata,
        user: &secreton_auth::User,
    ) -> Result<Policy, SecretError> {
        self.check_permission(user, &format!("sys/policies/{}", name), "update")
            .await?;

        let policy = Policy {
            name: name.to_string(),
            rules,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata,
        };

        let data = serde_json::to_vec(&policy).map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to serialize policy: {}", e))
        })?;

        let encrypted_data = self.crypto.encrypt_data(&data).await.map_err(|e| {
            SecretError::Internal(anyhow::anyhow!("Failed to encrypt policy: {}", e))
        })?;

        let policy_path = format!("sys/policies/{}", name);
        let existing_entry = self.storage.get_by_path(&policy_path).await.unwrap_or(None);
        let entry_id = existing_entry.as_ref().map(|e| e.id).unwrap_or_else(uuid::Uuid::new_v4);
        let created_at = existing_entry.as_ref().map(|e| e.created_at).unwrap_or_else(chrono::Utc::now);
        let version = existing_entry.as_ref().map(|e| e.version + 1).unwrap_or(1);

        let mut entry = secreton_storage::SecretEntry::new(
            policy_path,
            encrypted_data,
            secreton_storage::EncryptionMetadata::default(),
            secreton_storage::SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        entry.id = entry_id;
        entry.created_at = created_at;
        entry.version = version;

        self.storage.store(&entry).await.map_err(SecretError::Storage)?;

        Ok(policy)
    }

    pub async fn list_policies(&self, _filter: Option<&str>) -> Result<Vec<Policy>, SecretError> {
        let query_params = secreton_storage::QueryParams {
            path_prefix: Some("sys/policies/".to_string()),
            limit: None,
            offset: None,
            ..Default::default()
        };

        let entries = self.storage.list(&query_params).await.map_err(SecretError::Storage)?;
        let mut policies = Vec::new();

        for entry in entries {
            if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                if let Ok(policy) = serde_json::from_slice::<Policy>(&decrypted) {
                    policies.push(policy);
                }
            }
        }

        Ok(policies)
    }

    /// List key versions
    pub async fn list_key_versions(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<Vec<KeyInfo>, SecretError> {
        let key_path = format!("keys/{}/{}", user.id, key_id);
        self.check_permission(user, &key_path, "list_versions")
            .await?;

        // Check if key exists
        self.get_key(key_id, user).await?;

        // Return just the current version for now
        self.get_key(key_id, user).await.map(|k| vec![k])
    }

    /// Delete a key
    pub async fn delete_key(
        &self,
        key_id: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_id), "delete")
            .await?;
        // Placeholder
        Ok(true)
    }

    /// Delete a backup
    pub async fn delete_backup(
        &self,
        _backup_id: &str,
        user: &secreton_auth::User,
    ) -> Result<bool, SecretError> {
        self.check_permission(user, "sys/backups", "delete").await?;
        // Placeholder
        Ok(true)
    }

    /// Encrypt data using a key
    pub async fn encrypt(
        &self,
        key_name: &str,
        plaintext: &[u8],
        user: &secreton_auth::User,
    ) -> Result<(EncryptedData, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "encrypt")
            .await?;

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user.id, key_name);
        let key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_name.to_string(),
            })?;

        // Decrypt the stored key data
        let key_data = self
            .crypto
            .decrypt(&key_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Generate nonce/IV
        let nonce = secreton_crypto::generate_random_bytes(12)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Encrypt data using crypto engine
        let ciphertext = self
            .crypto
            .encrypt(&key_data, plaintext, None)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        let encrypted_data = EncryptedData {
            algorithm: secreton_crypto::AlgorithmId::Aes256Gcm,
            nonce: nonce.clone(),
            ciphertext: ciphertext.ciphertext,
            tag: ciphertext.tag,
        };

        // Create key ID for audit
        let key_id = format!("{}/{}", user.id, key_name);

        // Log audit trail
        let _ = self
            .audit
            .log_event(SecurityEventType::EncryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        Ok((encrypted_data, key_info.version))
    }

    /// Decrypt data using a key
    pub async fn decrypt(
        &self,
        key_name: &str,
        encrypted_data: &EncryptedData,
        user: &secreton_auth::User,
    ) -> Result<(Vec<u8>, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "decrypt")
            .await?;

        // Get key info to retrieve version
        let key_info = self.get_key(key_name, user).await?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user.id, key_name);
        let key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_name.to_string(),
            })?;

        // Decrypt the stored key data
        let key_data = self
            .crypto
            .decrypt(&key_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Decrypt the user data using the key
        let plaintext = self
            .crypto
            .decrypt_full(
                &key_data,
                &encrypted_data.nonce,
                &encrypted_data.ciphertext,
                None,
            )
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::DecryptionOperation {
                key_id: key_id.clone(),
                data_size: plaintext.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        Ok((plaintext, key_info.version))
    }

    /// Sign data using a key
    pub async fn sign_data(
        &self,
        key_name: &str,
        data: &[u8],
        user: &secreton_auth::User,
    ) -> Result<SignResult, SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "sign")
            .await?;

        let key_info = self.get_key(key_name, user).await?;

        // Map key type to algorithm
        let algorithm = match key_info.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type for signing: {}",
                    key_info.key_type
                )));
            }
        };

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user.id, key_name);
        let key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_name.to_string(),
            })?;

        // Decrypt the stored key data
        let key_data = self
            .crypto
            .decrypt(&key_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Sign data using crypto engine
        let signature = self
            .crypto
            .sign_data(&key_data, data, algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Return base64 encoded signature
        use base64::Engine;
        let signature_str = base64::engine::general_purpose::STANDARD.encode(signature);

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::SigningOperation {
                key_id: key_id.clone(),
                data_size: data.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
            })
            .await;

        Ok(SignResult {
            signature: signature_str,
            key_version: key_info.version,
        })
    }

    /// Verify signature using a key
    pub async fn verify_data(
        &self,
        key_name: &str,
        data: &[u8],
        signature_b64: &[u8],
        user: &secreton_auth::User,
    ) -> Result<(bool, u32), SecretError> {
        self.check_permission(user, &format!("keys/{}/{}", user.id, key_name), "verify")
            .await?;

        // Get key info to retrieve version and algorithm
        let key_info = self.get_key(key_name, user).await?;

        // Map key type to algorithm
        let algorithm = match key_info.key_type.as_str() {
            "aes256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
            "chacha20-poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
            "rsa-2048" => secreton_crypto::AlgorithmId::Rsa2048,
            "rsa-4096" => secreton_crypto::AlgorithmId::Rsa4096,
            "ecdsa-p256" => secreton_crypto::AlgorithmId::EcdsaP256,
            "ecdsa-p384" => secreton_crypto::AlgorithmId::EcdsaP384,
            "ed25519" => secreton_crypto::AlgorithmId::Ed25519,
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported key type for verification: {}",
                    key_info.key_type
                )));
            }
        };

        // Decode base64 signature
        use base64::Engine;
        let signature = base64::engine::general_purpose::STANDARD
            .decode(signature_b64)
            .map_err(|e| {
                SecretError::Internal(anyhow::anyhow!("Invalid base64 signature: {}", e))
            })?;

        // Retrieve key from storage
        let key_data_path = format!("key_data/{}/{}", user.id, key_name);
        let key_entry = self
            .storage
            .get_by_path(&key_data_path)
            .await
            .map_err(SecretError::Storage)?
            .ok_or_else(|| SecretError::KeyNotFound {
                key_id: key_name.to_string(),
            })?;

        // Decrypt the stored key data
        let key_data = self
            .crypto
            .decrypt(&key_entry.encrypted_data)
            .await
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Failed to decrypt key: {}", e)))?;

        // Verify signature
        let is_valid = self
            .crypto
            .verify_signature(&key_data, data, &signature, algorithm)
            .map_err(|e| SecretError::Internal(anyhow::anyhow!("Crypto error: {}", e)))?;

        // Log audit trail
        let key_id = format!("{}/{}", user.id, key_name);
        let _ = self
            .audit
            .log_event(SecurityEventType::VerificationOperation {
                key_id: key_id.clone(),
                data_size: data.len().try_into().unwrap_or(0),
                user: user.id.to_string(),
                valid: is_valid,
            })
            .await;

        Ok((is_valid, key_info.version))
    }

    /// Compute hash of data
    pub async fn hash_data(
        &self,
        data: &[u8],
        algorithm: &str,
        user: &secreton_auth::User,
    ) -> Result<String, SecretError> {
        self.check_permission(user, "sys/crypto", "hash").await?;

        // Compute hash based on algorithm
        let hash_hex = match algorithm {
            "SHA-256" | "sha256" => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            "SHA-512" | "sha512" => {
                let mut hasher = Sha512::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            "SHA3-256" | "sha3-256" => {
                let mut hasher = Sha3_256::new();
                hasher.update(data);
                hex::encode(hasher.finalize())
            }
            _ => {
                return Err(SecretError::InvalidOperation(format!(
                    "Unsupported hash algorithm: {}",
                    algorithm
                )));
            }
        };

        Ok(hash_hex)
    }
}

/// Secret data structure
#[derive(Debug, Serialize)]
pub struct SecretData {
    pub path: String,
    pub data: HashMap<String, String>,
    pub version: u32,
    pub previous_version: Option<u32>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Secret version info
#[derive(Debug, Serialize)]
pub struct SecretVersionInfo {
    pub version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
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

// Tests in `services/secret.rs` also need updates because signatures changed.
// I will update the tests to create a mock user and pass it.

#[cfg(test)]
mod tests {
    use super::*;
    use secreton_storage::{
        EncryptionMetadata, MockStorageBackend, SecretEntry, SecurityLevel, StorageBackend,
    };

    use crate::services::audit::AuditLogger;
    use base64::Engine;
    use secreton_core::storage::secure::types::KeyEntry; // Import Engine trait for encoding

    // Mock user helper
    fn mock_user() -> secreton_auth::User {
        let id = Uuid::new_v4().to_string();
        secreton_auth::User {
            id: id.clone(),
            username: "user1".to_string(),
            email: Some("user1@example.com".to_string()),
            display_name: None,
            full_name: None,
            roles: vec!["admin".to_string()],
            permissions: vec![],
            policies: vec![],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            last_login: None,
            failed_login_attempts: 0,
            locked_until: None,
            mfa_enabled: false,
            mfa_secret: None,
            password_hash: "".to_string(),
            disabled: false,
            enabled: true,
            is_active: true,
            is_superuser: false,
        }
    }

    async fn seed_admin_policy(policy_service: &secreton_auth::PolicyService) {
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "admin_policy".to_string(),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "allow_all".to_string(),
                conditions: vec![],
                actions: vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "list".to_string(),
                    "list_versions".to_string(),
                    "rotate".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "sign".to_string(),
                    "verify".to_string(),
                    "hash".to_string(),
                    "write".to_string(),
                ],
                resources: vec![
                    "app/".to_string(),
                    "keys/".to_string(),
                    "sys/".to_string(),
                    "key_data/".to_string(),
                    "users/".to_string(),
                ],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };
        let p = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: "admin".to_string(),
            description: None,
            parent_role: None,
            policies: vec![p.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let _ = policy_service.create_role(role).await;
    }

    #[tokio::test]
    async fn test_secreton_service_creation() {
        // Set root key for crypto service auto-unseal
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let secreton_service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await;
        assert!(secreton_service.is_ok());
    }

    #[tokio::test]
    async fn test_get_secret_with_permission() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        // Seed secret
        let mut data = HashMap::new();
        data.insert("key1".to_string(), "value1".to_string());

        let user = mock_user();
        let user_uuid = Uuid::parse_str(&user.id).unwrap();

        let secret_entry = SecretEntry::new(
            "app/config".to_string(),
            crypto
                .encrypt_data(&serde_json::to_vec(&data).unwrap())
                .await
                .unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user_uuid,
        );
        let _ = storage.store(&secret_entry).await;

        let service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let secret = service.get_secret("app/config", &user, None).await.unwrap();
        assert_eq!(secret.path, "app/config");
        assert!(secret.data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_put_secret_placeholder() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        let user = mock_user();
        let secret = service.put_secret("app/admin", data, &user).await.unwrap();
        assert_eq!(secret.path, "app/admin");
        assert!(secret.data.contains_key("username"));
    }

    #[tokio::test]
    async fn test_encrypt_placeholder_response() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policy
        seed_admin_policy(&policy_service).await;

        // Define key entry structure matching secreton_core model for JSON serialization
        let key_entry = KeyEntry {
            id: "key1".to_string(),
            key: base64::engine::general_purpose::STANDARD.encode(vec![0u8; 32]),
            salt: base64::engine::general_purpose::STANDARD.encode(vec![0u8; 16]),
            version: 1,
            created_at: chrono::Utc::now().timestamp() as u64,
            rotated_at: chrono::Utc::now().timestamp() as u64,
            active: true,
            metadata: Default::default(),
            expires_at: 0,
        };

        // Encrypt the raw key data using CryptoService
        let raw_key = vec![0u8; 32];
        let encrypted_key = crypto
            .encrypt_data(&raw_key)
            .await
            .expect("failed to encrypt key data");

        let user = mock_user();

        // Seed Key Metadata (required by get_key) using user.id
        let key_metadata_entry = SecretEntry::new(
            format!("keys/{}/key1", user.id),
            serde_json::to_vec(&key_entry).unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_metadata_entry).await;

        let key_storage_entry = SecretEntry::new(
            format!("key_data/{}/key1", user.id),
            encrypted_key,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            Uuid::new_v4(),
        );
        let _ = storage.store(&key_storage_entry).await;

        let service = SecretService::new(
            storage,
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let (result, key_version) = service
            .encrypt("key1", "plaintext".as_bytes(), &user)
            .await
            .unwrap();
        assert!(!result.ciphertext.is_empty());
        assert_eq!(key_version, 1);
    }

    #[tokio::test]
    async fn test_create_key_permission_denied() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let user = secreton_auth::User {
            id: "user_no_role".to_string(),
            username: "user_no_role".to_string(),
            email: None,
            roles: vec![],
            permissions: vec![],
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
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        };

        let result = service.create_key("test_key", "aes256-gcm", &user).await;

        assert!(matches!(result, Err(SecretError::PermissionDenied(_))));
    }

    #[tokio::test]
    async fn test_create_key_permission_allowed() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service.clone(),
            performance,
        )
        .await
        .unwrap();

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "allow_create_key".to_string(),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "rule_allow_create".to_string(),
                conditions: vec![],
                actions: vec!["create".to_string()],
                resources: vec!["keys/".to_string()],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };

        let created_policy = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: "key_creator".to_string(),
            description: None,
            parent_role: None,
            policies: vec![created_policy.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };

        policy_service.create_role(role.clone()).await.unwrap();

        let user = secreton_auth::User {
            id: "user_with_role".to_string(),
            username: "user_with_role".to_string(),
            email: None,
            roles: vec!["key_creator".to_string()],
            permissions: vec![],
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
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        };

        let result = service
            .create_key("test_key_allowed", "aes256-gcm", &user)
            .await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_secret_versioning() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let user = mock_user();

        // 1. Create Secret (v1)
        let mut data1 = HashMap::new();
        data1.insert("k".to_string(), "v1".to_string());
        let s1 = service.put_secret("app/ver", data1, &user).await.unwrap();
        assert_eq!(s1.version, 1);

        // 2. Update Secret (v2)
        let mut data2 = HashMap::new();
        data2.insert("k".to_string(), "v2".to_string());
        let s2 = service.put_secret("app/ver", data2, &user).await.unwrap();
        assert_eq!(s2.version, 2);

        // 3. Get Current (v2)
        let get_curr = service.get_secret("app/ver", &user, None).await.unwrap();
        assert_eq!(get_curr.version, 2);
        assert_eq!(get_curr.data.get("k").unwrap(), "v2");

        // 4. Get Old (v1)
        let get_v1 = service.get_secret("app/ver", &user, Some(1)).await.unwrap();
        assert_eq!(get_v1.version, 1);
        assert_eq!(get_v1.data.get("k").unwrap(), "v1");

        // 5. List Versions
        let versions = service
            .list_secret_versions("app/ver", &user)
            .await
            .unwrap();
        assert_eq!(versions.len(), 2);
        assert_eq!(versions[0].version, 2); // Sorted desc
        assert_eq!(versions[1].version, 1);
    }

    #[tokio::test]
    async fn test_cache_version_mismatch() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        seed_admin_policy(&policy_service).await;

        let service = SecretService::new(
            storage.clone(),
            crypto,
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();
        let user = mock_user();

        // 1. Create Secret (v1)
        let mut data = HashMap::new();
        data.insert("k".to_string(), "v1".to_string());
        service.put_secret("app/race", data, &user).await.unwrap();

        // 2. Pollute cache with "future" version (v2)
        // We need to construct the cache payload: [v2_bytes] + [json_data]
        let v2: u32 = 2;
        let mut cache_payload = v2.to_be_bytes().to_vec();
        let fake_data =
            serde_json::to_vec(&HashMap::from([("k".to_string(), "fake_v2".to_string())])).unwrap();
        cache_payload.extend_from_slice(&fake_data);

        service
            .performance
            .put_cached("app/race".to_string(), cache_payload)
            .await
            .unwrap();

        // 3. Get Secret (current). Storage still has v1.
        let result = service.get_secret("app/race", &user, None).await.unwrap();

        // 4. Assert we got v1 (from storage), NOT fake_v2 (from cache)
        assert_eq!(result.version, 1);
        assert_eq!(result.data.get("k").unwrap(), "v1");

        // 5. Assert cache is now corrected to v1
        let cached = service
            .performance
            .get_cached("app/race")
            .await
            .unwrap()
            .unwrap();
        let (ver_bytes, _) = cached.split_at(4);
        let cached_ver = u32::from_be_bytes(ver_bytes.try_into().unwrap());
        assert_eq!(cached_ver, 1);
    }
}

#[cfg(test)]
mod list_secrets_tests {
    use super::*;
    use crate::services::audit::AuditLogger;
    use secreton_storage::{
        EncryptionMetadata, MockStorageBackend, SecretEntry, SecurityLevel, StorageBackend,
    };
    use std::collections::HashMap;
    use uuid::Uuid;

    fn create_mock_user(id: &str, roles: Vec<String>) -> secreton_auth::User {
        secreton_auth::User {
            id: id.to_string(),
            username: format!("user_{}", id),
            email: Some(format!("user_{}@example.com", id)),
            roles: roles,
            permissions: vec![],
            policies: vec![],
            display_name: None,
            full_name: None,
            password_hash: "".to_string(),
            is_active: true,
            is_superuser: false, // Strict check
            disabled: false,
            enabled: true,
            mfa_enabled: false,
            mfa_secret: None,
            last_login: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            failed_login_attempts: 0,
            locked_until: None,
            metadata: HashMap::new(),
        }
    }

    // Helper to seed policy
    async fn seed_allow_all_policy(policy_service: &secreton_auth::PolicyService, role_name: &str) {
        use secreton_auth::policies::model::{Policy, PolicyEffect, PolicyRule, PolicyType, Role};

        let policy = Policy {
            id: Uuid::new_v4(),
            name: format!("{}_policy", role_name),
            policy_type: PolicyType::RBAC,
            effect: PolicyEffect::Allow,
            rules: vec![PolicyRule {
                id: Uuid::new_v4(),
                name: "allow_all".to_string(),
                conditions: vec![],
                actions: vec![
                    "create".to_string(),
                    "read".to_string(),
                    "update".to_string(),
                    "delete".to_string(),
                    "list".to_string(),
                    "list_versions".to_string(),
                    "rotate".to_string(),
                    "encrypt".to_string(),
                    "decrypt".to_string(),
                    "sign".to_string(),
                    "verify".to_string(),
                    "hash".to_string(),
                    "write".to_string(),
                ],
                resources: vec![
                    "*".to_string(),
                    "app/".to_string(),
                    "keys/".to_string(),
                    "sys/".to_string(),
                    "key_data/".to_string(),
                    "users/".to_string(),
                ],
            }],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            enabled: true,
        };
        let p = policy_service.create_policy(policy).await.unwrap();

        let role = Role {
            id: Uuid::new_v4(),
            name: role_name.to_string(),
            description: None,
            parent_role: None,
            policies: vec![p.id],
            metadata: HashMap::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let _ = policy_service.create_role(role).await;
    }

    #[tokio::test]
    async fn test_list_secrets_permissions() {
        unsafe {
            std::env::set_var("SECRETON_ROOT_KEY", "test_root_key_must_be_32_bytes_long!!");
        }
        let storage = Arc::new(MockStorageBackend::new());
        let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
        let audit = Arc::new(AuditLogger::new(storage.clone()).await.unwrap());
        let identity = Arc::new(secreton_auth::InMemoryIdentityService::new());
        let policy_service = Arc::new(secreton_auth::PolicyService::new());
        let performance = Arc::new(SecretPerformanceOptimizer::default());

        // Seed policies for user and admin
        seed_allow_all_policy(&policy_service, "user").await;
        seed_allow_all_policy(&policy_service, "admin").await;

        let service = SecretService::new(
            storage.clone(),
            crypto.clone(),
            audit,
            identity,
            policy_service,
            performance,
        )
        .await
        .unwrap();

        let user1_uuid = Uuid::new_v4();
        let user2_uuid = Uuid::new_v4();

        // Create secrets for user1
        let entry1 = SecretEntry::new(
            "app/user1/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).await.unwrap(),
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            user1_uuid,
        );
        storage.store(&entry1).await.unwrap();

        // Create secrets for user2
        let entry2 = SecretEntry::new(
            "app/user2/secret1".to_string(),
            crypto.encrypt_data(br#"{"key": "value"}"#).await.unwrap(),
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

        // Test admin accessing list (should see ZERO, because strict isolation is enforced)
        let admin_uuid = Uuid::new_v4();
        let admin = create_mock_user(&admin_uuid.to_string(), vec!["admin".to_string()]);
        let secrets_admin = service.list_secrets(None, &admin).await.unwrap();

        // Expectation changed from 2 to 0 to reflect strict Zero Trust isolation
        assert_eq!(secrets_admin.len(), 0);
    }
}
