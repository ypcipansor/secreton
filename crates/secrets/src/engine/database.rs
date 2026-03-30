//! Database secret engine for dynamic credential generation

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Database type
#[derive(Debug, Clone, PartialEq)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MongoDB,
}

/// Database role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub sql: String,
    pub max_ttl: u64,
    pub default_ttl: u64,
}

/// Lease information for tracking active credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub lease_duration: u64,
}

/// Database secret engine for dynamic credentials
pub struct DatabaseEngine {
    config: DatabaseConfig,
    enabled: bool,
    roles: HashMap<String, DatabaseRole>,
    // Use Mutex for interior mutability since SecretEngine::read is &self
    leases: Mutex<HashMap<String, LeaseInfo>>,
    backend: Option<Box<dyn crate::backend::database::DatabaseBackend + Send + Sync>>,
    storage: Arc<dyn StorageBackend>,
    cipher: Option<Arc<dyn secreton_crypto::encryption::SymmetricCipher + Send + Sync>>,
    encryption_key: Option<Zeroizing<Vec<u8>>>,
}

impl DatabaseEngine {
    // Default configuration to use before initialization
    #[allow(dead_code)]
    fn default_config() -> DatabaseConfig {
        DatabaseConfig {
            plugin_name: "database".to_string(),
            connection_url: String::new(),
            allowed_roles: Vec::new(),
            username: None,
            password: None,
            max_open_connections: Some(10),
            max_idle_connections: Some(5),
            max_connection_lifetime: Some(30),
        }
    }

    pub fn new(config: DatabaseConfig, storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            config,
            enabled: false,
            roles: HashMap::new(),
            leases: Mutex::new(HashMap::new()),
            backend: None,
            storage,
            cipher: None,
            encryption_key: None,
        }
    }

    /// Add crypto provider. The key is wrapped in `Zeroizing` to ensure it is
    /// wiped from memory when the engine is dropped.
    pub fn with_crypto(
        mut self,
        cipher: Arc<dyn secreton_crypto::encryption::SymmetricCipher + Send + Sync>,
        key: Zeroizing<Vec<u8>>,
    ) -> Self {
        self.cipher = Some(cipher);
        self.encryption_key = Some(key);
        self
    }

    /// Encrypt data using the configured cipher, returning the ciphertext and metadata.
    /// Falls back to plaintext if no cipher is configured.
    fn encrypt_data(&self, data: &[u8]) -> SecretResult<(Vec<u8>, EncryptionMetadata)> {
        if let (Some(cipher), Some(key)) = (&self.cipher, &self.encryption_key) {
            let enc_result = cipher.encrypt(data, key)
                .map_err(|e| SecretError::EncryptionFailed(format!("Encryption failed: {:?}", e)))?;
            let algorithm_str = format!("{}", enc_result.algorithm);
            Ok((
                enc_result.ciphertext,
                EncryptionMetadata {
                    algorithm: algorithm_str,
                    key_id: "internal".to_string(),
                    iv: enc_result.nonce,
                    // Note: For AES-GCM and ChaCha20-Poly1305, the auth tag is appended
                    // to the ciphertext by the aes-gcm/chacha20poly1305 crates, so this
                    // is None. The decrypt() impl reads the tag from the ciphertext.
                    auth_tag: enc_result.tag,
                    ..Default::default()
                },
            ))
        } else {
            Ok((
                data.to_vec(),
                EncryptionMetadata {
                    algorithm: "plaintext".to_string(),
                    ..Default::default()
                },
            ))
        }
    }

    /// Decrypt a stored entry using the configured cipher.
    /// Returns the plaintext bytes, or the raw data if stored as plaintext.
    fn decrypt_entry(&self, entry: &SecretEntry) -> SecretResult<Vec<u8>> {
        if entry.encryption_metadata.algorithm != "plaintext" {
            if let (Some(cipher), Some(key)) = (&self.cipher, &self.encryption_key) {
                // Match algorithm by Display string, with fallback for legacy
                // serde_json-serialized values (e.g. "\"Aes256Gcm\"") and
                // Debug-formatted values.
                let algo_str = &entry.encryption_metadata.algorithm;
                let algorithm = match algo_str.as_str() {
                    "AES-256-GCM" | "aes-256-gcm" => secreton_crypto::AlgorithmId::Aes256Gcm,
                    "ChaCha20-Poly1305" => secreton_crypto::AlgorithmId::ChaCha20Poly1305,
                    other => {
                        // Backward compat: try serde deserialization, then specific substring matching
                        serde_json::from_str::<secreton_crypto::AlgorithmId>(other)
                            .or_else(|_| {
                                if other.contains("Aes256Gcm") || other.contains("aes-256-gcm") {
                                    Ok(secreton_crypto::AlgorithmId::Aes256Gcm)
                                } else if other.contains("ChaCha20") || other.contains("chacha20") {
                                    Ok(secreton_crypto::AlgorithmId::ChaCha20Poly1305)
                                } else {
                                    Err(())
                                }
                            })
                            .map_err(|_| SecretError::DecryptionFailed(
                                format!("Unknown encryption algorithm: '{}'", other)
                            ))?
                    }
                };
                let enc_data = secreton_crypto::encryption::EncryptedData {
                    algorithm,
                    nonce: entry.encryption_metadata.iv.clone(),
                    ciphertext: entry.encrypted_data.clone(),
                    // Note: For AES-GCM and ChaCha20-Poly1305, the auth tag is appended
                    // to the ciphertext by the aes-gcm/chacha20poly1305 crates, so this
                    // field is None. The decrypt() impl reads the tag from the ciphertext.
                    tag: entry.encryption_metadata.auth_tag.clone(),
                };
                cipher.decrypt(&enc_data, key)
                    .map_err(|e| SecretError::DecryptionFailed(format!("Decryption failed: {:?}", e)))
            } else {
                Err(SecretError::DecryptionFailed("No crypto provider configured to decrypt data".to_string()))
            }
        } else {
            Ok(entry.encrypted_data.clone())
        }
    }

    /// Checks backend connectivity.
    /// Returns an error if the backend fails the connection test, allowing
    /// callers (e.g. `init`) to roll back configuration changes.
    /// When no leases are present the check is skipped (no active credentials
    /// depend on the connection).
    pub async fn check_backend_connectivity(&self) -> SecretResult<()> {
        let lease_count = {
            let leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
            leases.len()
        };

        if lease_count == 0 {
            return Ok(());
        }

        if let Some(backend) = &self.backend {
            backend.test_connection().await.map_err(|e| {
                tracing::error!(
                    "Failed to connect to database backend: {}. {} leases may be stale or orphaned.",
                    e, lease_count
                );
                SecretError::BackendConnectionFailed(format!(
                    "Database connectivity check failed: {}", e
                ))
            })?;
            tracing::info!("Database backend connected successfully. {} leases are considered valid pending background TTL enforcement.", lease_count);
        } else {
            tracing::warn!("Database backend not initialized during lease validation. {} leases loaded without backend validation.", lease_count);
        }

        Ok(())
    }

    /// Load roles and leases from storage
    pub async fn load_state(&mut self) -> SecretResult<()> {
        // Load roles
        let roles_path = "sys/database/roles/";
        let params = secreton_storage::QueryParams::new().with_path_prefix(roles_path.to_string());
        let entries = self
            .storage
            .list(&params)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to list roles: {}", e)))?;

        for entry in entries {
            let role_name = entry
                .path
                .strip_prefix(roles_path)
                .unwrap_or(&entry.path)
                .to_string();

            let data = self.decrypt_entry(&entry)?;

            let role: DatabaseRole = serde_json::from_slice(&data)
                .map_err(|e| SecretError::InvalidSecretData(format!("Failed to deserialize role: {}", e)))?;

            self.roles.insert(role_name, role);
        }

        // Load leases
        let leases_path = "sys/database/leases/";
        let params = secreton_storage::QueryParams::new().with_path_prefix(leases_path.to_string());
        let entries = self
            .storage
            .list(&params)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to list leases: {}", e)))?;

        let mut leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
        for entry in entries {
            let lease_id = entry
                .path
                .strip_prefix(leases_path)
                .unwrap_or(&entry.path)
                .to_string();

            let data = self.decrypt_entry(&entry)?;

            let lease: LeaseInfo = serde_json::from_slice(&data)
                .map_err(|e| SecretError::InvalidSecretData(format!("Failed to deserialize lease: {}", e)))?;

            leases.insert(lease_id, lease);
        }

        Ok(())
    }

    async fn save_role(&self, name: &str, role: &DatabaseRole) -> SecretResult<()> {
        let path = format!("sys/database/roles/{}", name);
        let data = serde_json::to_vec(role)
            .map_err(|e| SecretError::InvalidSecretData(format!("Serialization error: {}", e)))?;

        let (encrypted_data, encryption_metadata) = self.encrypt_data(&data)?;

        // Create SecretEntry
        let entry = SecretEntry::new(
            path.clone(),
            encrypted_data,
            encryption_metadata,
            SecurityLevel::Confidential,
            uuid::Uuid::nil(), // System owned
        );

        // Delete any existing entry first to ensure idempotent upsert
        let _ = self.storage.delete_by_path(&path).await;

        self.storage
            .store(&entry)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to store role: {}", e)))
    }

    async fn delete_role_storage(&self, name: &str) -> SecretResult<()> {
        let path = format!("sys/database/roles/{}", name);
        self.storage
            .delete_by_path(&path)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to delete role: {}", e)))?;
        Ok(())
    }

    async fn save_lease(&self, id: &str, lease: &LeaseInfo) -> SecretResult<()> {
        let path = format!("sys/database/leases/{}", id);
        let data = serde_json::to_vec(lease)
            .map_err(|e| SecretError::InvalidSecretData(format!("Serialization error: {}", e)))?;

        // NOTE: LeaseInfo contains metadata (username, role, lease_id) but NOT the actual password.
        // The password is returned to the client and not stored here.
        let (encrypted_data, encryption_metadata) = self.encrypt_data(&data)?;
        let entry = SecretEntry::new(
            path.clone(),
            encrypted_data,
            encryption_metadata,
            SecurityLevel::Confidential,
            uuid::Uuid::nil(),
        );

        // Delete any existing entry first to ensure idempotent upsert
        let _ = self.storage.delete_by_path(&path).await;

        self.storage
            .store(&entry)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to store lease: {}", e)))
    }

    async fn delete_lease_storage(&self, id: &str) -> SecretResult<()> {
        let path = format!("sys/database/leases/{}", id);
        self.storage
            .delete_by_path(&path)
            .await
            .map_err(|e| SecretError::BackendOperationFailed(format!("Failed to delete lease: {}", e)))?;
        Ok(())
    }

    /// Generate database credentials
    async fn generate_credentials(&self, role_name: &str) -> SecretResult<HashMap<String, Value>> {
        // Enforce allowed_roles if configured
        if !self.config.allowed_roles.is_empty() {
            if !self.config.allowed_roles.contains(&role_name.to_string()) {
                return Err(SecretError::InvalidConfiguration(format!(
                    "Role '{}' is not in the allowed_roles list",
                    role_name
                )));
            }
        }

        // Get role configuration
        let role = self.roles.get(role_name).ok_or_else(|| {
            SecretError::InvalidConfiguration(format!("Role '{}' not found", role_name))
        })?;

        if let Some(backend) = &self.backend {
            backend.generate_credentials(role_name, &role.sql).await
        } else {
            Err(SecretError::InvalidConfiguration("Database backend not initialized".to_string()))
        }
    }

    /// Detect database type from connection URL
    fn detect_database_type(&self, connection_url: &str) -> SecretResult<DatabaseType> {
        if connection_url.starts_with("postgresql://") || connection_url.starts_with("postgres://")
        {
            Ok(DatabaseType::PostgreSQL)
        } else if connection_url.starts_with("mysql://") {
            Ok(DatabaseType::MySQL)
        } else if connection_url.starts_with("mongodb://") {
            Ok(DatabaseType::MongoDB)
        } else {
            // Extract only the scheme from the URL to avoid leaking credentials
            // that may be embedded in the connection string.
            let scheme = match connection_url.find("://") {
                Some(pos) => &connection_url[..pos],
                None => "<unknown>",
            };
            Err(SecretError::InvalidConfiguration(format!(
                "Unsupported database type for scheme: {}://",
                scheme
            )))
        }
    }

    /// Initialize the backend based on configuration
    /// This is now synchronous to allow lazy initialization in enable()
    fn init_backend(&mut self) -> SecretResult<()> {
        let db_type = self.detect_database_type(&self.config.connection_url)?;

        match db_type {
            DatabaseType::PostgreSQL => {
                let backend = crate::backend::database::postgres::PostgresBackend::new(
                    self.config.clone(),
                )?;
                self.backend = Some(Box::new(backend));
                Ok(())
            }
            DatabaseType::MySQL => {
                let backend = crate::backend::database::mysql::MysqlBackend::new(
                    self.config.clone(),
                )?;
                self.backend = Some(Box::new(backend));
                Ok(())
            }
            DatabaseType::MongoDB => {
                Err(SecretError::NotImplemented("MongoDB backend not fully implemented".to_string()))
            }
        }
    }

    /// Collect lease IDs that have exceeded their TTL.
    /// This only acquires the mutex briefly to snapshot expired IDs.
    pub fn collect_expired_lease_ids(&self) -> SecretResult<Vec<String>> {
        if !self.enabled || self.backend.is_none() {
            return Ok(vec![]);
        }

        let leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
        let now = chrono::Utc::now();

        Ok(leases.iter().filter_map(|(id, info)| {
            if let Ok(created_at) = chrono::DateTime::parse_from_rfc3339(&info.created_at) {
                // Safely convert u64 lease_duration to i64; treat overflow as
                // non-expiring (the lease will never be considered expired).
                match i64::try_from(info.lease_duration) {
                    Ok(secs) => {
                        let expiration = created_at + chrono::TimeDelta::seconds(secs);
                        if now > expiration {
                            Some(id.clone())
                        } else {
                            None
                        }
                    }
                    Err(_) => {
                        tracing::warn!(
                            "Lease {} has an unreasonably large lease_duration ({}). Skipping expiration check.",
                            id, info.lease_duration
                        );
                        None
                    }
                }
            } else {
                tracing::warn!("Failed to parse lease creation time for {}. Assuming expired for safety.", id);
                Some(id.clone())
            }
        }).collect())
    }

    /// Revoke a lease
    pub async fn revoke_lease(&self, lease_id: &str) -> SecretResult<()> {
        // Need to find username first
        let username = {
            let leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
            leases.get(lease_id).map(|l| l.username.clone())
        };

        if let Some(username) = username {
            if let Some(backend) = &self.backend {
                // Call backend to revoke (DROP USER)
                backend.revoke_credentials(&username).await?;

                // Delete from storage
                self.delete_lease_storage(lease_id).await?;

                // Remove from map
                let mut leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
                leases.remove(lease_id);
                Ok(())
            } else {
                Err(SecretError::InvalidConfiguration("Backend not initialized".to_string()))
            }
        } else {
            Err(SecretError::SecretNotFound(format!("Lease '{}' not found", lease_id)))
        }
    }

    /// List active leases
    pub fn list_leases(&self) -> Vec<LeaseInfo> {
        match self.leases.lock() {
            Ok(leases) => leases.values().cloned().collect(),
            Err(_) => vec![],
        }
    }
}

#[async_trait]
impl SecretEngine for DatabaseEngine {
    fn engine_type(&self) -> EngineType {
        EngineType::Database
    }

    async fn init(&mut self, config: &EngineConfig) -> SecretResult<()> {
        let db_config_value = config.config.get("database");

        if config.enabled && db_config_value.is_none() {
            return Err(SecretError::InvalidConfiguration(
                "Database configuration missing for enabled engine".to_string()
            ));
        }

        if let Some(db_config) = db_config_value {
             match serde_json::from_value::<DatabaseConfig>(db_config.clone()) {
                 Ok(cfg) => {
                     // Validate connection URL before mutating state to avoid
                     // leaving the engine in a partially-updated state on error.
                     self.detect_database_type(&cfg.connection_url)?;

                     let old_config = std::mem::replace(&mut self.config, cfg);

                     // Initialize backend only if enabled to avoid wasteful resource allocation
                     if config.enabled {
                         let old_backend = self.backend.take();
                         if let Err(e) = self.init_backend() {
                             // Rollback on failure
                             self.config = old_config;
                             self.backend = old_backend;
                             return Err(e);
                         }
                         if let Err(e) = self.check_backend_connectivity().await {
                             // Rollback on failure
                             self.config = old_config;
                             self.backend = old_backend;
                             return Err(e);
                         }
                     }
                 },
                 Err(e) => return Err(SecretError::InvalidConfiguration(format!("Invalid database configuration: {}", e)))
             }
        }

        self.enabled = config.enabled;
        Ok(())
    }

    async fn read(&self, path: &str) -> SecretResult<Option<Secret>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        // Database engine generates credentials on demand
        // Reading a role generates new credentials
        if let Some(role_name) = path.strip_prefix("creds/") {
            let data = self.generate_credentials(role_name).await?;

            // Generate Lease ID
            let lease_id = uuid::Uuid::new_v4().to_string();

            // Extract username for tracking
            let username = data.get("username")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            // Determine lease duration from role config
            let lease_duration = self.roles.get(role_name)
                .map(|r| r.default_ttl)
                .unwrap_or(3600); // Default to 1 hour if role config missing

            // Store Lease Info
            let lease_info = LeaseInfo {
                lease_id: lease_id.clone(),
                username: username.clone(),
                role: role_name.to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                lease_duration,
            };

            // Persist lease first
            if let Err(e) = self.save_lease(&lease_id, &lease_info).await {
                 // Revoke credentials if persistence fails
                 if let Some(backend) = &self.backend {
                     let _ = backend.revoke_credentials(&username).await;
                 }
                 return Err(e);
            }

            // Update memory
            // We need to drop the lock guard before awaiting on delete_lease_storage to ensure Send + Sync
            let lock_failed = {
                let lock_result = self.leases.lock();
                match lock_result {
                    Ok(mut leases) => {
                        leases.insert(lease_id.clone(), lease_info);
                        false
                    }
                    Err(_) => true,
                }
            };

            if lock_failed {
                // Critical failure: Mutex is poisoned.
                // Attempt rollback
                self.delete_lease_storage(&lease_id).await.ok();
                if let Some(backend) = &self.backend {
                    let _ = backend.revoke_credentials(&username).await;
                }
                return Err(SecretError::BackendOperationFailed("Failed to lock leases registry (poisoned). Credentials revoked.".to_string()));
            }

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data,
                metadata: SecretMetadata {
                    version: 1,
                    created_by: "system".to_string(),
                    updated_by: "system".to_string(),
                    lease_id: Some(lease_id),
                    lease_duration: Some(lease_duration),
                    tags: HashMap::new(),
                },
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    async fn write(&mut self, path: &str, data: HashMap<String, Value>) -> SecretResult<Secret> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        // Handle role creation
        if let Some(role_name) = path.strip_prefix("roles/") {
            // Enforce allowed_roles if configured
            if !self.config.allowed_roles.is_empty() {
                if !self.config.allowed_roles.contains(&role_name.to_string()) {
                    return Err(SecretError::InvalidConfiguration(format!(
                        "Role '{}' is not in the allowed_roles list",
                        role_name
                    )));
                }
            }

            let sql = data.get("sql").and_then(|v| v.as_str()).ok_or_else(|| {
                SecretError::InvalidConfiguration("Missing SQL for role".to_string())
            })?;

            let max_ttl = data
                .get("max_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(86400); // 24 hours default

            let default_ttl = data
                .get("default_ttl")
                .and_then(|v| v.as_u64())
                .unwrap_or(3600); // 1 hour default

            // Store role configuration
            let role = DatabaseRole {
                sql: sql.to_string(),
                max_ttl,
                default_ttl,
            };

            // Persist role
            self.save_role(role_name, &role).await?;

            // Store the role in memory
            self.roles.insert(role_name.to_string(), role);

            let secret = Secret {
                id: uuid::Uuid::new_v4(),
                path: path.to_string(),
                data: HashMap::new(), // Don't expose sensitive role data
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
            Err(SecretError::InvalidConfiguration(
                "Invalid database path".to_string(),
            ))
        }
    }

    async fn delete(&mut self, path: &str) -> SecretResult<()> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        if let Some(role_name) = path.strip_prefix("roles/") {
            self.delete_role_storage(role_name).await?;
            self.roles.remove(role_name);
            Ok(())
        } else if let Some(lease_id) = path.strip_prefix("leases/") {
            self.revoke_lease(lease_id).await
        } else {
            Err(SecretError::InvalidConfiguration(
                "Invalid database path".to_string(),
            ))
        }
    }

    async fn list(&self, path: &str) -> SecretResult<Vec<String>> {
        if !self.enabled {
            return Err(SecretError::EngineNotFound("database".to_string()));
        }

        if path == "roles" || path == "roles/" {
            // Return list of role names
            Ok(self.roles.keys().cloned().collect())
        } else if path == "leases" || path == "leases/" {
             // Return list of lease IDs
             Ok(self.list_leases().iter().map(|l| l.lease_id.clone()).collect())
        } else {
            Ok(vec![])
        }
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        // Lazily initialize backend if needed before enabling
        if self.backend.is_none() {
            if !self.config.connection_url.is_empty() {
                match self.init_backend() {
                    Ok(_) => self.enabled = true,
                    Err(e) => {
                        // Log error and keep enabled = false
                        tracing::error!("Failed to initialize database backend during enable: {}", e);
                        self.enabled = false;
                    }
                }
            } else {
                // No config, cannot enable
                self.enabled = false;
            }
        } else {
            // Backend already initialized
            self.enabled = true;
        }
    }

    fn disable(&mut self) {
        self.enabled = false;
        // Optionally release backend resources?
        // self.backend = None;
        // Keeping it might be better for re-enable performance, but dropping it saves resources.
        // Given the Bug 1 concern about "wasteful resource allocation", dropping it makes sense?
        // But pooling libraries handle idle connections well.
        // Let's keep it to avoid thrashing if toggled often.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::database::DatabaseBackend;

    struct MockBackend;

    #[async_trait]
    impl DatabaseBackend for MockBackend {
        async fn generate_credentials(
            &self,
            _role_name: &str,
            _role_sql: &str,
        ) -> SecretResult<HashMap<String, Value>> {
            let mut data = HashMap::new();
            data.insert("username".to_string(), Value::String("test_user".to_string()));
            data.insert("password".to_string(), Value::String("test_pass".to_string()));
            Ok(data)
        }

        async fn test_connection(&self) -> SecretResult<()> {
            Ok(())
        }

        async fn revoke_credentials(&self, username: &str) -> SecretResult<()> {
            if username == "test_user" {
                Ok(())
            } else {
                Err(SecretError::SecretNotFound("User not found".to_string()))
            }
        }
    }

    fn test_config() -> DatabaseConfig {
        DatabaseConfig {
            connection_url: "postgresql://localhost:5432/db".to_string(),
            plugin_name: "test".to_string(),
            allowed_roles: vec![],
            username: None,
            password: None,
            max_open_connections: None,
            max_idle_connections: None,
            max_connection_lifetime: None,
        }
    }

    #[tokio::test]
    async fn test_lease_lifecycle() -> SecretResult<()> {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);

        // Inject mock backend
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        // Create a role
        let mut role_data = HashMap::new();
        role_data.insert("sql".to_string(), Value::String("CREATE ROLE".to_string()));
        role_data.insert("default_ttl".to_string(), Value::Number(serde_json::Number::from(7200)));
        engine.write("roles/test_role", role_data).await?;

        // Generate credentials (creates lease)
        let secret = engine.read("creds/test_role").await?.unwrap();
        let lease_id = secret.metadata.lease_id.unwrap();

        // Verify lease exists
        let leases = engine.list_leases();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].lease_id, lease_id);
        assert_eq!(leases[0].username, "test_user");
        assert_eq!(leases[0].role, "test_role");
        assert_eq!(leases[0].lease_duration, 7200);

        // Verify secret metadata lease duration
        assert_eq!(secret.metadata.lease_duration, Some(7200));

        // Revoke lease
        engine.revoke_lease(&lease_id).await?;

        // Verify lease removed
        let leases = engine.list_leases();
        assert_eq!(leases.len(), 0);

        Ok(())
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip_with_aes256gcm() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let cipher = Arc::new(secreton_crypto::encryption::Aes256GcmCipher);
        let key = Zeroizing::new(vec![0xABu8; 32]);
        let engine = DatabaseEngine::new(test_config(), storage)
            .with_crypto(cipher, key);

        let plaintext = b"sensitive role data";
        let (ciphertext, metadata) = engine.encrypt_data(plaintext).unwrap();

        // Ciphertext must differ from plaintext
        assert_ne!(ciphertext, plaintext);
        assert_eq!(metadata.algorithm, "AES-256-GCM");
        assert_eq!(metadata.key_id, "internal");
        assert!(!metadata.iv.is_empty());

        // Build a SecretEntry to test decrypt_entry
        let entry = SecretEntry::new(
            "test/path".to_string(),
            ciphertext,
            metadata,
            SecurityLevel::Confidential,
            uuid::Uuid::nil(),
        );

        let decrypted = engine.decrypt_entry(&entry).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_data_plaintext_fallback_without_cipher() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let engine = DatabaseEngine::new(test_config(), storage);

        let plaintext = b"no encryption configured";
        let (data, metadata) = engine.encrypt_data(plaintext).unwrap();

        assert_eq!(data, plaintext);
        assert_eq!(metadata.algorithm, "plaintext");
    }

    #[test]
    fn test_decrypt_entry_plaintext_passthrough() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let engine = DatabaseEngine::new(test_config(), storage);

        let raw = b"raw plaintext bytes";
        let entry = SecretEntry::new(
            "test/path".to_string(),
            raw.to_vec(),
            EncryptionMetadata {
                algorithm: "plaintext".to_string(),
                ..Default::default()
            },
            SecurityLevel::Confidential,
            uuid::Uuid::nil(),
        );

        let result = engine.decrypt_entry(&entry).unwrap();
        assert_eq!(result, raw);
    }

    #[test]
    fn test_decrypt_entry_fails_without_cipher_for_encrypted_data() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        // Engine has no cipher configured
        let engine = DatabaseEngine::new(test_config(), storage);

        let entry = SecretEntry::new(
            "test/path".to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "AES-256-GCM".to_string(),
                key_id: "internal".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Confidential,
            uuid::Uuid::nil(),
        );

        let result = engine.decrypt_entry(&entry);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("No crypto provider configured"));
    }

    #[test]
    fn test_decrypt_entry_unknown_algorithm_fails() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let cipher = Arc::new(secreton_crypto::encryption::Aes256GcmCipher);
        let key = Zeroizing::new(vec![0xABu8; 32]);
        let engine = DatabaseEngine::new(test_config(), storage)
            .with_crypto(cipher, key);

        let entry = SecretEntry::new(
            "test/path".to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "unknown-cipher-xyz".to_string(),
                key_id: "internal".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Confidential,
            uuid::Uuid::nil(),
        );

        let result = engine.decrypt_entry(&entry);
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("Unknown encryption algorithm"));
    }

    #[test]
    fn test_collect_expired_lease_ids_returns_expired() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        // Insert an already-expired lease (created 2 hours ago, duration 1 second)
        let expired_lease = LeaseInfo {
            lease_id: "expired-1".to_string(),
            username: "user1".to_string(),
            role: "role1".to_string(),
            created_at: (chrono::Utc::now() - chrono::TimeDelta::seconds(7200)).to_rfc3339(),
            lease_duration: 1,
        };

        // Insert a still-valid lease (created now, duration 1 hour)
        let valid_lease = LeaseInfo {
            lease_id: "valid-1".to_string(),
            username: "user2".to_string(),
            role: "role1".to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
            lease_duration: 3600,
        };

        {
            let mut leases = engine.leases.lock().unwrap();
            leases.insert("expired-1".to_string(), expired_lease);
            leases.insert("valid-1".to_string(), valid_lease);
        }

        let expired_ids = engine.collect_expired_lease_ids().unwrap();
        assert_eq!(expired_ids.len(), 1);
        assert_eq!(expired_ids[0], "expired-1");
    }

    #[test]
    fn test_collect_expired_lease_ids_empty_when_disabled() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let engine = DatabaseEngine::new(test_config(), storage);
        // Engine is disabled by default

        let expired_ids = engine.collect_expired_lease_ids().unwrap();
        assert!(expired_ids.is_empty());
    }

    #[test]
    fn test_collect_expired_lease_ids_treats_unparseable_as_expired() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        let bad_lease = LeaseInfo {
            lease_id: "bad-date".to_string(),
            username: "user1".to_string(),
            role: "role1".to_string(),
            created_at: "not-a-date".to_string(),
            lease_duration: 3600,
        };

        {
            let mut leases = engine.leases.lock().unwrap();
            leases.insert("bad-date".to_string(), bad_lease);
        }

        let expired_ids = engine.collect_expired_lease_ids().unwrap();
        assert_eq!(expired_ids.len(), 1);
        assert_eq!(expired_ids[0], "bad-date");
    }

    #[tokio::test]
    async fn test_encrypted_role_persistence_roundtrip() -> SecretResult<()> {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let cipher = Arc::new(secreton_crypto::encryption::Aes256GcmCipher);
        let key = Zeroizing::new(vec![0xCDu8; 32]);
        let mut engine = DatabaseEngine::new(test_config(), storage.clone())
            .with_crypto(cipher.clone(), key.clone());

        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        // Write a role (this encrypts and persists)
        let mut role_data = HashMap::new();
        role_data.insert("sql".to_string(), Value::String("CREATE ROLE".to_string()));
        role_data.insert("default_ttl".to_string(), Value::Number(serde_json::Number::from(900)));
        engine.write("roles/encrypted_role", role_data).await?;

        // Create a fresh engine with the same key and load state
        let mut engine2 = DatabaseEngine::new(test_config(), storage)
            .with_crypto(cipher, key);
        engine2.load_state().await?;

        // Verify the role was loaded correctly
        assert!(engine2.roles.contains_key("encrypted_role"));
        let loaded_role = engine2.roles.get("encrypted_role").unwrap();
        assert_eq!(loaded_role.sql, "CREATE ROLE");
        assert_eq!(loaded_role.default_ttl, 900);

        Ok(())
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_lease_returns_not_found() {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        let result = engine.revoke_lease("nonexistent-lease-id").await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(err_msg.contains("not found"));
    }

    #[tokio::test]
    async fn test_check_backend_connectivity_ok_with_no_leases() -> SecretResult<()> {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        // No leases → should return Ok immediately
        engine.check_backend_connectivity().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_check_backend_connectivity_ok_with_leases() -> SecretResult<()> {
        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(test_config(), storage);
        engine.backend = Some(Box::new(MockBackend));
        engine.enabled = true;

        // Add a lease so the connectivity check actually runs
        {
            let mut leases = engine.leases.lock().unwrap();
            leases.insert("lease-1".to_string(), LeaseInfo {
                lease_id: "lease-1".to_string(),
                username: "user1".to_string(),
                role: "role1".to_string(),
                created_at: chrono::Utc::now().to_rfc3339(),
                lease_duration: 3600,
            });
        }

        engine.check_backend_connectivity().await?;
        Ok(())
    }
}
