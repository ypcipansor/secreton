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
    // TODO: Implement background task for TTL enforcement to automatically revoke expired leases.
    // Currently, leases are only tracked for manual revocation.
    leases: Mutex<HashMap<String, LeaseInfo>>,
    backend: Option<Box<dyn crate::backend::database::DatabaseBackend + Send + Sync>>,
    storage: Arc<dyn StorageBackend>,
    cipher: Option<Arc<dyn secreton_crypto::encryption::SymmetricCipher + Send + Sync>>,
    encryption_key: Option<Vec<u8>>,
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

    /// Add crypto provider
    pub fn with_crypto(
        mut self,
        cipher: Arc<dyn secreton_crypto::encryption::SymmetricCipher + Send + Sync>,
        key: Vec<u8>,
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
            let algorithm_str = serde_json::to_string(&enc_result.algorithm)
                .unwrap_or_else(|_| format!("{:?}", enc_result.algorithm));
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
                // Try serde deserialization first (stable round-trip), then fall back
                // to substring matching for backward compatibility with Debug-formatted values.
                let algorithm = serde_json::from_str::<secreton_crypto::AlgorithmId>(
                    &entry.encryption_metadata.algorithm,
                ).unwrap_or_else(|_| {
                    if entry.encryption_metadata.algorithm.contains("Aes256Gcm") {
                        secreton_crypto::AlgorithmId::Aes256Gcm
                    } else if entry.encryption_metadata.algorithm.contains("ChaCha20Poly1305") {
                        secreton_crypto::AlgorithmId::ChaCha20Poly1305
                    } else {
                        secreton_crypto::AlgorithmId::Aes256Gcm
                    }
                });
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

    /// Validates loaded leases against the initialized database backend.
    pub async fn validate_leases(&self) -> SecretResult<()> {
        let lease_count = {
            let leases = self.leases.lock().map_err(|_| SecretError::BackendOperationFailed("Failed to lock leases".to_string()))?;
            leases.len()
        };

        if lease_count == 0 {
            return Ok(());
        }

        if let Some(backend) = &self.backend {
            if let Err(e) = backend.test_connection().await {
                tracing::warn!("Failed to connect to database backend during lease validation: {}. Loaded {} leases may be stale or orphaned.", e, lease_count);
            } else {
                tracing::info!("Database backend connected successfully. {} leases are considered valid pending background TTL enforcement.", lease_count);
            }
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

        // We currently store this metadata in plaintext (serialized JSON) within the storage backend.
        // If the storage backend supports encryption at rest, it will be encrypted there.
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
            Err(SecretError::InvalidConfiguration(format!(
                "Unsupported database type in URL: {}",
                connection_url
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
                let expiration = created_at + chrono::Duration::seconds(info.lease_duration as i64);
                if now > expiration {
                    Some(id.clone())
                } else {
                    None
                }
            } else {
                tracing::warn!("Failed to parse lease creation time for {}. Assuming expired for safety.", id);
                Some(id.clone())
            }
        }).collect())
    }

    /// Automatically revoke leases that have exceeded their TTL
    pub async fn revoke_expired_leases(&self) -> SecretResult<()> {
        let expired_lease_ids = self.collect_expired_lease_ids()?;

        let mut revoked_count = 0;
        for lease_id in &expired_lease_ids {
            match self.revoke_lease(lease_id).await {
                Ok(_) => {
                    tracing::info!("Successfully revoked expired lease {}", lease_id);
                    revoked_count += 1;
                }
                Err(e) => tracing::error!("Failed to revoke expired lease {}: {}", lease_id, e),
            }
        }

        if revoked_count > 0 {
            tracing::info!("Revoked {} expired leases out of {} identified", revoked_count, expired_lease_ids.len());
        }

        Ok(())
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
                     self.config = cfg;
                     // Validate connection URL regardless of enabled state
                     self.detect_database_type(&self.config.connection_url)?;

                     // Initialize backend only if enabled to avoid wasteful resource allocation
                     if config.enabled {
                         self.init_backend()?;
                         self.validate_leases().await?;
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
                        eprintln!("Failed to initialize database backend during enable: {}", e);
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

    #[tokio::test]
    async fn test_lease_lifecycle() -> SecretResult<()> {
        let config = DatabaseConfig {
            connection_url: "postgresql://localhost:5432/db".to_string(),
            plugin_name: "test".to_string(),
            allowed_roles: vec![],
            username: None,
            password: None,
            max_open_connections: None,
            max_idle_connections: None,
            max_connection_lifetime: None,
        };

        let storage = Arc::new(secreton_storage::MockStorageBackend::new());
        let mut engine = DatabaseEngine::new(config, storage);

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
}
