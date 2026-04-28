//! Secreton Storage Abstraction Layer
//!
//! Provides unified interface for different storage backends including
//! PostgreSQL, Redis, file-based storage, and Raft integrated storage.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

pub mod backends;
pub mod cache;
pub mod factory;
pub mod models;
pub mod storage_backends;

// Re-export common backends
pub use backends::{FileBackend, PostgresBackend, RaftConfig, RaftStorageBackend, RedisBackend};

// Re-export new backends
pub use backends::{ConsulStorage, ConsulStorageConfig};
pub use backends::{DynamoDBStorage, DynamoDBStorageConfig};
pub use backends::{EtcdStorage, EtcdStorageConfig};
pub use backends::{MySQLStorage, MySQLStorageConfig};
pub use backends::{S3Storage, S3StorageConfig};

// Re-export factory
pub use factory::{StorageBackendType, StorageFactory, StorageFactoryConfig};

// Import from common
use secreton_common::models::oauth_state::OAuthState;

/// Encryption metadata for secreton entries
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm used
    pub algorithm: String,
    /// Key ID used for encryption
    pub key_id: String,
    /// Initialization vector
    pub iv: Vec<u8>,
    /// Authentication tag for AEAD ciphers.
    /// Note: For AES-GCM and ChaCha20-Poly1305 as implemented in `secreton_crypto`,
    /// the auth tag is appended to the ciphertext by the underlying crates, so this
    /// field is `None`. It is kept for ciphers that produce a separate tag.
    pub auth_tag: Option<Vec<u8>>,
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
    /// Key derivation parameters
    pub kdf_params: Option<HashMap<String, String>>,
}

/// Security classification levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Public information - no security controls required
    Public = 0,
    /// Internal use - basic access controls
    Internal = 1,
    /// Confidential - restricted access
    Confidential = 2,
    /// Secret - highly restricted access
    Secret = 3,
    /// Top Secret - maximum security controls
    TopSecret = 4,
}

/// Secret entry for storing secrets
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretEntry {
    /// Unique identifier for the entry
    pub id: Uuid,
    /// Path to the secret
    pub path: String,
    /// Encrypted secret data
    pub encrypted_data: Vec<u8>,
    /// Encryption metadata
    pub encryption_metadata: EncryptionMetadata,
    /// Security level of the data
    pub security_level: SecurityLevel,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Version number
    pub version: u32,
    /// Owner of the entry
    pub owner_id: Uuid,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last update timestamp
    pub updated_at: DateTime<Utc>,
    /// Optional expiration time
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretEntry {
    /// Create a new secreton entry
    pub fn new(
        path: String,
        encrypted_data: Vec<u8>,
        encryption_metadata: EncryptionMetadata,
        security_level: SecurityLevel,
        owner_id: Uuid,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            path,
            encrypted_data,
            encryption_metadata,
            security_level,
            metadata: HashMap::new(),
            tags: Vec::new(),
            version: 1,
            owner_id,
            created_at: now,
            updated_at: now,
            expires_at: None,
        }
    }

    /// Check if the entry is expired
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() > expires_at
        } else {
            false
        }
    }

    /// Set expiration time
    pub fn with_expiration(mut self, expires_at: DateTime<Utc>) -> Self {
        self.expires_at = Some(expires_at);
        self
    }

    /// Add metadata
    pub fn add_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Add tag
    pub fn add_tag(mut self, tag: String) -> Self {
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
        self
    }
}

impl Default for EncryptionMetadata {
    fn default() -> Self {
        Self {
            algorithm: "plaintext".to_string(),
            key_id: String::new(),
            iv: Vec::new(),
            auth_tag: None,
            aad: None,
            kdf_params: None,
        }
    }
}

/// Query parameters for filtering secreton entries
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    /// Filter by path prefix
    pub path_prefix: Option<String>,

    /// Exclude entries whose path starts with any of these prefixes.
    ///
    /// Used by the lifecycle sweep to skip reserved namespaces (e.g. `sys/`,
    /// `keys/`) at the storage layer instead of paying for them with the
    /// query's `limit` budget. Backends that ignore this field are not
    /// incorrect — callers must still apply their own in-memory exclusion as
    /// a fallback — but on backends that honor it (e.g. PostgreSQL), reserved
    /// entries no longer consume rows from `limit`.
    pub excluded_path_prefixes: Vec<String>,

    /// Filter by security level (minimum)
    pub security_level: Option<SecurityLevel>,

    /// Filter by tags
    pub tags: Vec<String>,

    /// Filter by owner
    pub owner_id: Option<Uuid>,

    /// Filter by metadata
    pub metadata_filters: HashMap<String, String>,

    /// Include expired entries
    pub include_expired: bool,

    /// Maximum number of results
    pub limit: Option<u32>,

    /// Results offset
    pub offset: Option<u32>,

    /// Sort order
    pub sort_by: Option<String>,

    /// Sort direction (asc/desc)
    pub sort_order: Option<String>,
}

impl QueryParams {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_path_prefix(mut self, prefix: String) -> Self {
        self.path_prefix = Some(prefix);
        self
    }

    pub fn with_excluded_path_prefixes<I, S>(mut self, prefixes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.excluded_path_prefixes = prefixes.into_iter().map(Into::into).collect();
        self
    }

    pub fn with_security_level(mut self, level: SecurityLevel) -> Self {
        self.security_level = Some(level);
        self
    }

    pub fn with_tag(mut self, tag: String) -> Self {
        self.tags.push(tag);
        self
    }

    pub fn with_owner(mut self, owner_id: Uuid) -> Self {
        self.owner_id = Some(owner_id);
        self
    }

    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Storage operation errors
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Query failed: {message}")]
    QueryFailed { message: String },

    #[error("Transaction failed: {message}")]
    TransactionFailed { message: String },

    #[error("Serialization error: {message}")]
    SerializationError { message: String },

    #[error("Not found: {resource_type} with ID {id}")]
    NotFound { resource_type: String, id: String },

    #[error("Duplicate entry: {resource_type} with ID {id}")]
    Duplicate { resource_type: String, id: String },

    #[error("Constraint violation: {constraint} - {message}")]
    ConstraintViolation { constraint: String, message: String },

    #[error("Permission denied for operation: {operation}")]
    PermissionDenied { operation: String },

    #[error("Storage backend error: {backend} - {message}")]
    BackendError { backend: String, message: String },

    #[error("Configuration error: {message}")]
    ConfigurationError { message: String },

    #[error("Migration error: {message}")]
    MigrationError { message: String },
}

// impl From<azure_storage::Error> for StorageError {
//     fn from(error: azure_storage::Error) -> Self {
//         StorageError::BackendError {
//             backend: "Azure Blob Storage".to_string(),
//             message: error.to_string(),
//         }
//     }
// }

// impl From<google_cloud_storage::Error> for StorageError {
//     fn from(error: google_cloud_storage::Error) -> Self {
//         StorageError::BackendError {
//             backend: "Google Cloud Storage".to_string(),
//             message: error.to_string(),
//         }
//     }
// }

/// Type alias for Results with StorageError
pub type StorageResult<T> = Result<T, StorageError>;

/// Storage backend trait for different implementations
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a secreton entry
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()>;

    /// Retrieve a secreton entry by ID
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>>;

    /// Retrieve a secreton entry by path
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>>;

    /// Update an existing secreton entry
    async fn update(&self, entry: &SecretEntry) -> StorageResult<()>;

    /// Delete a secreton entry by ID
    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool>;

    /// Delete a secreton entry by path
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool>;

    /// List secreton entries with filtering
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>>;

    /// Count secreton entries matching query
    async fn count(&self, params: &QueryParams) -> StorageResult<u64>;

    /// Check if path exists
    async fn exists(&self, path: &str) -> StorageResult<bool>;

    /// Begin a transaction
    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>>;

    /// Perform health check
    async fn health_check(&self) -> StorageResult<HealthStatus>;

    /// Get storage statistics
    async fn get_stats(&self) -> StorageResult<StorageStats>;

    /// Run migrations
    async fn migrate(&self) -> StorageResult<()>;

    /// Compact the storage backend to reclaim space
    async fn compact(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Perform a vacuum/cleanup operation on the database
    async fn vacuum(&self) -> StorageResult<()> {
        Ok(())
    }

    /// Delete expired entries
    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let params = QueryParams {
            path_prefix,
            include_expired: true,
            ..Default::default()
        };

        let entries = self.list(&params).await?;
        let mut deleted_count = 0;
        let now = Utc::now();

        for entry in entries {
            if let Some(expires_at) = entry.expires_at {
                if expires_at < now {
                    if self.delete_by_id(entry.id).await? {
                        deleted_count += 1;
                    }
                }
            }
        }

        Ok(deleted_count)
    }

    /// Delete a secret entry directly by path (convenience wrapper for delete_by_path)
    async fn delete_secret(&self, path: &str) -> StorageResult<bool> {
        self.delete_by_path(path).await
    }

    /// Store OAuth state.
    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()>;

    /// Retrieve and consume OAuth state.
    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>>;

    /// Delete expired OAuth states.
    async fn delete_expired_oauth_states(&self) -> StorageResult<u64>;
}

/// Transaction interface for atomic operations
#[async_trait]
pub trait StorageTransaction: Send + Sync {
    /// Store entry within transaction
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()>;

    /// Update entry within transaction
    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()>;

    /// Delete entry within transaction
    async fn delete(&mut self, id: Uuid) -> StorageResult<bool>;

    /// Commit the transaction
    async fn commit(self: Box<Self>) -> StorageResult<()>;

    /// Rollback the transaction
    async fn rollback(self: Box<Self>) -> StorageResult<()>;
}

/// Storage health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub response_time_ms: f64,
    pub connections_active: u32,
    pub connections_idle: u32,
    pub last_error: Option<String>,
    pub uptime_seconds: u64,
}

/// Storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_entries: u64,
    pub total_size_bytes: u64,
    pub average_entry_size: f64,
    pub entries_by_security_level: HashMap<SecurityLevel, u64>,
    pub entries_created_today: u64,
    pub entries_updated_today: u64,
    pub expired_entries: u64,
}

/// Storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Backend type (postgres, redis, file)
    pub backend_type: String,

    /// Connection string or path
    pub connection_string: String,

    /// Connection pool settings
    pub pool_settings: PoolSettings,

    /// Encryption settings
    pub encryption_enabled: bool,

    /// Compression settings
    pub compression_enabled: bool,

    /// Backup settings
    pub backup_enabled: bool,

    /// Cache settings
    pub cache_enabled: bool,
}

/// Connection pool settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSettings {
    pub max_connections: u32,
    pub min_connections: u32,
    pub connection_timeout_seconds: u64,
    pub idle_timeout_seconds: u64,
    pub max_lifetime_seconds: u64,
}

impl Default for PoolSettings {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            connection_timeout_seconds: 30,
            idle_timeout_seconds: 600,
            max_lifetime_seconds: 3600,
        }
    }
}

/// Simple in-memory mock storage backend for testing and development
#[derive(Debug, Clone)]
pub struct MockStorageBackend {
    data: Arc<std::sync::RwLock<HashMap<String, SecretEntry>>>,
    id_index: Arc<std::sync::RwLock<HashMap<Uuid, String>>>,
    oauth_states: Arc<std::sync::RwLock<HashMap<String, OAuthState>>>,
}

impl Default for MockStorageBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MockStorageBackend {
    pub fn new() -> Self {
        Self {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
            id_index: Arc::new(std::sync::RwLock::new(HashMap::new())),
            oauth_states: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl StorageBackend for MockStorageBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        let mut id_index = self.id_index.write().unwrap();

        data.insert(entry.path.clone(), entry.clone());
        id_index.insert(entry.id, entry.path.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let id_index = self.id_index.read().unwrap();
        if let Some(path) = id_index.get(&id) {
            let data = self.data.read().unwrap();
            Ok(data.get(path).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let data = self.data.read().unwrap();
        Ok(data.get(path).cloned())
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        if data.contains_key(&entry.path) {
            data.insert(entry.path.clone(), entry.clone());
            Ok(())
        } else {
            Err(StorageError::NotFound {
                resource_type: "SecretEntry".to_string(),
                id: entry.id.to_string(),
            })
        }
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let mut id_index = self.id_index.write().unwrap();
        if let Some(path) = id_index.remove(&id) {
            let mut data = self.data.write().unwrap();
            if data.remove(&path).is_some() {
                Ok(true)
            } else {
                // restore index consistency if data missing unexpectedly
                id_index.insert(id, path);
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut data = self.data.write().unwrap();
        if let Some(entry) = data.remove(path) {
            let mut id_index = self.id_index.write().unwrap();
            id_index.remove(&entry.id);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let data = self.data.read().unwrap();
        let mut results: Vec<SecretEntry> = data
            .values()
            .filter(|entry| {
                // Simple filtering logic
                if let Some(prefix) = &params.path_prefix
                    && !entry.path.starts_with(prefix)
                {
                    return false;
                }
                if let Some(owner) = params.owner_id
                    && entry.owner_id != owner
                {
                    return false;
                }
                !entry.is_expired() || params.include_expired
            })
            .cloned()
            .collect();

        // Apply limit
        if let Some(limit) = params.limit {
            results.truncate(limit as usize);
        }

        Ok(results)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let data = self.data.read().unwrap();
        Ok(data.contains_key(path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        // For mock, just return a no-op transaction
        Ok(Box::new(MockTransaction))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 3600,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let data = self.data.read().unwrap();
        let total_entries = data.len() as u64;
        let total_size_bytes = data.values().map(|e| e.encrypted_data.len() as u64).sum();

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: HashMap::new(),
            entries_created_today: total_entries,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // Mock migration - nothing to do
        Ok(())
    }

    async fn compact(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn vacuum(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn delete_expired(&self, path_prefix: Option<String>) -> StorageResult<u64> {
        let now = Utc::now();
        let mut data = self.data.write().unwrap();
        let mut id_index = self.id_index.write().unwrap();
        let mut deleted_count = 0;

        // Collect keys to delete first to avoid borrowing issues
        let keys_to_delete: Vec<String> = data
            .iter()
            .filter(|(_, entry)| {
                let matches_prefix = if let Some(prefix) = &path_prefix {
                    entry.path.starts_with(prefix)
                } else {
                    true
                };

                let is_expired = if let Some(expires_at) = entry.expires_at {
                    expires_at < now
                } else {
                    false
                };

                matches_prefix && is_expired
            })
            .map(|(k, _)| k.clone())
            .collect();

        for key in keys_to_delete {
            if let Some(entry) = data.remove(&key) {
                id_index.remove(&entry.id);
                deleted_count += 1;
            }
        }

        Ok(deleted_count)
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        let mut states = self.oauth_states.write().unwrap();
        states.insert(state.state.clone(), state.clone());
        Ok(())
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        let mut states = self.oauth_states.write().unwrap();
        if let Some(oauth_state) = states.get(state) {
            if oauth_state.expires_at < Utc::now() {
                states.remove(state);
                return Ok(None);
            }
        }
        Ok(states.remove(state))
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        let mut states = self.oauth_states.write().unwrap();
        let mut count = 0;
        states.retain(|_, state| {
            if state.expires_at < Utc::now() {
                count += 1;
                false
            } else {
                true
            }
        });
        Ok(count)
    }
}

/// Mock transaction for testing
pub struct MockTransaction;

#[async_trait]
impl StorageTransaction for MockTransaction {
    async fn store(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        Ok(())
    }

    async fn update(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        Ok(())
    }

    async fn delete(&mut self, _id: Uuid) -> StorageResult<bool> {
        Ok(true)
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        Ok(())
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_secreton_entry_initialization_defaults() {
        let owner = Uuid::new_v4();
        let entry = SecretEntry::new(
            "secret/path".to_string(),
            vec![1, 2, 3],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-123".to_string(),
                iv: vec![0; 12],
                auth_tag: Some(vec![0; 16]),
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Secret,
            owner,
        );

        assert_eq!(entry.path, "secret/path");
        assert_eq!(entry.version, 1);
        assert_eq!(entry.security_level, SecurityLevel::Secret);
        assert_eq!(entry.owner_id, owner);
        assert!(entry.metadata.is_empty());
        assert!(entry.tags.is_empty());
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_secreton_entry_tag_and_metadata_helpers() {
        let owner = Uuid::new_v4();
        let entry = SecretEntry::new(
            "secret/path".to_string(),
            vec![],
            EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-123".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            SecurityLevel::Confidential,
            owner,
        )
        .add_metadata("env".to_string(), "prod".to_string())
        .add_metadata("region".to_string(), "apac".to_string())
        .add_tag("finance".to_string())
        .add_tag("finance".to_string())
        .add_tag("internal".to_string());

        assert_eq!(entry.metadata.get("env"), Some(&"prod".to_string()));
        assert_eq!(entry.metadata.get("region"), Some(&"apac".to_string()));

        let tag_set: HashSet<String> = entry.tags.iter().cloned().collect();
        assert_eq!(tag_set.len(), 2);
        assert!(tag_set.contains("finance"));
        assert!(tag_set.contains("internal"));
    }

    #[test]
    fn test_query_params_helpers() {
        let owner = Uuid::new_v4();
        let params = QueryParams::new()
            .with_path_prefix("apps/".to_string())
            .with_security_level(SecurityLevel::Internal)
            .with_tag("pci".to_string())
            .with_tag("finance".to_string())
            .with_owner(owner)
            .with_limit(50);

        assert_eq!(params.path_prefix.as_deref(), Some("apps/"));
        assert_eq!(params.security_level, Some(SecurityLevel::Internal));
        assert_eq!(params.tags.len(), 2);
        assert_eq!(params.owner_id, Some(owner));
        assert_eq!(params.limit, Some(50));
    }

    #[test]
    fn test_storage_error_debug_and_display() {
        let error = StorageError::NotFound {
            resource_type: "secreton_entry".to_string(),
            id: "123".to_string(),
        };

        let display = format!("{}", error);
        assert!(display.contains("Not found"));
        assert!(display.contains("secreton_entry"));
        assert!(display.contains("123"));

        let debug = format!("{:?}", error);
        assert!(debug.contains("NotFound"));
    }
}
