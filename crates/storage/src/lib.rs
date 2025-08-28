//! Brankas Storage Abstraction Layer
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
pub mod models;

// Re-export common backends
pub use backends::{FileBackend, PostgresBackend, RaftConfig, RaftStorageBackend, RedisBackend};

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

/// Type alias for Results with StorageError
pub type StorageResult<T> = Result<T, StorageError>;

/// Security classification levels for data
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    Public = 0,
    Internal = 1,
    Confidential = 2,
    Secret = 3,
    TopSecret = 4,
}

/// Generic vault entry for storing encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier
    pub id: Uuid,

    /// Entry path/key
    pub path: String,

    /// Encrypted data
    pub encrypted_data: Vec<u8>,

    /// Encryption metadata
    pub encryption_metadata: EncryptionMetadata,

    /// Security classification
    pub security_level: SecurityLevel,

    /// Entry metadata
    pub metadata: HashMap<String, String>,

    /// Entry tags for organization
    pub tags: Vec<String>,

    /// Entry version
    pub version: u32,

    /// Owner user ID
    pub owner_id: Uuid,

    /// Creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last modified timestamp
    pub updated_at: DateTime<Utc>,

    /// Expiration timestamp (optional)
    pub expires_at: Option<DateTime<Utc>>,
}

impl VaultEntry {
    pub fn new(
        path: String,
        encrypted_data: Vec<u8>,
        encryption_metadata: EncryptionMetadata,
        security_level: SecurityLevel,
        owner_id: Uuid,
    ) -> Self {
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
            created_at: Utc::now(),
            updated_at: Utc::now(),
            expires_at: None,
        }
    }

    /// Check if entry has expired
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

/// Encryption metadata for stored data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm used
    pub algorithm: String,

    /// Key identifier
    pub key_id: String,

    /// Initialization vector/nonce
    pub iv: Vec<u8>,

    /// Authentication tag (for AEAD modes)
    pub auth_tag: Option<Vec<u8>>,

    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,

    /// Key derivation parameters
    pub kdf_params: Option<HashMap<String, String>>,
}

/// Query parameters for filtering vault entries
#[derive(Debug, Clone, Default)]
pub struct QueryParams {
    /// Filter by path prefix
    pub path_prefix: Option<String>,

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

/// Storage backend trait for different implementations
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Store a vault entry
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()>;

    /// Retrieve a vault entry by ID
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>>;

    /// Retrieve a vault entry by path
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>>;

    /// Update an existing vault entry
    async fn update(&self, entry: &VaultEntry) -> StorageResult<()>;

    /// Delete a vault entry by ID
    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool>;

    /// Delete a vault entry by path
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool>;

    /// List vault entries with filtering
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>>;

    /// Count vault entries matching query
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
}

/// Transaction interface for atomic operations
#[async_trait]
pub trait StorageTransaction: Send + Sync {
    /// Store entry within transaction
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()>;

    /// Update entry within transaction
    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()>;

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
    data: Arc<std::sync::RwLock<HashMap<String, VaultEntry>>>,
    id_index: Arc<std::sync::RwLock<HashMap<Uuid, String>>>,
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
        }
    }
}

#[async_trait]
impl StorageBackend for MockStorageBackend {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        let mut id_index = self.id_index.write().unwrap();

        data.insert(entry.path.clone(), entry.clone());
        id_index.insert(entry.id, entry.path.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        let id_index = self.id_index.read().unwrap();
        if let Some(path) = id_index.get(&id) {
            let data = self.data.read().unwrap();
            Ok(data.get(path).cloned())
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        let data = self.data.read().unwrap();
        Ok(data.get(path).cloned())
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        if data.contains_key(&entry.path) {
            data.insert(entry.path.clone(), entry.clone());
            Ok(())
        } else {
            Err(StorageError::NotFound {
                resource_type: "VaultEntry".to_string(),
                id: entry.path.clone(),
            })
        }
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let mut id_index = self.id_index.write().unwrap();
        if let Some(path) = id_index.remove(&id) {
            let mut data = self.data.write().unwrap();
            data.remove(&path);
            Ok(true)
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

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let data = self.data.read().unwrap();
        let mut results: Vec<VaultEntry> = data
            .values()
            .filter(|entry| {
                // Simple filtering logic
                if let Some(prefix) = &params.path_prefix {
                    if !entry.path.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(owner) = params.owner_id {
                    if entry.owner_id != owner {
                        return false;
                    }
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
}

/// Mock transaction for testing
pub struct MockTransaction;

#[async_trait]
impl StorageTransaction for MockTransaction {
    async fn store(&mut self, _entry: &VaultEntry) -> StorageResult<()> {
        Ok(())
    }

    async fn update(&mut self, _entry: &VaultEntry) -> StorageResult<()> {
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
