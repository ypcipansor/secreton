//! Brankas Storage Abstraction Layer
//!
//! Provides unified interface for different storage backends including
//! PostgreSQL, Redis, and file-based storage.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use uuid::Uuid;
use thiserror::Error;

pub mod backends;
pub mod models;
pub mod cache;

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
