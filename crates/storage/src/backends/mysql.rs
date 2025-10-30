use crate::{
    HealthStatus, QueryParams, StorageBackend, StorageError, StorageResult, StorageStats,
    StorageTransaction, VaultEntry,
};
use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use mysql::prelude::Queryable;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// MySQL storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MySQLStorageConfig {
    /// MySQL connection string
    pub connection_string: String,
    /// Table name for storing vault data
    pub table_name: String,
    /// Maximum number of connections in pool
    pub max_connections: u32,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Enable SSL/TLS
    pub ssl_enabled: bool,
}

impl Default for MySQLStorageConfig {
    fn default() -> Self {
        Self {
            connection_string: "mysql://vault:password@localhost/vault".to_string(),
            table_name: "vault_kv_store".to_string(),
            max_connections: 10,
            connection_timeout: 30,
            ssl_enabled: false,
        }
    }
}

/// MySQL storage backend
pub struct MySQLStorage {
    config: MySQLStorageConfig,
    pool: mysql::Pool,
    cache: Arc<RwLock<HashMap<String, VaultEntry>>>,
}

/// MySQL transaction implementation
pub struct MySQLTransaction {
    operations: Vec<MySQLOperation>,
    committed: bool,
}

enum MySQLOperation {
    Store(VaultEntry),
    Update(VaultEntry),
    Delete(Uuid),
}

impl MySQLTransaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for MySQLTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(MySQLOperation::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(MySQLOperation::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(MySQLOperation::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real MySQL implementation, you would execute all operations
        // in a transaction using the mysql crate's transaction support
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl MySQLStorage {
    /// Validate SQL identifier (table name) to prevent SQL injection
    /// SECURITY FIX: Prevents SQL injection via table name
    fn validate_sql_identifier(name: &str) -> Result<(), StorageError> {
        // Check length (max 64 chars for MySQL)
        if name.is_empty() || name.len() > 64 {
            return Err(StorageError::ConfigurationError {
                message: format!(
                    "Table name length must be 1-64 characters, got {}",
                    name.len()
                ),
            });
        }

        // Only allow alphanumeric and underscore (no spaces, special chars)
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            return Err(StorageError::ConfigurationError {
                message: format!(
                    "Table name '{}' contains invalid characters. Only alphanumeric and underscore allowed.",
                    name
                ),
            });
        }

        // Prevent SQL keywords as table names
        let uppercase = name.to_uppercase();
        let sql_keywords = [
            "SELECT",
            "INSERT",
            "UPDATE",
            "DELETE",
            "DROP",
            "CREATE",
            "ALTER",
            "TABLE",
            "DATABASE",
            "INDEX",
            "VIEW",
            "PROCEDURE",
            "FUNCTION",
            "TRIGGER",
            "USER",
            "GRANT",
            "REVOKE",
            "FROM",
            "WHERE",
            "JOIN",
        ];

        if sql_keywords.contains(&uppercase.as_str()) {
            return Err(StorageError::ConfigurationError {
                message: format!("Table name '{}' is a reserved SQL keyword", name),
            });
        }

        // Must not start with number (MySQL rule)
        if name.chars().next().unwrap().is_ascii_digit() {
            return Err(StorageError::ConfigurationError {
                message: format!("Table name '{}' cannot start with a digit", name),
            });
        }

        Ok(())
    }

    /// Create new MySQL storage backend
    pub async fn new(config: MySQLStorageConfig) -> Result<Self, StorageError> {
        // SECURITY FIX: Validate table name before use
        Self::validate_sql_identifier(&config.table_name)?;

        let opts = mysql::Opts::from_url(&config.connection_string).map_err(|e| {
            StorageError::ConnectionFailed {
                message: format!("Invalid MySQL URL: {}", e),
            }
        })?;
        let pool = mysql::Pool::new(opts).map_err(|e| StorageError::ConnectionFailed {
            message: format!("Failed to create MySQL pool: {}", e),
        })?;

        // Create table if not exists
        Self::create_table_if_not_exists(&pool, &config.table_name).await?;

        Ok(Self {
            config,
            pool,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create table if not exists
    async fn create_table_if_not_exists(
        pool: &mysql::Pool,
        table_name: &str,
    ) -> Result<(), StorageError> {
        let mut conn = pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let create_table_query = format!(
            r#"
            CREATE TABLE IF NOT EXISTS {} (
                id CHAR(36) PRIMARY KEY,
                path VARCHAR(512) UNIQUE NOT NULL,
                encrypted_data LONGBLOB NOT NULL,
                encryption_metadata JSON NOT NULL,
                security_level TINYINT NOT NULL,
                metadata JSON,
                tags JSON,
                version INT NOT NULL DEFAULT 1,
                owner_id CHAR(36) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NULL,
                INDEX idx_path (path),
                INDEX idx_owner (owner_id),
                INDEX idx_expires (expires_at)
            )
            "#,
            table_name
        );

        conn.query_drop(create_table_query)
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to create table: {}", e),
            })?;

        Ok(())
    }

    /// Build MySQL query for inserting/updating entries
    fn build_upsert_query(&self, _entry: &VaultEntry) -> String {
        format!(
            r#"
            INSERT INTO {} (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE
                encrypted_data = VALUES(encrypted_data),
                encryption_metadata = VALUES(encryption_metadata),
                security_level = VALUES(security_level),
                metadata = VALUES(metadata),
                tags = VALUES(tags),
                version = version + 1,
                updated_at = CURRENT_TIMESTAMP,
                expires_at = VALUES(expires_at)
            "#,
            self.config.table_name
        )
    }

    /// Build MySQL query for selecting entries
    fn build_select_query(&self, _path: &str) -> String {
        format!(
            "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM {} WHERE path = ?",
            self.config.table_name
        )
    }

    /// Build MySQL query for deleting entries
    fn build_delete_query(&self, _path: &str) -> String {
        format!("DELETE FROM {} WHERE path = ?", self.config.table_name)
    }

    /// Build MySQL query for listing entries with prefix
    fn build_list_query(&self, prefix: &str) -> String {
        if prefix.is_empty() {
            format!(
                "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM {} ORDER BY path",
                self.config.table_name
            )
        } else {
            format!(
                "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM {} WHERE path LIKE ? ORDER BY path",
                self.config.table_name
            )
        }
    }
}

#[async_trait]
impl StorageBackend for MySQLStorage {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = self.build_upsert_query(entry);

        let encryption_metadata_json =
            serde_json::to_string(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;

        let metadata_json = serde_json::to_string(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        let tags_json =
            serde_json::to_string(&entry.tags).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize tags: {}", e),
            })?;
        let expires_at: Option<NaiveDateTime> = entry.expires_at.map(|dt| dt.naive_utc());

        conn.exec_drop(
            &query,
            (
                &entry.id.to_string(),
                &entry.path,
                &entry.encrypted_data,
                &encryption_metadata_json,
                entry.security_level as u8,
                &metadata_json,
                &tags_json,
                entry.version as u32,
                &entry.owner_id.to_string(),
                entry.created_at.naive_utc(),
                entry.updated_at.naive_utc(),
                &expires_at,
            ),
        )
        .map_err(|e| StorageError::BackendError {
            backend: "mysql".to_string(),
            message: format!("Failed to store entry: {}", e),
        })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entry.path.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<VaultEntry>> {
        // For MySQL, we need to query by path first to find the entry
        // This is a limitation of the current design
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(entry.clone()));
            }
        }

        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = self.build_select_query(path);

        let rows: Vec<mysql::Row> =
            conn.exec(&query, (path,))
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to query entry: {}", e),
                })?;

        if let Some(row) = rows.first() {
            let entry = self.row_to_vault_entry(row)?;
            let mut cache = self.cache.write().await;
            cache.insert(path.to_string(), entry.clone());
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        // For MySQL, we need to find the path first
        // This is a limitation of the current design
        Ok(false)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = self.build_delete_query(path);

        conn.exec_drop(&query, (path,))
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to delete entry: {}", e),
            })?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(path);

        Ok(conn.affected_rows() > 0)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = self.build_list_query(&params.path_prefix.as_deref().unwrap_or(""));

        let rows: Vec<mysql::Row> = if params.path_prefix.as_deref().unwrap_or("").is_empty() {
            conn.exec(&query, ())
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to list entries: {}", e),
                })?
        } else {
            conn.exec(
                &query,
                (format!("{}%", params.path_prefix.as_deref().unwrap_or("")),),
            )
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to list entries: {}", e),
            })?
        };

        let mut entries = Vec::new();
        for row in rows {
            let entry = self.row_to_vault_entry(&row)?;
            entries.push(entry);
        }

        // Apply filters
        let mut filtered_entries = Vec::new();
        for entry in entries {
            if let Some(owner_id) = params.owner_id {
                if entry.owner_id != owner_id {
                    continue;
                }
            }
            if !params.include_expired && entry.is_expired() {
                continue;
            }
            filtered_entries.push(entry);
        }

        // Apply limit
        if let Some(limit) = params.limit {
            filtered_entries.truncate(limit as usize);
        }

        Ok(filtered_entries)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        Ok(self.get_by_path(path).await?.is_some())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(MySQLTransaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        let result = self.pool.get_conn();

        let duration = start.elapsed().as_millis() as f64;

        match result {
            Ok(_) => Ok(HealthStatus {
                is_healthy: true,
                response_time_ms: duration,
                connections_active: self.config.max_connections,
                connections_idle: 0,
                last_error: None,
                uptime_seconds: 0,
            }),
            Err(e) => Ok(HealthStatus {
                is_healthy: false,
                response_time_ms: duration,
                connections_active: 0,
                connections_idle: 0,
                last_error: Some(e.to_string()),
                uptime_seconds: 0,
            }),
        }
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let entries = self.list(&QueryParams::default()).await?;
        let total_entries = entries.len() as u64;
        let total_size_bytes: u64 = entries.iter().map(|e| e.encrypted_data.len() as u64).sum();

        let mut entries_by_security_level = HashMap::new();
        for entry in &entries {
            *entries_by_security_level
                .entry(entry.security_level)
                .or_insert(0) += 1;
        }

        Ok(StorageStats {
            total_entries,
            total_size_bytes,
            average_entry_size: if total_entries > 0 {
                total_size_bytes as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level,
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: entries.iter().filter(|e| e.is_expired()).count() as u64,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // MySQL migrations would be implemented here
        Ok(())
    }
}

impl MySQLStorage {
    /// Convert MySQL row to VaultEntry
    fn row_to_vault_entry(&self, row: &mysql::Row) -> Result<VaultEntry, StorageError> {
        let id: String = row.get(0).ok_or_else(|| StorageError::SerializationError {
            message: "Missing id field".to_string(),
        })?;
        let path: String = row.get(1).ok_or_else(|| StorageError::SerializationError {
            message: "Missing path field".to_string(),
        })?;
        let encrypted_data: Vec<u8> =
            row.get(2).ok_or_else(|| StorageError::SerializationError {
                message: "Missing encrypted_data field".to_string(),
            })?;
        let encryption_metadata_json: String =
            row.get(3).ok_or_else(|| StorageError::SerializationError {
                message: "Missing encryption_metadata field".to_string(),
            })?;
        let security_level: u8 = row.get(4).ok_or_else(|| StorageError::SerializationError {
            message: "Missing security_level field".to_string(),
        })?;
        let metadata_json: Option<String> = row.get(5);
        let tags_json: String = row.get(6).ok_or_else(|| StorageError::SerializationError {
            message: "Missing tags field".to_string(),
        })?;
        let version: i32 = row.get(7).ok_or_else(|| StorageError::SerializationError {
            message: "Missing version field".to_string(),
        })?;
        let owner_id: String = row.get(8).ok_or_else(|| StorageError::SerializationError {
            message: "Missing owner_id field".to_string(),
        })?;
        let created_at: NaiveDateTime =
            row.get(9).ok_or_else(|| StorageError::SerializationError {
                message: "Missing created_at field".to_string(),
            })?;
        let updated_at: NaiveDateTime =
            row.get(10)
                .ok_or_else(|| StorageError::SerializationError {
                    message: "Missing updated_at field".to_string(),
                })?;
        let expires_at: Option<NaiveDateTime> = row.get(11);

        let id = Uuid::parse_str(&id).map_err(|e| StorageError::SerializationError {
            message: format!("Invalid UUID: {}", e),
        })?;
        let owner_id =
            Uuid::parse_str(&owner_id).map_err(|e| StorageError::SerializationError {
                message: format!("Invalid owner UUID: {}", e),
            })?;

        let encryption_metadata: crate::EncryptionMetadata =
            serde_json::from_str(&encryption_metadata_json).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to deserialize encryption metadata: {}", e),
                }
            })?;

        let security_level = match security_level {
            0 => crate::SecurityLevel::Public,
            1 => crate::SecurityLevel::Internal,
            2 => crate::SecurityLevel::Secret,
            3 => crate::SecurityLevel::TopSecret,
            _ => crate::SecurityLevel::Secret,
        };

        let metadata = if let Some(json) = metadata_json {
            Some(
                serde_json::from_str(&json).map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to deserialize metadata: {}", e),
                })?,
            )
        } else {
            None
        };

        let tags: Vec<String> =
            serde_json::from_str(&tags_json).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to deserialize tags: {}", e),
            })?;

        let expires_at_dt =
            expires_at.map(|dt| chrono::DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc));

        Ok(VaultEntry {
            id,
            path,
            encrypted_data,
            encryption_metadata,
            security_level,
            metadata: metadata.unwrap_or_default(),
            tags,
            version: version as u32,
            owner_id,
            created_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(created_at, Utc),
            updated_at: chrono::DateTime::<Utc>::from_naive_utc_and_offset(updated_at, Utc),
            expires_at: expires_at_dt,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_config_default() {
        let config = MySQLStorageConfig::default();
        assert_eq!(config.table_name, "vault_kv_store");
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connection_timeout, 30);
        assert!(!config.ssl_enabled);
    }

    #[test]
    fn test_build_upsert_query() {
        let config = MySQLStorageConfig::default();
        let storage = MySQLStorage {
            config,
            pool: mysql::Pool::new("mysql://test").unwrap(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let entry = VaultEntry::new(
            "test/path".to_string(),
            vec![1, 2, 3],
            crate::EncryptionMetadata {
                algorithm: "aes-256-gcm".to_string(),
                key_id: "key-123".to_string(),
                iv: vec![0; 12],
                auth_tag: None,
                aad: None,
                kdf_params: None,
            },
            crate::SecurityLevel::Secret,
            Uuid::new_v4(),
        );

        let query = storage.build_upsert_query(&entry);
        assert!(query.contains("INSERT INTO vault_kv_store"));
        assert!(query.contains("ON DUPLICATE KEY UPDATE"));
    }

    #[test]
    fn test_build_select_query() {
        let config = MySQLStorageConfig::default();
        let storage = MySQLStorage {
            config,
            pool: mysql::Pool::new("mysql://test").unwrap(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let query = storage.build_select_query("test/path");
        assert!(query.contains("SELECT"));
        assert!(query.contains("FROM vault_kv_store"));
        assert!(query.contains("WHERE path = ?"));
    }
}
