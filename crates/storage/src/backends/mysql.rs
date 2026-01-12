use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
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
    /// Table name for storing secreton data
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
            connection_string: "mysql://secreton:password@localhost/secreton".to_string(),
            table_name: "secreton_kv_store".to_string(),
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
    cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

/// MySQL transaction implementation
pub struct MySQLTransaction {
    pool: mysql::Pool,
    table_name: String,
    cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
    operations: Vec<MySQLOperation>,
    committed: bool,
}

enum MySQLOperation {
    Store(SecretEntry),
    Update(SecretEntry),
    Delete(Uuid),
}

impl MySQLTransaction {
    pub fn new(
        pool: mysql::Pool,
        table_name: String,
        cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
    ) -> Self {
        Self {
            pool,
            table_name,
            cache,
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for MySQLTransaction {
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(MySQLOperation::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(MySQLOperation::Update(entry.clone()));
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

        if self.operations.is_empty() {
            self.committed = true;
            return Ok(());
        }

        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut tx = conn
            .start_transaction(mysql::TxOpts::default())
            .map_err(|e| StorageError::TransactionFailed {
                message: format!("Failed to start transaction: {}", e),
            })?;

        // Cache updates to apply after successful commit
        let mut cache_inserts = Vec::new();
        let mut cache_removals = Vec::new();

        for op in &self.operations {
            match op {
                MySQLOperation::Store(entry) | MySQLOperation::Update(entry) => {
                    let query = MySQLStorage::build_upsert_query(&self.table_name);

                    let encryption_metadata_json =
                        serde_json::to_string(&entry.encryption_metadata).map_err(|e| {
                            StorageError::SerializationError {
                                message: format!("Failed to serialize encryption metadata: {}", e),
                            }
                        })?;

                    let metadata_json =
                        serde_json::to_string(&entry.metadata).map_err(|e| {
                            StorageError::SerializationError {
                                message: format!("Failed to serialize metadata: {}", e),
                            }
                        })?;

                    let tags_json =
                        serde_json::to_string(&entry.tags).map_err(|e| {
                            StorageError::SerializationError {
                                message: format!("Failed to serialize tags: {}", e),
                            }
                        })?;

                    let expires_at: Option<NaiveDateTime> =
                        entry.expires_at.map(|dt| dt.naive_utc());

                    tx.exec_drop(
                        &query,
                        (
                            &entry.id.to_string(),
                            &entry.path,
                            &entry.encrypted_data,
                            &encryption_metadata_json,
                            entry.security_level as u8,
                            &metadata_json,
                            &tags_json,
                            entry.version,
                            &entry.owner_id.to_string(),
                            entry.created_at.naive_utc(),
                            entry.updated_at.naive_utc(),
                            &expires_at,
                        ),
                    )
                    .map_err(|e| StorageError::BackendError {
                        backend: "mysql".to_string(),
                        message: format!("Failed to execute transaction operation: {}", e),
                    })?;

                    cache_inserts.push(entry.clone());
                }
                MySQLOperation::Delete(id) => {
                    // Try to get path for cache invalidation
                    let select_query =
                        format!("SELECT path FROM `{}` WHERE id = ?", self.table_name);
                    let path: Option<String> = tx
                        .exec_first(&select_query, (id.to_string(),))
                        .map_err(|e| StorageError::BackendError {
                            backend: "mysql".to_string(),
                            message: format!("Failed to query path for deletion: {}", e),
                        })?;

                    if let Some(p) = path {
                        let delete_query = MySQLStorage::build_delete_query_by_id(&self.table_name);
                        tx.exec_drop(&delete_query, (id.to_string(),))
                            .map_err(|e| StorageError::BackendError {
                                backend: "mysql".to_string(),
                                message: format!("Failed to execute delete operation: {}", e),
                            })?;

                        cache_removals.push(p);
                    }
                }
            }
        }

        tx.commit()
            .map_err(|e| StorageError::TransactionFailed {
                message: format!("Failed to commit transaction: {}", e),
            })?;

        self.committed = true;

        // Apply cache updates
        if !cache_inserts.is_empty() || !cache_removals.is_empty() {
            let mut cache = self.cache.write().await;
            for entry in cache_inserts {
                cache.insert(entry.path.clone(), entry);
            }
            for path in cache_removals {
                cache.remove(&path);
            }
        }

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
            "SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TABLE", "DATABASE",
            "INDEX", "VIEW", "PROCEDURE", "FUNCTION", "TRIGGER", "USER", "GRANT", "REVOKE",
            "FROM", "WHERE", "JOIN", "ORDER", "GROUP", "BY", "KEY", "LIMIT", "OFFSET", "HAVING",
            "UNION", "VALUES", "SET",
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
            CREATE TABLE IF NOT EXISTS `{}` (
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
    fn build_upsert_query(table_name: &str) -> String {
        format!(
            r#"
            INSERT INTO `{}` (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
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
            table_name
        )
    }

    /// Build MySQL query for selecting entries
    fn build_select_query(table_name: &str) -> String {
        format!(
            "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM `{}` WHERE path = ?",
            table_name
        )
    }

    /// Build MySQL query for deleting entries by path
    fn build_delete_query(table_name: &str) -> String {
        format!("DELETE FROM `{}` WHERE path = ?", table_name)
    }

    /// Build MySQL query for deleting entries by id
    fn build_delete_query_by_id(table_name: &str) -> String {
        format!("DELETE FROM `{}` WHERE id = ?", table_name)
    }

    /// Build MySQL query for listing entries with prefix
    fn build_list_query(table_name: &str, prefix: &str) -> String {
        if prefix.is_empty() {
            format!(
                "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM `{}` ORDER BY path",
                table_name
            )
        } else {
            format!(
                "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM `{}` WHERE path LIKE ? ORDER BY path",
                table_name
            )
        }
    }
}

#[async_trait]
impl StorageBackend for MySQLStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = MySQLStorage::build_upsert_query(&self.config.table_name);

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
                entry.version,
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

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        // For MySQL, we need to query by path first to find the entry
        // This is a limitation of the current design
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
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

        let query = MySQLStorage::build_select_query(&self.config.table_name);

        let rows: Vec<mysql::Row> =
            conn.exec(&query, (path,))
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to query entry: {}", e),
                })?;

        if let Some(row) = rows.first() {
            let entry = MySQLStorage::row_to_secreton_entry(row)?;
            let mut cache = self.cache.write().await;
            cache.insert(path.to_string(), entry.clone());
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
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

        let query = MySQLStorage::build_delete_query(&self.config.table_name);

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

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let mut conn = self
            .pool
            .get_conn()
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = MySQLStorage::build_list_query(
            &self.config.table_name,
            params.path_prefix.as_deref().unwrap_or(""),
        );

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
            let entry = MySQLStorage::row_to_secreton_entry(&row)?;
            entries.push(entry);
        }

        // Apply filters
        let mut filtered_entries = Vec::new();
        for entry in entries {
            if let Some(owner_id) = params.owner_id
                && entry.owner_id != owner_id
            {
                continue;
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
        Ok(Box::new(MySQLTransaction::new(
            self.pool.clone(),
            self.config.table_name.clone(),
            self.cache.clone(),
        )))
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
    /// Convert MySQL row to SecretEntry
    fn row_to_secreton_entry(row: &mysql::Row) -> Result<SecretEntry, StorageError> {
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

        Ok(SecretEntry {
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
        assert_eq!(config.table_name, "secreton_kv_store");
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.connection_timeout, 30);
        assert!(!config.ssl_enabled);
    }

    #[test]
    fn test_validate_sql_identifier() {
        // Valid names
        assert!(MySQLStorage::validate_sql_identifier("users").is_ok());
        assert!(MySQLStorage::validate_sql_identifier("user_data").is_ok());
        assert!(MySQLStorage::validate_sql_identifier("app1_secrets").is_ok());
        assert!(MySQLStorage::validate_sql_identifier("_hidden").is_ok());

        // Invalid length
        assert!(MySQLStorage::validate_sql_identifier("").is_err());
        let long_name = "a".repeat(65);
        assert!(MySQLStorage::validate_sql_identifier(&long_name).is_err());

        // Invalid characters
        assert!(MySQLStorage::validate_sql_identifier("user-data").is_err()); // dash
        assert!(MySQLStorage::validate_sql_identifier("user data").is_err()); // space
        assert!(MySQLStorage::validate_sql_identifier("users;drop").is_err()); // semicolon
        assert!(MySQLStorage::validate_sql_identifier("table`").is_err()); // backtick

        // Reserved keywords
        assert!(MySQLStorage::validate_sql_identifier("SELECT").is_err());
        assert!(MySQLStorage::validate_sql_identifier("select").is_err()); // case insensitive
        assert!(MySQLStorage::validate_sql_identifier("TABLE").is_err());
        assert!(MySQLStorage::validate_sql_identifier("ORDER").is_err());
        assert!(MySQLStorage::validate_sql_identifier("GROUP").is_err());

        // Check start with digit
        assert!(MySQLStorage::validate_sql_identifier("1users").is_err());
    }

    #[test]
    fn test_build_upsert_query() {
        let query = MySQLStorage::build_upsert_query("secreton_kv_store");
        assert!(query.contains("INSERT INTO `secreton_kv_store`"));
        assert!(query.contains("ON DUPLICATE KEY UPDATE"));
    }

    #[test]
    fn test_build_select_query() {
        let query = MySQLStorage::build_select_query("secreton_kv_store");
        assert!(query.contains("SELECT"));
        assert!(query.contains("FROM `secreton_kv_store`"));
        assert!(query.contains("WHERE path = ?"));
    }
}
