use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::{NaiveDateTime, Utc};
use mysql_async::prelude::*;
use secreton_common::models::oauth_state::OAuthState;
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
    pool: mysql_async::Pool,
    cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

/// MySQL transaction implementation
pub struct MySQLTransaction {
    pool: mysql_async::Pool,
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
        pool: mysql_async::Pool,
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
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut tx = conn
            .start_transaction(mysql_async::TxOpts::default())
            .await
            .map_err(|e| StorageError::TransactionFailed {
                message: format!("Failed to start transaction: {}", e),
            })?;

        // Cache updates to apply after successful commit
        let mut cache_inserts = Vec::new();
        let mut cache_removals = Vec::new();

        // Batch operations
        let mut upsert_params = Vec::new();
        let mut delete_ids = Vec::new();

        for op in &self.operations {
            match op {
                MySQLOperation::Store(entry) | MySQLOperation::Update(entry) => {
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

                    upsert_params.push((
                        entry.id.to_string(),
                        entry.path.clone(),
                        entry.encrypted_data.clone(),
                        encryption_metadata_json,
                        entry.security_level as u8,
                        metadata_json,
                        tags_json,
                        entry.version,
                        entry.owner_id.to_string(),
                        entry.created_at.naive_utc(),
                        entry.updated_at.naive_utc(),
                        expires_at,
                    ));

                    cache_inserts.push(entry.clone());
                }
                MySQLOperation::Delete(id) => {
                    delete_ids.push(id);
                }
            }
        }

        // Execute batch upserts
        if !upsert_params.is_empty() {
            let query = MySQLStorage::build_upsert_query(&self.table_name);
            tx.exec_batch(query, upsert_params)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to execute batch upsert: {}", e),
                })?;
        }

        // Execute batch deletes
        if !delete_ids.is_empty() {
            // 1. Get paths for cache invalidation
            let select_query =
                MySQLStorage::build_select_paths_query(&self.table_name, delete_ids.len());

            let delete_id_params: Vec<mysql_async::Value> = delete_ids
                .iter()
                .map(|id| mysql_async::Value::from(id.to_string()))
                .collect();

            let paths: Vec<String> = tx
                .exec(select_query, delete_id_params.clone())
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to query paths for deletion: {}", e),
                })?;

            cache_removals.extend(paths);

            // 2. Delete entries
            let delete_query =
                MySQLStorage::build_delete_ids_query(&self.table_name, delete_ids.len());
            tx.exec_drop(delete_query, delete_id_params)
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to execute batch delete: {}", e),
                })?;
        }

        tx.commit()
            .await
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

        let opts = mysql_async::Opts::from_url(&config.connection_string).map_err(|e| {
            StorageError::ConnectionFailed {
                message: format!("Invalid MySQL URL: {}", e),
            }
        })?;
        let pool = mysql_async::Pool::new(opts);

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
        pool: &mysql_async::Pool,
        table_name: &str,
    ) -> Result<(), StorageError> {
        let mut conn = pool
            .get_conn()
            .await
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
            .await
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

    /// Build MySQL query for listing entries with filters
    fn build_list_query(
        table_name: &str,
        params: &QueryParams,
    ) -> (String, Vec<mysql_async::Value>) {
        let mut query = format!(
            "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM `{}`",
            table_name
        );
        let mut where_clauses = Vec::new();
        let mut values: Vec<mysql_async::Value> = Vec::new();

        if let Some(prefix) = &params.path_prefix {
            if !prefix.is_empty() {
                where_clauses.push("path LIKE ?");
                values.push(mysql_async::Value::from(format!("{}%", prefix)));
            }
        }

        if let Some(owner_id) = params.owner_id {
            where_clauses.push("owner_id = ?");
            values.push(mysql_async::Value::from(owner_id.to_string()));
        }

        if !params.include_expired {
            // entry.is_expired() checks if expires_at is some and <= now.
            // So we want (expires_at IS NULL OR expires_at > NOW())
            where_clauses.push("(expires_at IS NULL OR expires_at > NOW())");
        }

        if !where_clauses.is_empty() {
            query.push_str(" WHERE ");
            query.push_str(&where_clauses.join(" AND "));
        }

        query.push_str(" ORDER BY path");

        if let Some(limit) = params.limit {
            query.push_str(" LIMIT ?");
            values.push(mysql_async::Value::from(limit));
        }

        (query, values)
    }

    /// Build MySQL query for selecting paths by multiple IDs
    fn build_select_paths_query(table_name: &str, num_ids: usize) -> String {
        let placeholders = vec!["?"; num_ids].join(",");
        format!(
            "SELECT path FROM `{}` WHERE id IN ({})",
            table_name, placeholders
        )
    }

    /// Build MySQL query for deleting entries by multiple IDs
    fn build_delete_ids_query(table_name: &str, num_ids: usize) -> String {
        let placeholders = vec!["?"; num_ids].join(",");
        format!("DELETE FROM `{}` WHERE id IN ({})", table_name, placeholders)
    }
}

#[async_trait]
impl StorageBackend for MySQLStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let mut conn = self
            .pool
            .get_conn()
            .await
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
        .await
        .map_err(|e| StorageError::BackendError {
            backend: "mysql".to_string(),
            message: format!("Failed to store entry: {}", e),
        })?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entry.path.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = format!(
            "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM `{}` WHERE id = ?",
            self.config.table_name
        );

        let rows: Vec<mysql_async::Row> =
            conn.exec(&query, (id.to_string(),))
                .await
                .map_err(|e| StorageError::BackendError {
                    backend: "mysql".to_string(),
                    message: format!("Failed to query entry by id: {}", e),
                })?;

        if let Some(row) = rows.first() {
            let entry = MySQLStorage::row_to_secreton_entry(row)?;
            // Update cache since we have the full entry
            let mut cache = self.cache.write().await;
            cache.insert(entry.path.clone(), entry.clone());
            Ok(Some(entry))
        } else {
            Ok(None)
        }
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
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = MySQLStorage::build_select_query(&self.config.table_name);

        let rows: Vec<mysql_async::Row> =
            conn.exec(&query, (path,))
                .await
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

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        // First get the path to remove from cache
        let select_query = format!("SELECT path FROM `{}` WHERE id = ?", self.config.table_name);
        let rows: Vec<mysql_async::Row> = conn
            .exec(&select_query, (id.to_string(),))
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to query path for deletion: {}", e),
            })?;

        let path: Option<String> = rows.first().and_then(|row| row.get(0));

        // Delete the entry
        let delete_query = format!("DELETE FROM `{}` WHERE id = ?", self.config.table_name);
        conn.exec_drop(&delete_query, (id.to_string(),))
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to delete entry: {}", e),
            })?;

        let affected = conn.affected_rows() > 0;

        if affected {
            if let Some(p) = path {
                let mut cache = self.cache.write().await;
                cache.remove(&p);
            }
        }

        Ok(affected)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let mut conn = self
            .pool
            .get_conn()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = MySQLStorage::build_delete_query(&self.config.table_name);

        conn.exec_drop(&query, (path,))
            .await
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
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let (query, values) = MySQLStorage::build_list_query(&self.config.table_name, params);

        let rows: Vec<mysql_async::Row> = conn
            .exec(&query, values)
            .await
            .map_err(|e| StorageError::BackendError {
                backend: "mysql".to_string(),
                message: format!("Failed to list entries: {}", e),
            })?;

        let mut entries = Vec::new();
        for row in rows {
            let entry = MySQLStorage::row_to_secreton_entry(&row)?;
            entries.push(entry);
        }

        Ok(entries)
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

        // mysql_async doesn't have a direct health check, but we can try to get a connection
        let result = self.pool.get_conn().await;

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

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "MySQL".to_string(), message: "Not implemented".to_string() })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError { backend: "MySQL".to_string(), message: "Not implemented".to_string() })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}

impl MySQLStorage {
    /// Convert MySQL row to SecretEntry
    fn row_to_secreton_entry(row: &mysql_async::Row) -> Result<SecretEntry, StorageError> {
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
            2 => crate::SecurityLevel::Confidential,
            3 => crate::SecurityLevel::Secret,
            4 => crate::SecurityLevel::TopSecret,
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

    #[test]
    fn test_build_list_query_filters() {
        let owner = Uuid::new_v4();
        let params = QueryParams::new()
            .with_path_prefix("apps/".to_string())
            .with_owner(owner)
            .with_limit(50);
        // include_expired is false by default in QueryParams::default/new

        let (query, values) = MySQLStorage::build_list_query("secreton_kv_store", &params);

        assert!(query.contains("SELECT"));
        assert!(query.contains("FROM `secreton_kv_store`"));
        assert!(query.contains("WHERE"));

        // Verify filters are in the query
        assert!(query.contains("path LIKE ?"));
        assert!(query.contains("owner_id = ?"));
        assert!(query.contains("(expires_at IS NULL OR expires_at > NOW())"));
        assert!(query.contains("LIMIT ?"));

        // Verify values
        // Order of addition: prefix, owner_id, limit
        // 1. prefix
        // 2. owner_id
        // 3. limit
        assert_eq!(values.len(), 3);
        assert_eq!(values[0], mysql_async::Value::from("apps/%"));
        assert_eq!(values[1], mysql_async::Value::from(owner.to_string()));
        assert_eq!(values[2], mysql_async::Value::from(50u32));
    }

    #[test]
    fn test_build_list_query_no_filters() {
        let params = QueryParams::new().with_path_prefix("".to_string());
        // include_expired false by default

        let (query, values) = MySQLStorage::build_list_query("secreton_kv_store", &params);

        assert!(query.contains("WHERE")); // because of expiry check
        assert!(query.contains("(expires_at IS NULL OR expires_at > NOW())"));
        assert!(!query.contains("path LIKE"));
        assert!(!query.contains("owner_id ="));

        assert_eq!(values.len(), 0);
    }

    #[test]
    fn test_build_list_query_include_expired() {
        let mut params = QueryParams::new();
        params.include_expired = true;

        let (query, values) = MySQLStorage::build_list_query("secreton_kv_store", &params);

        assert!(!query.contains("WHERE")); // No filters at all
        assert_eq!(values.len(), 0);
    }

    #[test]
    fn test_build_select_paths_query() {
        let query = MySQLStorage::build_select_paths_query("table", 3);
        assert!(query.contains("SELECT path FROM `table` WHERE id IN (?,?,?)"));
    }

    #[test]
    fn test_build_delete_ids_query() {
        let query = MySQLStorage::build_delete_ids_query("table", 2);
        assert!(query.contains("DELETE FROM `table` WHERE id IN (?,?)"));

    }
}
