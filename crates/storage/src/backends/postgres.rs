//! PostgreSQL storage backend implementation using tokio-postgres

use crate::{
    HealthStatus, QueryParams, SecurityLevel, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction, VaultEntry,
};
use async_trait::async_trait;
use deadpool_postgres::{Config, Pool, Runtime};
use std::sync::Arc;
use tokio_postgres::{NoTls, Row};
use uuid::Uuid;

/// PostgreSQL storage backend
pub struct PostgresBackend {
    pool: Arc<Pool>,
}

impl PostgresBackend {
    /// Create a new PostgreSQL backend
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        let mut cfg = Config::new();
        cfg.url = Some(database_url.to_string());
        let pool = cfg.create_pool(Some(Runtime::Tokio1), NoTls).map_err(|e| {
            StorageError::ConnectionFailed {
                message: format!("Failed to create PostgreSQL pool: {}", e),
            }
        })?;

        Ok(Self { pool: Arc::new(pool) })
    }

    /// Get the connection pool
    pub fn pool(&self) -> &Arc<Pool> {
        &self.pool
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            INSERT INTO vault_entries 
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;

        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        client
            .execute(
                query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &entry.tags,
                    &(entry.version as i32),
                    &entry.owner_id,
                    &entry.created_at,
                    &entry.updated_at,
                    &entry.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store vault entry: {}", e),
            })?;

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM vault_entries 
            WHERE id = $1
        "#;

        let rows = client
            .query(query, &[&id])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to query vault entry: {}", e),
            })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        let entry = self.row_to_vault_entry(row)?;
        Ok(Some(entry))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM vault_entries 
            WHERE path = $1
        "#;

        let rows = client
            .query(query, &[&path])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to query vault entry: {}", e),
            })?;

        if rows.is_empty() {
            return Ok(None);
        }

        let row = &rows[0];
        let entry = self.row_to_vault_entry(row)?;
        Ok(Some(entry))
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut query = "SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at FROM vault_entries WHERE 1=1".to_string();
        let mut bind_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_count = 1;

        if let Some(prefix) = &params.path_prefix {
            query.push_str(&format!(" AND path LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        if let Some(owner) = &params.owner_id {
            query.push_str(&format!(" AND owner_id = ${}", param_count));
            bind_params.push(Box::new(*owner));
            param_count += 1;
        }

        query.push_str(&format!(" ORDER BY created_at DESC LIMIT ${}", param_count));
        let limit = params.limit.unwrap_or(100);
        bind_params.push(Box::new(limit as i64));

        let bind_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = bind_params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let rows =
            client
                .query(&query, &bind_refs)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to list vault entries: {}", e),
                })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(self.row_to_vault_entry(&row)?);
        }

        Ok(entries)
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = r#"
            UPDATE vault_entries 
            SET path = $2, encrypted_data = $3, encryption_metadata = $4, security_level = $5, 
                metadata = $6, tags = $7, version = $8, updated_at = $9, expires_at = $10
            WHERE id = $1
        "#;

        let encryption_metadata_json =
            serde_json::to_value(&entry.encryption_metadata).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to serialize encryption metadata: {}", e),
                }
            })?;

        let metadata_json = serde_json::to_value(&entry.metadata).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            }
        })?;

        let rows_affected = client
            .execute(
                query,
                &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &entry.tags,
                    &(entry.version as i32),
                    &entry.updated_at,
                    &entry.expires_at,
                ],
            )
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to update vault entry: {}", e),
            })?;

        if rows_affected == 0 {
            return Err(StorageError::NotFound {
                resource_type: "VaultEntry".to_string(),
                id: entry.id.to_string(),
            });
        }

        Ok(())
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "DELETE FROM vault_entries WHERE id = $1";

        let rows_affected =
            client
                .execute(query, &[&id])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete vault entry: {}", e),
                })?;

        Ok(rows_affected > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "DELETE FROM vault_entries WHERE path = $1";

        let rows_affected =
            client
                .execute(query, &[&path])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete vault entry: {}", e),
                })?;

        Ok(rows_affected > 0)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let mut query = "SELECT COUNT(*) FROM vault_entries WHERE 1=1".to_string();
        let mut bind_params: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_count = 1;

        if let Some(prefix) = &params.path_prefix {
            query.push_str(&format!(" AND path LIKE ${}", param_count));
            let prefix_pattern = format!("{}%", prefix);
            bind_params.push(Box::new(prefix_pattern));
            param_count += 1;
        }

        if let Some(owner) = &params.owner_id {
            query.push_str(&format!(" AND owner_id = ${}", param_count));
            bind_params.push(Box::new(*owner));
        }

        let bind_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = bind_params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();
        let rows =
            client
                .query(&query, &bind_refs)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to count vault entries: {}", e),
                })?;

        let count: i64 = rows[0].get(0);
        Ok(count as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let query = "SELECT EXISTS(SELECT 1 FROM vault_entries WHERE path = $1)";
        let rows = client
            .query(query, &[&path])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to check existence: {}", e),
            })?;

        let exists: bool = rows[0].get(0);
        Ok(exists)
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        client
            .query("SELECT 1", &[])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Health check failed: {}", e),
            })?;

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
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let count_query = "SELECT COUNT(*) FROM vault_entries";
        let size_query = "SELECT pg_total_relation_size('vault_entries')";

        let count_rows =
            client
                .query(count_query, &[])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get entry count: {}", e),
                })?;

        let size_rows =
            client
                .query(size_query, &[])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get storage size: {}", e),
                })?;

        let total_entries: i64 = count_rows[0].get(0);
        let storage_size: i64 = size_rows[0].get(0);

        Ok(StorageStats {
            total_entries: total_entries as u64,
            total_size_bytes: storage_size as u64,
            average_entry_size: if total_entries > 0 {
                storage_size as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: std::collections::HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction + 'static>> {
        Ok(Box::new(PostgresTransaction::new(Arc::clone(&self.pool))))
    }

    async fn migrate(&self) -> StorageResult<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to get connection: {}", e),
            })?;

        let create_table_query = r#"
            CREATE TABLE IF NOT EXISTS vault_entries (
                id UUID PRIMARY KEY,
                path VARCHAR NOT NULL UNIQUE,
                encrypted_data BYTEA NOT NULL,
                encryption_metadata JSONB NOT NULL,
                security_level INTEGER NOT NULL,
                metadata JSONB NOT NULL,
                tags TEXT[] NOT NULL,
                version INTEGER NOT NULL,
                owner_id UUID NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                expires_at TIMESTAMPTZ
            );
            CREATE INDEX IF NOT EXISTS idx_vault_entries_path ON vault_entries(path);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_owner ON vault_entries(owner_id);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_security_level ON vault_entries(security_level);
        "#;

        client
            .batch_execute(create_table_query)
            .await
            .map_err(|e| StorageError::MigrationError {
                message: format!("Failed to run migrations: {}", e),
            })?;

        Ok(())
    }
}

impl PostgresBackend {
    fn row_to_vault_entry(&self, row: &Row) -> StorageResult<VaultEntry> {
        let encryption_metadata_value: serde_json::Value = row.get("encryption_metadata");
        let encryption_metadata =
            serde_json::from_value(encryption_metadata_value).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to deserialize encryption metadata: {}", e),
                }
            })?;

        let metadata_value: serde_json::Value = row.get("metadata");
        let metadata = serde_json::from_value(metadata_value).map_err(|e| {
            StorageError::SerializationError {
                message: format!("Failed to deserialize metadata: {}", e),
            }
        })?;

        let security_level_int: i32 = row.get("security_level");
        let security_level = match security_level_int {
            0 => SecurityLevel::Public,
            1 => SecurityLevel::Internal,
            2 => SecurityLevel::Confidential,
            3 => SecurityLevel::Secret,
            4 => SecurityLevel::TopSecret,
            _ => SecurityLevel::Internal,
        };

        Ok(VaultEntry {
            id: row.get("id"),
            path: row.get("path"),
            encrypted_data: row.get("encrypted_data"),
            encryption_metadata,
            security_level,
            metadata,
            tags: row.get("tags"),
            version: row.get::<_, i32>("version") as u32,
            owner_id: row.get("owner_id"),
            created_at: row.get("created_at"),
            updated_at: row.get("updated_at"),
            expires_at: row.get("expires_at"),
        })
    }
}

/// PostgreSQL transaction implementation
pub struct PostgresTransaction {
    pool: Arc<Pool>,
    operations: Vec<PostgresOperation>,
    committed: bool,
}

enum PostgresOperation {
    Store(VaultEntry),
    Update(VaultEntry),
    Delete(Uuid),
}

impl PostgresTransaction {
    pub fn new(pool: Arc<Pool>) -> Self {
        Self {
            pool,
            operations: Vec::new(),
            committed: false,
        }
    }

    async fn execute_operation(&self, transaction: &deadpool_postgres::Transaction<'_>, op: &PostgresOperation) -> StorageResult<()> {
        match op {
            PostgresOperation::Store(entry) => {
                let query = r#"
                    INSERT INTO vault_entries
                    (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                    ON CONFLICT (id) DO UPDATE SET
                        path = EXCLUDED.path,
                        encrypted_data = EXCLUDED.encrypted_data,
                        encryption_metadata = EXCLUDED.encryption_metadata,
                        security_level = EXCLUDED.security_level,
                        metadata = EXCLUDED.metadata,
                        tags = EXCLUDED.tags,
                        version = EXCLUDED.version,
                        owner_id = EXCLUDED.owner_id,
                        updated_at = EXCLUDED.updated_at,
                        expires_at = EXCLUDED.expires_at
                "#;

                let metadata_json = serde_json::to_value(&entry.metadata).unwrap_or(serde_json::Value::Null);
                let tags_json = serde_json::to_value(&entry.tags).unwrap_or(serde_json::Value::Null);
                let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata).unwrap_or(serde_json::Value::Null);

                transaction.execute(query, &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &tags_json,
                    &(entry.version as i32),
                    &entry.owner_id,
                    &entry.created_at.naive_utc(),
                    &entry.updated_at.naive_utc(),
                    &entry.expires_at.map(|dt| dt.naive_utc()),
                ]).await.map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to store entry: {}", e),
                })?;
            }
            PostgresOperation::Update(entry) => {
                let query = r#"
                    UPDATE vault_entries SET
                        path = $2,
                        encrypted_data = $3,
                        encryption_metadata = $4,
                        security_level = $5,
                        metadata = $6,
                        tags = $7,
                        version = $8,
                        owner_id = $9,
                        updated_at = $10,
                        expires_at = $11
                    WHERE id = $1
                "#;

                let metadata_json = serde_json::to_value(&entry.metadata).unwrap_or(serde_json::Value::Null);
                let tags_json = serde_json::to_value(&entry.tags).unwrap_or(serde_json::Value::Null);
                let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata).unwrap_or(serde_json::Value::Null);

                transaction.execute(query, &[
                    &entry.id,
                    &entry.path,
                    &entry.encrypted_data,
                    &encryption_metadata_json,
                    &(entry.security_level as i32),
                    &metadata_json,
                    &tags_json,
                    &(entry.version as i32),
                    &entry.owner_id,
                    &entry.updated_at.naive_utc(),
                    &entry.expires_at.map(|dt| dt.naive_utc()),
                ]).await.map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to update entry: {}", e),
                })?;
            }
            PostgresOperation::Delete(id) => {
                let query = "DELETE FROM vault_entries WHERE id = $1";
                transaction.execute(query, &[id]).await.map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete entry: {}", e),
                })?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StorageTransaction for PostgresTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(PostgresOperation::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(PostgresOperation::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(PostgresOperation::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // Execute all operations in a database transaction
        let mut client = self.pool.get().await.map_err(|e| StorageError::ConnectionFailed {
            message: format!("Failed to get connection for transaction: {}", e),
        })?;

        let transaction = client.transaction().await.map_err(|e| StorageError::TransactionFailed {
            message: format!("Failed to begin transaction: {}", e),
        })?;

        for op in &self.operations {
            self.execute_operation(&transaction, op).await?;
        }

        transaction.commit().await.map_err(|e| StorageError::TransactionFailed {
            message: format!("Failed to commit transaction: {}", e),
        })?;

        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}
