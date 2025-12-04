use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio_postgres::{Client, NoTls};
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, SecretEntry, SecurityLevel, StorageBackend, StorageError,
    StorageResult, StorageStats, StorageTransaction,
};

/// Configuration for CockroachDB storage backend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CockroachDBConfig {
    /// Database connection URL
    pub connection_string: String,
    /// Database name
    pub database_name: String,
    /// Connection pool settings
    pub max_connections: u32,
}

/// CockroachDB storage backend implementation
pub struct CockroachDBStorage {
    _config: CockroachDBConfig,
    client: Client,
}

/// CockroachDB transaction implementation
pub struct CockroachDBTransaction {
    operations: Vec<CockroachDBOperation>,
    committed: bool,
}

enum CockroachDBOperation {
    Store(()),
    Update(()),
    Delete(()),
}

impl Default for CockroachDBTransaction {
    fn default() -> Self {
        Self::new()
    }
}

impl CockroachDBTransaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for CockroachDBTransaction {
    async fn store(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(CockroachDBOperation::Store(()));
        Ok(())
    }

    async fn update(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(CockroachDBOperation::Update(()));
        Ok(())
    }

    async fn delete(&mut self, _id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(CockroachDBOperation::Delete(()));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real CockroachDB implementation, you would execute all operations
        // in a CockroachDB transaction (PostgreSQL-compatible)
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl CockroachDBStorage {
    /// Create a new CockroachDB storage instance
    pub async fn new(config: CockroachDBConfig) -> StorageResult<Self> {
        // Parse connection string and connect
        let (client, connection) = tokio_postgres::connect(&config.connection_string, NoTls)
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to CockroachDB: {}", e),
            })?;

        // Spawn connection in background
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                eprintln!("CockroachDB connection error: {}", e);
            }
        });

        // Create vault_entries table if it doesn't exist
        Self::create_tables(&client).await?;

        Ok(Self {
            _config: config,
            client,
        })
    }

    async fn create_tables(client: &Client) -> StorageResult<()> {
        // Create vault_entries table with CockroachDB-specific optimizations
        let create_table_query = r#"
            CREATE TABLE IF NOT EXISTS vault_entries (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                path STRING NOT NULL UNIQUE,
                encrypted_data BYTES NOT NULL,
                encryption_metadata JSONB NOT NULL,
                security_level INT2 NOT NULL,
                metadata JSONB DEFAULT '{}',
                tags STRING[] DEFAULT ARRAY[],
                version INT4 NOT NULL DEFAULT 1,
                owner_id UUID NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                expires_at TIMESTAMPTZ,
                INDEX idx_path (path),
                INDEX idx_owner_id (owner_id),
                INDEX idx_security_level (security_level),
                INDEX idx_created_at (created_at),
                INDEX idx_expires_at (expires_at),
                FAMILY data (encrypted_data, encryption_metadata),
                FAMILY metadata (metadata, tags, version),
                FAMILY timestamps (created_at, updated_at, expires_at)
            )
        "#;

        client
            .execute(create_table_query, &[])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to create vault_entries table: {}", e),
            })?;

        Ok(())
    }

    fn vault_entry_to_params<'a>(
        entry: &'a SecretEntry,
    ) -> Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync + 'a>> {
        vec![
            Box::new(entry.id),
            Box::new(&entry.path),
            Box::new(&entry.encrypted_data),
            Box::new(serde_json::to_value(&entry.encryption_metadata).unwrap_or_default()),
            Box::new(entry.security_level as i16),
            Box::new(serde_json::to_value(&entry.metadata).unwrap_or_default()),
            Box::new(&entry.tags),
            Box::new(entry.version as i32),
            Box::new(entry.owner_id),
            Box::new(entry.created_at),
            Box::new(entry.updated_at),
            Box::new(entry.expires_at),
        ]
    }

    fn row_to_vault_entry(row: &tokio_postgres::Row) -> StorageResult<SecretEntry> {
        let id: Uuid = row.get(0);
        let path: String = row.get(1);
        let encrypted_data: Vec<u8> = row.get(2);
        let encryption_metadata_json: serde_json::Value = row.get(3);
        let security_level_int: i16 = row.get(4);
        let metadata_json: serde_json::Value = row.get(5);
        let tags: Vec<String> = row.get(6);
        let version: i32 = row.get(7);
        let owner_id: Uuid = row.get(8);
        let created_at: DateTime<Utc> = row.get(9);
        let updated_at: DateTime<Utc> = row.get(10);
        let expires_at: Option<DateTime<Utc>> = row.get(11);

        let encryption_metadata: crate::EncryptionMetadata =
            serde_json::from_value(encryption_metadata_json).map_err(|e| {
                StorageError::SerializationError {
                    message: format!("Failed to deserialize encryption metadata: {}", e),
                }
            })?;

        let metadata: HashMap<String, String> =
            serde_json::from_value(metadata_json).unwrap_or_default();

        let security_level = match security_level_int {
            0 => SecurityLevel::Public,
            1 => SecurityLevel::Internal,
            2 => SecurityLevel::Confidential,
            3 => SecurityLevel::Secret,
            4 => SecurityLevel::TopSecret,
            _ => SecurityLevel::Secret,
        };

        Ok(SecretEntry {
            id,
            path,
            encrypted_data,
            encryption_metadata,
            security_level,
            metadata,
            tags,
            version: version as u32,
            owner_id,
            created_at,
            updated_at,
            expires_at,
        })
    }
}

#[async_trait]
impl StorageBackend for CockroachDBStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let params = Self::vault_entry_to_params(entry);
        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = params
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let query = r#"
            INSERT INTO vault_entries
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (path) DO UPDATE SET
                encrypted_data = EXCLUDED.encrypted_data,
                encryption_metadata = EXCLUDED.encryption_metadata,
                security_level = EXCLUDED.security_level,
                metadata = EXCLUDED.metadata,
                tags = EXCLUDED.tags,
                version = EXCLUDED.version,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at
        "#;

        self.client
            .execute(query, &params_refs)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store entry: {}", e),
            })?;

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let query = "SELECT * FROM vault_entries WHERE id = $1";
        let rows =
            self.client
                .query(query, &[&id])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to query by ID: {}", e),
                })?;

        if let Some(row) = rows.first() {
            Ok(Some(Self::row_to_vault_entry(row)?))
        } else {
            Ok(None)
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let query = "SELECT * FROM vault_entries WHERE path = $1";
        let rows =
            self.client
                .query(query, &[&path])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to query by path: {}", e),
                })?;

        if let Some(row) = rows.first() {
            Ok(Some(Self::row_to_vault_entry(row)?))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let query = "DELETE FROM vault_entries WHERE id = $1";
        let result =
            self.client
                .execute(query, &[&id])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete by ID: {}", e),
                })?;

        Ok(result > 0)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let query = "DELETE FROM vault_entries WHERE path = $1";
        let result =
            self.client
                .execute(query, &[&path])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to delete by path: {}", e),
                })?;

        Ok(result > 0)
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_index = 1;

        if let Some(ref prefix) = params.path_prefix {
            conditions.push(format!("path LIKE ${} || '%'", param_index));
            param_values.push(Box::new(prefix.clone()));
            param_index += 1;
        }

        if let Some(owner_id) = params.owner_id {
            conditions.push(format!("owner_id = ${}", param_index));
            param_values.push(Box::new(owner_id));
            param_index += 1;
        }

        if let Some(security_level) = params.security_level {
            conditions.push(format!("security_level >= ${}", param_index));
            param_values.push(Box::new(security_level as i16));
            param_index += 1;
        }

        if !params.include_expired {
            conditions.push(format!(
                "(expires_at IS NULL OR expires_at > ${})",
                param_index
            ));
            param_values.push(Box::new(Utc::now()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let limit_clause = if let Some(limit) = params.limit {
            format!("LIMIT {}", limit)
        } else {
            String::new()
        };

        let query = format!(
            "SELECT * FROM vault_entries {} {}",
            where_clause, limit_clause
        );
        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = param_values
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let rows = self.client.query(&query, &params_refs).await.map_err(|e| {
            StorageError::QueryFailed {
                message: format!("Failed to list entries: {}", e),
            }
        })?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(Self::row_to_vault_entry(&row)?);
        }

        Ok(entries)
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let mut conditions = Vec::new();
        let mut param_values: Vec<Box<dyn tokio_postgres::types::ToSql + Send + Sync>> = Vec::new();
        let mut param_index = 1;

        if let Some(ref prefix) = params.path_prefix {
            conditions.push(format!("path LIKE ${} || '%'", param_index));
            param_values.push(Box::new(prefix.clone()));
            param_index += 1;
        }

        if let Some(owner_id) = params.owner_id {
            conditions.push(format!("owner_id = ${}", param_index));
            param_values.push(Box::new(owner_id));
            param_index += 1;
        }

        if let Some(security_level) = params.security_level {
            conditions.push(format!("security_level >= ${}", param_index));
            param_values.push(Box::new(security_level as i16));
            param_index += 1;
        }

        if !params.include_expired {
            conditions.push(format!(
                "(expires_at IS NULL OR expires_at > ${})",
                param_index
            ));
            param_values.push(Box::new(Utc::now()));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

        let query = format!("SELECT COUNT(*) FROM vault_entries {}", where_clause);
        let params_refs: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = param_values
            .iter()
            .map(|b| &**b as &(dyn tokio_postgres::types::ToSql + Sync))
            .collect();

        let rows = self.client.query(&query, &params_refs).await.map_err(|e| {
            StorageError::QueryFailed {
                message: format!("Failed to count entries: {}", e),
            }
        })?;

        let count: i64 = rows[0].get(0);
        Ok(count as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let query = "SELECT 1 FROM vault_entries WHERE path = $1 LIMIT 1";
        let rows =
            self.client
                .query(query, &[&path])
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to check existence: {}", e),
                })?;

        Ok(!rows.is_empty())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(CockroachDBTransaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        let query = "SELECT 1";
        match self.client.execute(query, &[]).await {
            Ok(_) => {
                let duration = start.elapsed().as_millis() as f64;
                Ok(HealthStatus {
                    is_healthy: true,
                    response_time_ms: duration,
                    connections_active: 1,
                    connections_idle: 0,
                    last_error: None,
                    uptime_seconds: 0,
                })
            }
            Err(e) => {
                let duration = start.elapsed().as_millis() as f64;
                Ok(HealthStatus {
                    is_healthy: false,
                    response_time_ms: duration,
                    connections_active: 0,
                    connections_idle: 0,
                    last_error: Some(e.to_string()),
                    uptime_seconds: 0,
                })
            }
        }
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let query = "SELECT COUNT(*), SUM(octet_length(encrypted_data)) FROM vault_entries";
        let rows = self
            .client
            .query(query, &[])
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to get stats: {}", e),
            })?;

        let total_entries: i64 = rows[0].get(0);
        let total_size_bytes: Option<i64> = rows[0].get(1);

        Ok(StorageStats {
            total_entries: total_entries as u64,
            total_size_bytes: total_size_bytes.unwrap_or(0) as u64,
            average_entry_size: if total_entries > 0 {
                total_size_bytes.unwrap_or(0) as f64 / total_entries as f64
            } else {
                0.0
            },
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        // CockroachDB migrations would be implemented here
        Ok(())
    }
}

impl Default for CockroachDBConfig {
    fn default() -> Self {
        Self {
            connection_string: "postgresql://root@localhost:26257/defaultdb?sslmode=disable"
                .to_string(),
            database_name: "defaultdb".to_string(),
            max_connections: 10,
        }
    }
}
