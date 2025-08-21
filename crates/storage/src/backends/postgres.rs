//! PostgreSQL storage backend implementation

use crate::{StorageBackend, StorageResult, StorageError, VaultEntry, QueryParams, StorageTransaction, HealthStatus, StorageStats, SecurityLevel};
use async_trait::async_trait;
use sqlx::{PgPool, Row};
use uuid::Uuid;
use std::collections::HashMap;

/// PostgreSQL storage backend
pub struct PostgresBackend {
    pool: PgPool,
}

impl PostgresBackend {
    /// Create a new PostgreSQL backend
    pub async fn new(database_url: &str) -> StorageResult<Self> {
        let pool = PgPool::connect(database_url)
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to PostgreSQL: {}", e),
            })?;
        
        Ok(Self { pool })
    }
    
    /// Get the connection pool
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl StorageBackend for PostgresBackend {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let query = r#"
            INSERT INTO vault_entries 
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#;
        
        let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize encryption metadata: {}", e),
            })?;
        
        let metadata_json = serde_json::to_value(&entry.metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;
        
        sqlx::query(query)
            .bind(&entry.id)
            .bind(&entry.path)
            .bind(&entry.encrypted_data)
            .bind(encryption_metadata_json)
            .bind(entry.security_level as i32)
            .bind(metadata_json)
            .bind(&entry.tags)
            .bind(entry.version as i32)
            .bind(&entry.owner_id)
            .bind(&entry.created_at)
            .bind(&entry.updated_at)
            .bind(&entry.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store vault entry: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM vault_entries 
            WHERE id = $1 AND (expires_at IS NULL OR expires_at > NOW())
        "#;
        
        let row = sqlx::query(query)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to get vault entry by ID: {}", e),
            })?;
        
        if let Some(row) = row {
            let entry = row_to_vault_entry(row)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }
    
    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        let query = r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM vault_entries 
            WHERE path = $1 AND (expires_at IS NULL OR expires_at > NOW())
        "#;
        
        let row = sqlx::query(query)
            .bind(path)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to get vault entry by path: {}", e),
            })?;
        
        if let Some(row) = row {
            let entry = row_to_vault_entry(row)?;
            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }
    
    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        let query = r#"
            UPDATE vault_entries 
            SET encrypted_data = $2, encryption_metadata = $3, security_level = $4, metadata = $5, tags = $6, version = $7, updated_at = $8, expires_at = $9
            WHERE id = $1
        "#;
        
        let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize encryption metadata: {}", e),
            })?;
        
        let metadata_json = serde_json::to_value(&entry.metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;
        
        let result = sqlx::query(query)
            .bind(&entry.id)
            .bind(&entry.encrypted_data)
            .bind(encryption_metadata_json)
            .bind(entry.security_level as i32)
            .bind(metadata_json)
            .bind(&entry.tags)
            .bind(entry.version as i32)
            .bind(&entry.updated_at)
            .bind(&entry.expires_at)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to update vault entry: {}", e),
            })?;
        
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound {
                resource_type: "VaultEntry".to_string(),
                id: entry.id.to_string(),
            });
        }
        
        Ok(())
    }
    
    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        let query = "DELETE FROM vault_entries WHERE id = $1";
        
        let result = sqlx::query(query)
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete vault entry: {}", e),
            })?;
        
        Ok(result.rows_affected() > 0)
    }
    
    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let query = "DELETE FROM vault_entries WHERE path = $1";
        
        let result = sqlx::query(query)
            .bind(path)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete vault entry: {}", e),
            })?;
        
        Ok(result.rows_affected() > 0)
    }
    
    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let mut query = String::from(r#"
            SELECT id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at
            FROM vault_entries 
            WHERE 1=1
        "#);
        
        if !params.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }
        
        if let Some(ref prefix) = params.path_prefix {
            query.push_str(&format!(" AND path LIKE '{}%'", prefix));
        }
        
        if let Some(security_level) = params.security_level {
            query.push_str(&format!(" AND security_level >= {}", security_level as i32));
        }
        
        if let Some(ref owner_id) = params.owner_id {
            query.push_str(&format!(" AND owner_id = '{}'", owner_id));
        }
        
        if let Some(limit) = params.limit {
            query.push_str(&format!(" LIMIT {}", limit));
        }
        
        if let Some(offset) = params.offset {
            query.push_str(&format!(" OFFSET {}", offset));
        }
        
        let rows = sqlx::query(&query)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to list vault entries: {}", e),
            })?;
        
        let entries = rows.into_iter()
            .map(row_to_vault_entry)
            .collect::<StorageResult<Vec<_>>>()?;
        
        Ok(entries)
    }
    
    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        let mut query = String::from("SELECT COUNT(*) FROM vault_entries WHERE 1=1");
        
        if !params.include_expired {
            query.push_str(" AND (expires_at IS NULL OR expires_at > NOW())");
        }
        
        if let Some(ref prefix) = params.path_prefix {
            query.push_str(&format!(" AND path LIKE '{}%'", prefix));
        }
        
        if let Some(security_level) = params.security_level {
            query.push_str(&format!(" AND security_level >= {}", security_level as i32));
        }
        
        if let Some(ref owner_id) = params.owner_id {
            query.push_str(&format!(" AND owner_id = '{}'", owner_id));
        }
        
        let row = sqlx::query(&query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to count vault entries: {}", e),
            })?;
        
        let count: i64 = row.get(0);
        Ok(count as u64)
    }
    
    async fn exists(&self, path: &str) -> StorageResult<bool> {
        let query = "SELECT 1 FROM vault_entries WHERE path = $1 AND (expires_at IS NULL OR expires_at > NOW()) LIMIT 1";
        
        let row = sqlx::query(query)
            .bind(path)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to check entry existence: {}", e),
            })?;
        
        Ok(row.is_some())
    }
    
    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        let tx = self.pool.begin()
            .await
            .map_err(|e| StorageError::TransactionFailed {
                message: format!("Failed to begin transaction: {}", e),
            })?;
        
        Ok(Box::new(PostgresTransaction { tx: Some(tx) }))
    }
    
    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();
        
        let result = sqlx::query("SELECT 1")
            .fetch_one(&self.pool)
            .await;
        
        let response_time_ms = start.elapsed().as_secs_f64() * 1000.0;
        
        match result {
            Ok(_) => Ok(HealthStatus {
                is_healthy: true,
                response_time_ms,
                connections_active: self.pool.size(),
                connections_idle: self.pool.num_idle() as u32,
                last_error: None,
                uptime_seconds: 0, // Would need to be tracked separately
            }),
            Err(e) => Ok(HealthStatus {
                is_healthy: false,
                response_time_ms,
                connections_active: self.pool.size(),
                connections_idle: self.pool.num_idle() as u32,
                last_error: Some(e.to_string()),
                uptime_seconds: 0,
            }),
        }
    }
    
    async fn get_stats(&self) -> StorageResult<StorageStats> {
        let total_query = "SELECT COUNT(*), COALESCE(SUM(LENGTH(encrypted_data)), 0) FROM vault_entries";
        let row = sqlx::query(total_query)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to get stats: {}", e),
            })?;
        
        let total_entries: i64 = row.get(0);
        let total_size_bytes: i64 = row.get(1);
        let average_entry_size = if total_entries > 0 {
            total_size_bytes as f64 / total_entries as f64
        } else {
            0.0
        };
        
        // This is a simplified implementation - in production, you'd want more detailed statistics
        Ok(StorageStats {
            total_entries: total_entries as u64,
            total_size_bytes: total_size_bytes as u64,
            average_entry_size,
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }
    
    async fn migrate(&self) -> StorageResult<()> {
        let migration_sql = r#"
            CREATE TABLE IF NOT EXISTS vault_entries (
                id UUID PRIMARY KEY,
                path VARCHAR(255) UNIQUE NOT NULL,
                encrypted_data BYTEA NOT NULL,
                encryption_metadata JSONB NOT NULL,
                security_level INTEGER NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}',
                tags TEXT[] NOT NULL DEFAULT '{}',
                version INTEGER NOT NULL DEFAULT 1,
                owner_id UUID NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ
            );
            
            CREATE INDEX IF NOT EXISTS idx_vault_entries_path ON vault_entries(path);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_owner_id ON vault_entries(owner_id);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_security_level ON vault_entries(security_level);
            CREATE INDEX IF NOT EXISTS idx_vault_entries_expires_at ON vault_entries(expires_at) WHERE expires_at IS NOT NULL;
        "#;
        
        sqlx::query(migration_sql)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::MigrationError {
                message: format!("Failed to run migrations: {}", e),
            })?;
        
        Ok(())
    }
}

/// PostgreSQL transaction implementation
pub struct PostgresTransaction {
    tx: Option<sqlx::Transaction<'static, sqlx::Postgres>>,
}

#[async_trait]
impl StorageTransaction for PostgresTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        let tx = self.tx.as_mut().ok_or(StorageError::TransactionFailed {
            message: "Transaction already completed".to_string(),
        })?;
        
        let query = r#"
            INSERT INTO vault_entries 
            (id, path, encrypted_data, encryption_metadata, security_level, metadata, tags, version, owner_id, created_at, updated_at, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#;
        
        let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize encryption metadata: {}", e),
            })?;
        
        let metadata_json = serde_json::to_value(&entry.metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;
        
        sqlx::query(query)
            .bind(&entry.id)
            .bind(&entry.path)
            .bind(&entry.encrypted_data)
            .bind(encryption_metadata_json)
            .bind(entry.security_level as i32)
            .bind(metadata_json)
            .bind(&entry.tags)
            .bind(entry.version as i32)
            .bind(&entry.owner_id)
            .bind(&entry.created_at)
            .bind(&entry.updated_at)
            .bind(&entry.expires_at)
            .execute(&mut **tx)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store vault entry in transaction: {}", e),
            })?;
        
        Ok(())
    }
    
    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        let tx = self.tx.as_mut().ok_or(StorageError::TransactionFailed {
            message: "Transaction already completed".to_string(),
        })?;
        
        let query = r#"
            UPDATE vault_entries 
            SET encrypted_data = $2, encryption_metadata = $3, security_level = $4, metadata = $5, tags = $6, version = $7, updated_at = $8, expires_at = $9
            WHERE id = $1
        "#;
        
        let encryption_metadata_json = serde_json::to_value(&entry.encryption_metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize encryption metadata: {}", e),
            })?;
        
        let metadata_json = serde_json::to_value(&entry.metadata)
            .map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize metadata: {}", e),
            })?;
        
        let result = sqlx::query(query)
            .bind(&entry.id)
            .bind(&entry.encrypted_data)
            .bind(encryption_metadata_json)
            .bind(entry.security_level as i32)
            .bind(metadata_json)
            .bind(&entry.tags)
            .bind(entry.version as i32)
            .bind(&entry.updated_at)
            .bind(&entry.expires_at)
            .execute(&mut **tx)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to update vault entry in transaction: {}", e),
            })?;
        
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound {
                resource_type: "VaultEntry".to_string(),
                id: entry.id.to_string(),
            });
        }
        
        Ok(())
    }
    
    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        let tx = self.tx.as_mut().ok_or(StorageError::TransactionFailed {
            message: "Transaction already completed".to_string(),
        })?;
        
        let query = "DELETE FROM vault_entries WHERE id = $1";
        
        let result = sqlx::query(query)
            .bind(id)
            .execute(&mut **tx)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to delete vault entry in transaction: {}", e),
            })?;
        
        Ok(result.rows_affected() > 0)
    }
    
    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if let Some(tx) = self.tx.take() {
            tx.commit()
                .await
                .map_err(|e| StorageError::TransactionFailed {
                    message: format!("Failed to commit transaction: {}", e),
                })?;
        }
        Ok(())
    }
    
    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        if let Some(tx) = self.tx.take() {
            tx.rollback()
                .await
                .map_err(|e| StorageError::TransactionFailed {
                    message: format!("Failed to rollback transaction: {}", e),
                })?;
        }
        Ok(())
    }
}

/// Convert a database row to a VaultEntry
fn row_to_vault_entry(row: sqlx::postgres::PgRow) -> StorageResult<VaultEntry> {
    use crate::EncryptionMetadata;
    
    let encryption_metadata_json: serde_json::Value = row.get("encryption_metadata");
    let encryption_metadata: EncryptionMetadata = serde_json::from_value(encryption_metadata_json)
        .map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize encryption metadata: {}", e),
        })?;
    
    let metadata_json: serde_json::Value = row.get("metadata");
    let metadata: HashMap<String, String> = serde_json::from_value(metadata_json)
        .map_err(|e| StorageError::SerializationError {
            message: format!("Failed to deserialize metadata: {}", e),
        })?;
    
    let security_level_int: i32 = row.get("security_level");
    let security_level = match security_level_int {
        0 => SecurityLevel::Public,
        1 => SecurityLevel::Internal,
        2 => SecurityLevel::Confidential,
        3 => SecurityLevel::Secret,
        4 => SecurityLevel::TopSecret,
        _ => SecurityLevel::Internal, // Default fallback
    };
    
    Ok(VaultEntry {
        id: row.get("id"),
        path: row.get("path"),
        encrypted_data: row.get("encrypted_data"),
        encryption_metadata,
        security_level,
        metadata,
        tags: row.get("tags"),
        version: row.get::<i32, _>("version") as u32,
        owner_id: row.get("owner_id"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        expires_at: row.get("expires_at"),
    })
}
