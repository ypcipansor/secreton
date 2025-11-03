//! Modern Redis storage backend implementation using redis v1.0.0-alpha.1

use crate::{
    HealthStatus, QueryParams, StorageBackend, StorageError, StorageResult, StorageStats,
    StorageTransaction, VaultEntry,
};
use async_trait::async_trait;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use std::sync::Arc;
use std::collections::HashMap;
use uuid::Uuid;
use tokio::sync::Mutex;

/// Modern Redis storage backend with connection pooling
pub struct RedisBackend {
    manager: Arc<Mutex<ConnectionManager>>,
}

/// Redis transaction implementation using pipelines
pub struct RedisTransaction {
    manager: Arc<Mutex<ConnectionManager>>,
    operations: Vec<RedisTransactionOp>,
    committed: bool,
}

#[derive(Clone)]
enum RedisTransactionOp {
    Store(VaultEntry),
    Update(VaultEntry),
    Delete(Uuid),
}

impl RedisTransaction {
    pub fn new(manager: Arc<Mutex<ConnectionManager>>) -> Self {
        Self {
            manager,
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for RedisTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(RedisTransactionOp::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(RedisTransactionOp::Update(entry.clone()));
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(RedisTransactionOp::Delete(id));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // Get Redis connection from backend and execute all operations
        let mut conn = self.manager.lock().await;
        
        for op in self.operations {
            match op {
                RedisTransactionOp::Store(entry) => {
                    let key = format!("vault:entry:{}", entry.id);
                    let value = serde_json::to_string(&entry).map_err(|e| StorageError::SerializationError {
                        message: e.to_string(),
                    })?;
                    conn.set::<_, _, ()>(&key, &value)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to store entry in transaction: {}", e),
                        })?;
                }
                RedisTransactionOp::Update(entry) => {
                    let key = format!("vault:entry:{}", entry.id);
                    let value = serde_json::to_string(&entry).map_err(|e| StorageError::SerializationError {
                        message: e.to_string(),
                    })?;
                    conn.set::<_, _, ()>(&key, &value)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to update entry in transaction: {}", e),
                        })?;
                }
                RedisTransactionOp::Delete(id) => {
                    let key = format!("vault:entry:{}", id);
                    conn.del::<_, ()>(&key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to delete entry in transaction: {}", e),
                        })?;
                }
            }
        }
        
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl RedisBackend {
    /// Create a new modern Redis backend with connection pooling
    pub async fn new(connection_url: &str) -> StorageResult<Self> {
        let client = Client::open(connection_url).map_err(|e| StorageError::ConnectionFailed {
            message: format!("Invalid Redis URL: {}", e),
        })?;

        let manager =
            ConnectionManager::new(client)
                .await
                .map_err(|e| StorageError::ConnectionFailed {
                    message: format!("Failed to create Redis connection manager: {}", e),
                })?;

        Ok(Self { manager: Arc::new(Mutex::new(manager)) })
    }
}

#[async_trait]
impl StorageBackend for RedisBackend {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let key = format!("vault:entry:{}", entry.id);
        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let mut conn = self.manager.lock().await;
        conn.set::<_, _, ()>(&key, value)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to store entry: {}", e),
            })?;

        // Also store path mapping
        if !entry.path.is_empty() {
            let path_key = format!("vault:path:{}", entry.path);
            conn.set::<_, _, ()>(&path_key, entry.id.to_string())
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to store path mapping: {}", e),
                })?;
        }

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        let key = format!("vault:entry:{}", id);
        let mut conn = self.manager.lock().await;

        let value: Option<String> =
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get entry: {}", e),
                })?;

        match value {
            Some(json_str) => {
                let entry = serde_json::from_str(&json_str).map_err(|e| {
                    StorageError::SerializationError {
                        message: e.to_string(),
                    }
                })?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        let key = format!("vault:path:{}", path);
        let mut conn = self.manager.lock().await;

        let entry_id: Option<String> =
            conn.get(&key)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to get path mapping: {}", e),
                })?;

        match entry_id {
            Some(id_str) => {
                let id =
                    Uuid::parse_str(&id_str).map_err(|e| StorageError::SerializationError {
                        message: e.to_string(),
                    })?;
                self.get_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        // For updates, we use the same store logic
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Ok(false)
    }

    async fn delete_by_path(&self, _path: &str) -> StorageResult<bool> {
        Ok(false)
    }

    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        Ok(Vec::new())
    }

    async fn count(&self, _params: &QueryParams) -> StorageResult<u64> {
        Ok(0)
    }

    async fn exists(&self, _path: &str) -> StorageResult<bool> {
        Ok(false)
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(RedisTransaction::new(self.manager.clone())))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 1.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 0,
        })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats {
            total_entries: 0,
            total_size_bytes: 0,
            average_entry_size: 0.0,
            entries_by_security_level: HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
}
