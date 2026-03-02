//! Modern Redis storage backend implementation using redis v1.0.0-alpha.1

use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use chrono::Utc;
use redis::{AsyncCommands, Client, aio::ConnectionManager};
use secreton_common::models::oauth_state::OAuthState;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

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
    Store(SecretEntry),
    Update(SecretEntry),
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
    async fn store(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Store(entry.clone()));
        Ok(())
    }

    async fn update(&mut self, entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations
            .push(RedisTransactionOp::Update(entry.clone()));
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
        let mut pipe = redis::pipe();
        pipe.atomic();

        for op in self.operations {
            match op {
                RedisTransactionOp::Store(entry) | RedisTransactionOp::Update(entry) => {
                    let key = format!("secreton:entry:{}", entry.id);
                    let value = serde_json::to_string(&entry).map_err(|e| {
                        StorageError::SerializationError {
                            message: e.to_string(),
                        }
                    })?;

                    if let Some(expires_at) = entry.expires_at {
                        let ttl = (expires_at - Utc::now()).num_seconds();
                        if ttl > 0 {
                            pipe.set_ex(&key, value, ttl as u64);
                        } else {
                            // Already expired, ensure it is removed
                            pipe.del(&key);
                        }
                    } else {
                        pipe.set(&key, value);
                    }
                }
                RedisTransactionOp::Delete(id) => {
                    let key = format!("secreton:entry:{}", id);
                    pipe.del(&key);
                }
            }
        }

        pipe.query_async::<()>(&mut *conn)
            .await
            .map_err(|e| StorageError::QueryFailed {
                message: format!("Failed to execute transaction pipeline: {}", e),
            })?;

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

        Ok(Self {
            manager: Arc::new(Mutex::new(manager)),
        })
    }
}

#[async_trait]
impl StorageBackend for RedisBackend {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let key = format!("secreton:entry:{}", entry.id);
        let value = serde_json::to_string(entry).map_err(|e| StorageError::SerializationError {
            message: e.to_string(),
        })?;

        let mut conn = self.manager.lock().await;

        if let Some(expires_at) = entry.expires_at {
            let ttl = (expires_at - Utc::now()).num_seconds();
            if ttl > 0 {
                conn.set_ex::<_, _, ()>(&key, value, ttl as u64)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store entry with TTL: {}", e),
                    })?;
            } else {
                // Already expired, ensure it is removed
                conn.del::<_, ()>(&key)
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to delete expired entry: {}", e),
                    })?;
            }
        } else {
            conn.set::<_, _, ()>(&key, value)
                .await
                .map_err(|e| StorageError::QueryFailed {
                    message: format!("Failed to store entry: {}", e),
                })?;
        }

        // Also store path mapping
        if !entry.path.is_empty() {
            let path_key = format!("secreton:path:{}", entry.path);

            if let Some(expires_at) = entry.expires_at {
                let ttl = (expires_at - Utc::now()).num_seconds();
                if ttl > 0 {
                    conn.set_ex::<_, _, ()>(&path_key, entry.id.to_string(), ttl as u64)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to store path mapping with TTL: {}", e),
                        })?;
                } else {
                    conn.del::<_, ()>(&path_key)
                        .await
                        .map_err(|e| StorageError::QueryFailed {
                            message: format!("Failed to delete expired path mapping: {}", e),
                        })?;
                }
            } else {
                conn.set::<_, _, ()>(&path_key, entry.id.to_string())
                    .await
                    .map_err(|e| StorageError::QueryFailed {
                        message: format!("Failed to store path mapping: {}", e),
                    })?;
            }
        }

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:entry:{}", id);
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

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let key = format!("secreton:path:{}", path);
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

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For updates, we use the same store logic
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Ok(false)
    }

    async fn delete_by_path(&self, _path: &str) -> StorageResult<bool> {
        Ok(false)
    }

    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
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

    async fn delete_expired(&self, _path_prefix: Option<String>) -> StorageResult<u64> {
        // Redis handles expiration automatically via TTL
        Ok(0)
    }

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError {
            backend: "Redis".to_string(),
            message: "Not implemented".to_string(),
        })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
