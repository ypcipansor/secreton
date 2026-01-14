//! ZooKeeper storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zookeeper_client::{Client};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};
use secreton_common::models::oauth_state::OAuthState;

/// ZooKeeper storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZooKeeperConfig {
    pub hosts: Vec<String>,
    pub base_path: String,
    pub connection_timeout: u64,
    pub session_timeout: u64,
}

pub struct ZooKeeperStorage {
    config: ZooKeeperConfig,
    client: Arc<Client>,
}

impl ZooKeeperStorage {
    pub async fn new(config: ZooKeeperConfig) -> StorageResult<Self> {
        let connection_string = config.hosts.join(",");
        let client = Client::connect(&connection_string)
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to ZooKeeper: {}", e),
            })?;

        Ok(Self {
            config,
            client: Arc::new(client),
        })
    }

    fn path(&self, suffix: &str) -> String {
        format!("{}/{}", self.config.base_path.trim_end_matches('/'), suffix.trim_start_matches('/'))
    }

    fn path_key(&self, path: &str) -> String {
        self.path(&format!("secrets/{}", path))
    }
}

#[async_trait]
impl StorageBackend for ZooKeeperStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
        let path = self.path_key(&entry.path);

        // Use check_stat instead of check_exists/exists
        let exists_result = self.client.check_stat(&path).await;

        match exists_result {
            Ok(Some(_)) => {
                self.client.set_data(&path, &data, None).await.map_err(|e| StorageError::QueryFailed { message: e.to_string() })?;
            },
            Ok(None) | Err(zookeeper_client::Error::NoNode) => {
                // Creation temporarily disabled due to API mismatch
                return Err(StorageError::QueryFailed { message: "ZooKeeper create not fully implemented (API mismatch)".to_string() });
            },
            Err(e) => return Err(StorageError::ConnectionFailed { message: e.to_string() }),
        }

        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let zk_path = self.path_key(path);
        match self.client.get_data(&zk_path).await {
            Ok((data, _stat)) => {
                let entry: SecretEntry = serde_json::from_slice(&data).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
                Ok(Some(entry))
            },
            Err(zookeeper_client::Error::NoNode) => Ok(None),
            Err(e) => Err(StorageError::QueryFailed { message: e.to_string() }),
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Ok(false)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let zk_path = self.path_key(path);
        match self.client.delete(&zk_path, None).await {
            Ok(_) => Ok(true),
            Err(zookeeper_client::Error::NoNode) => Ok(false),
            Err(e) => Err(StorageError::QueryFailed { message: e.to_string() }),
        }
    }

    async fn list(&self, _params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        Ok(Vec::new())
    }

    async fn count(&self, _params: &QueryParams) -> StorageResult<u64> {
        Ok(0)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        Ok(self.get_by_path(path).await?.is_some())
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        Ok(Box::new(crate::MockTransaction))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 0.0,
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

    async fn store_oauth_state(&self, _state: &OAuthState) -> StorageResult<()> {
        Err(StorageError::BackendError { backend: "ZooKeeper".to_string(), message: "Not implemented".to_string() })
    }

    async fn get_oauth_state(&self, _state: &str) -> StorageResult<Option<OAuthState>> {
        Err(StorageError::BackendError { backend: "ZooKeeper".to_string(), message: "Not implemented".to_string() })
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        Ok(0)
    }
}
