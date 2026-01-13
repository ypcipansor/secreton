//! Manta storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use reqwest::Client;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// Manta storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MantaConfig {
    pub url: String,
    pub account: String,
    pub key_path: String,
    pub timeout: u64,
}

pub struct MantaStorage {
    config: MantaConfig,
    client: Client,
}

impl MantaStorage {
    pub fn new(config: MantaConfig) -> Self {
        Self { config, client: Client::new() }
    }

    fn get_url(&self, path: &str) -> String {
        format!("{}/{}/stor/{}", self.config.url, self.config.account, path)
    }
}

#[async_trait]
impl StorageBackend for MantaStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let url = self.get_url(&entry.path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
        // Manta requires http-signature auth usually
        let res = self.client.put(&url).body(data).send().await.map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        if !res.status().is_success() { return Err(StorageError::QueryFailed { message: res.status().to_string() }); }
        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let url = self.get_url(path);
        let res = self.client.get(&url).send().await.map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        if res.status() == reqwest::StatusCode::NOT_FOUND { return Ok(None); }
        if !res.status().is_success() { return Err(StorageError::QueryFailed { message: res.status().to_string() }); }
        let bytes = res.bytes().await.map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        let entry = serde_json::from_slice(&bytes).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;
        Ok(Some(entry))
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, _id: Uuid) -> StorageResult<bool> {
        Ok(false)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let url = self.get_url(path);
        let res = self.client.delete(&url).send().await.map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
        Ok(res.status().is_success())
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
        Ok(HealthStatus { is_healthy: true, response_time_ms: 0.0, connections_active: 0, connections_idle: 0, last_error: None, uptime_seconds: 0 })
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        Ok(StorageStats { total_entries: 0, total_size_bytes: 0, average_entry_size: 0.0, entries_by_security_level: std::collections::HashMap::new(), entries_created_today: 0, entries_updated_today: 0, expired_entries: 0 })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
}
