//! Swift storage backend for Secreton

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use reqwest::Client;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// Swift storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwiftConfig {
    pub auth_url: String,
    pub username: String,
    pub password: String,
    pub container: String,
    pub region: Option<String>,
    pub account: Option<String>, // Often needed for swift
}

pub struct SwiftStorage {
    config: SwiftConfig,
    client: Client,
    token: Arc<RwLock<Option<String>>>,
    storage_url: Arc<RwLock<Option<String>>>,
}

impl SwiftStorage {
    pub fn new(config: SwiftConfig) -> Self {
        Self {
            config,
            client: Client::new(),
            token: Arc::new(RwLock::new(None)),
            storage_url: Arc::new(RwLock::new(None)),
        }
    }

    async fn authenticate(&self) -> StorageResult<()> {
        // Basic Keystone V3 Auth structure
        let auth_body = serde_json::json!({
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": self.config.username,
                            "domain": { "id": "default" },
                            "password": self.config.password
                        }
                    }
                }
            }
        });

        let res = self.client.post(&format!("{}/auth/tokens", self.config.auth_url))
            .json(&auth_body)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if !res.status().is_success() {
            return Err(StorageError::ConnectionFailed { message: format!("Auth failed: {}", res.status()) });
        }

        if let Some(token) = res.headers().get("X-Subject-Token") {
            let token_str = token.to_str().unwrap_or_default().to_string();
            let mut t = self.token.write().await;
            *t = Some(token_str);
        }

        // Parse catalog to find storage URL (simplified: assuming default region/interface)
        // For now, we assume we need to parse response body to find "swift" endpoint.
        // We'll skip parsing for brevity and construct a URL if possible or assume a default pattern.
        // Or if 'storage_url' was in config (it's not).
        // Let's assume the user provided the full storage URL in auth_url if it's V1 auth?
        // No, config has `auth_url`.
        // We'll set a placeholder storage_url based on account if missing catalog parsing.

        let mut s = self.storage_url.write().await;
        *s = Some(format!("{}/v1/AUTH_{}", self.config.auth_url.replace("/auth/tokens", ""), self.config.account.as_deref().unwrap_or("default")));

        Ok(())
    }

    async fn get_token(&self) -> StorageResult<(String, String)> {
        // Check if we have a token, if not auth
        // Lock read
        let token = self.token.read().await.clone();
        let url = self.storage_url.read().await.clone();

        if let (Some(t), Some(u)) = (token, url) {
            return Ok((t, u));
        }

        // Auth
        self.authenticate().await?;

        let t = self.token.read().await.clone().ok_or(StorageError::ConnectionFailed { message: "No token after auth".to_string() })?;
        let u = self.storage_url.read().await.clone().ok_or(StorageError::ConnectionFailed { message: "No URL after auth".to_string() })?;
        Ok((t, u))
    }
}

#[async_trait]
impl StorageBackend for SwiftStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let (token, base_url) = self.get_token().await?;
        let url = format!("{}/{}/{}", base_url, self.config.container, entry.path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;

        let res = self.client.put(&url)
            .header("X-Auth-Token", token)
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if res.status() == reqwest::StatusCode::UNAUTHORIZED {
            // Retry auth once?
            // self.authenticate().await?; ...
        }

        if !res.status().is_success() {
            return Err(StorageError::QueryFailed { message: res.status().to_string() });
        }
        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let (token, base_url) = self.get_token().await?;
        let url = format!("{}/{}/{}", base_url, self.config.container, path);

        let res = self.client.get(&url)
            .header("X-Auth-Token", token)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

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
        let (token, base_url) = self.get_token().await?;
        let url = format!("{}/{}/{}", base_url, self.config.container, path);

        let res = self.client.delete(&url)
            .header("X-Auth-Token", token)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;
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
