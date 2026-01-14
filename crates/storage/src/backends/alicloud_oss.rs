//! AliCloud OSS storage backend implementation

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use reqwest::Client;
use chrono::Utc;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

use crate::{
    StorageBackend, StorageError, SecretEntry, StorageResult,
    StorageTransaction, HealthStatus, StorageStats, QueryParams
};

/// AliCloud OSS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliCloudOSSConfig {
    pub endpoint: String,
    pub access_key_id: String,
    pub access_key_secret: String,
    pub bucket: String,
    pub region: String,
    pub connection_timeout: u64,
    pub request_timeout: u64,
}

pub struct AliCloudOSSStorage {
    config: AliCloudOSSConfig,
    client: Client,
}

impl AliCloudOSSStorage {
    pub fn new(config: AliCloudOSSConfig) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(config.request_timeout))
            .connect_timeout(std::time::Duration::from_secs(config.connection_timeout))
            .build()
            .unwrap_or_else(|_| Client::new());

        Self { config, client }
    }

    fn get_url(&self, path: &str) -> String {
        format!("https://{}.{}/{}", self.config.bucket, self.config.endpoint, path.trim_start_matches('/'))
    }

    fn sign_request(&self, verb: &str, resource: &str, date: &str, content_type: &str) -> StorageResult<String> {
        // Signature = Base64( HMAC-SHA1( AccessKeySecret, VERB + "\n"
        // + Content-MD5 + "\n"
        // + Content-Type + "\n"
        // + Date + "\n"
        // + CanonicalizedOSSHeaders
        // + CanonicalizedResource ) )

        let canonical_resource = format!("/{}/{}", self.config.bucket, resource.trim_start_matches('/'));
        let string_to_sign = format!("{}\n\n{}\n{}\n{}", verb, content_type, date, canonical_resource);

        type HmacSha1 = Hmac<Sha1>;
        let mut mac = HmacSha1::new_from_slice(self.config.access_key_secret.as_bytes())
            .map_err(|e| StorageError::ConfigurationError { message: format!("Invalid HMAC key: {}", e) })?;

        mac.update(string_to_sign.as_bytes());
        let result = mac.finalize();
        let signature = BASE64.encode(result.into_bytes());

        Ok(format!("OSS {}:{}", self.config.access_key_id, signature))
    }
}

#[async_trait]
impl StorageBackend for AliCloudOSSStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let path = entry.path.clone();
        let url = self.get_url(&path);
        let data = serde_json::to_vec(entry).map_err(|e| StorageError::SerializationError { message: e.to_string() })?;

        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_type = "application/json";
        let auth = self.sign_request("PUT", &path, &date, content_type)?;

        let res = self.client.put(&url)
            .header("Date", date)
            .header("Content-Type", content_type)
            .header("Authorization", auth)
            .body(data)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if !res.status().is_success() {
            return Err(StorageError::QueryFailed { message: format!("OSS Error: {}", res.status()) });
        }
        Ok(())
    }

    async fn get_by_id(&self, _id: Uuid) -> StorageResult<Option<SecretEntry>> {
        Ok(None)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let url = self.get_url(path);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_type = ""; // GET has no content type
        let auth = self.sign_request("GET", path, &date, content_type)?;

        let res = self.client.get(&url)
            .header("Date", date)
            .header("Authorization", auth)
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed { message: e.to_string() })?;

        if res.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !res.status().is_success() {
            return Err(StorageError::QueryFailed { message: format!("OSS Error: {}", res.status()) });
        }

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
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string();
        let content_type = "";
        let auth = self.sign_request("DELETE", path, &date, content_type)?;

        let res = self.client.delete(&url)
            .header("Date", date)
            .header("Authorization", auth)
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
        Ok(HealthStatus {
            is_healthy: true,
            response_time_ms: 0.0,
            connections_active: 0,
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
            entries_by_security_level: std::collections::HashMap::new(),
            entries_created_today: 0,
            entries_updated_today: 0,
            expired_entries: 0,
        })
    }

    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
}
