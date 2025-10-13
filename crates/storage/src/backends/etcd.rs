use crate::{
    HealthStatus, QueryParams, StorageBackend, StorageError, StorageResult, StorageStats,
    StorageTransaction, VaultEntry,
};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};

/// etcd storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EtcdStorageConfig {
    /// etcd server endpoints
    pub endpoints: Vec<String>,
    /// Key prefix for all vault data
    pub prefix: String,
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
    /// TLS configuration
    pub tls_enabled: bool,
    /// TLS CA certificate
    pub tls_ca_cert: Option<String>,
    /// TLS client certificate
    pub tls_client_cert: Option<String>,
    /// TLS client key
    pub tls_client_key: Option<String>,
    /// Connection timeout in seconds
    pub timeout: u64,
}

impl Default for EtcdStorageConfig {
    fn default() -> Self {
        Self {
            endpoints: vec!["http://localhost:2379".to_string()],
            prefix: "/vault/".to_string(),
            username: None,
            password: None,
            tls_enabled: false,
            tls_ca_cert: None,
            tls_client_cert: None,
            tls_client_key: None,
            timeout: 30,
        }
    }
}

/// etcd storage backend
pub struct EtcdStorage {
    config: EtcdStorageConfig,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, VaultEntry>>>,
}

impl EtcdStorage {
    /// Create new etcd storage backend
    pub async fn new(config: EtcdStorageConfig) -> Result<Self, StorageError> {
        let mut client_builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(config.timeout));

        // Add TLS configuration if enabled
        if config.tls_enabled {
            if let Some(ca_cert) = &config.tls_ca_cert {
                let cert = reqwest::Certificate::from_pem(ca_cert.as_bytes()).map_err(|e| {
                    StorageError::ConfigurationError {
                        message: format!("Invalid CA certificate: {}", e),
                    }
                })?;
                client_builder = client_builder.add_root_certificate(cert);
            }

            if let (Some(client_cert), Some(client_key)) =
                (&config.tls_client_cert, &config.tls_client_key)
            {
                let identity = reqwest::Identity::from_pem(
                    format!("{}\n{}", client_cert, client_key).as_bytes(),
                )
                .map_err(|e| StorageError::ConfigurationError {
                    message: format!("Invalid client certificate: {}", e),
                })?;
                client_builder = client_builder.identity(identity);
            }
        }

        let client = client_builder
            .build()
            .map_err(|e| StorageError::ConfigurationError {
                message: format!("Failed to create HTTP client: {}", e),
            })?;

        Ok(Self {
            config,
            client,
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Build full key with prefix
    fn build_key(&self, key: &str) -> String {
        format!("{}{}", self.config.prefix.trim_end_matches('/'), key)
    }

    /// Get primary endpoint
    fn get_endpoint(&self) -> &str {
        self.config
            .endpoints
            .first()
            .map(|s| s.as_str())
            .unwrap_or("http://localhost:2379")
    }

    /// Build etcd v3 API URL
    fn build_url(&self, path: &str) -> String {
        format!("{}/v3/{}", self.get_endpoint().trim_end_matches('/'), path)
    }

    /// Add authentication if configured
    fn add_auth(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let (Some(username), Some(password)) = (&self.config.username, &self.config.password) {
            request = request.basic_auth(username, Some(password));
        }
        request
    }
}

#[async_trait]
impl StorageBackend for EtcdStorage {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        let key = &entry.path;
        let full_key = self.build_key(key);
        let url = self.build_url("kv/put");

        // Serialize entry
        let serialized =
            serde_json::to_vec(&entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        let request_body = serde_json::json!({
            "key": BASE64_STANDARD.encode(&full_key),
            "value": BASE64_STANDARD.encode(&serialized),
        });

        let request = self.client.post(&url).json(&request_body);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to etcd: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "etcd".to_string(),
                message: format!("etcd returned error: {}", response.status()),
            });
        }

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(key.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        // For etcd, we need to list all entries and find by ID
        let entries = self.list(&QueryParams::default()).await?;
        Ok(entries.into_iter().find(|e| e.id == id))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(entry.clone()));
            }
        }

        // Fetch from etcd using v3 API
        let full_key = self.build_key(path);
        let url = self.build_url("kv/range");

        let request_body = serde_json::json!({
            "key": BASE64_STANDARD.encode(&full_key),
        });

        let request = self.client.post(&url).json(&request_body);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to etcd: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "etcd".to_string(),
                message: format!("etcd returned error: {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct EtcdRangeResponse {
            kvs: Option<Vec<EtcdKV>>,
        }

        #[derive(Deserialize)]
        struct EtcdKV {
            value: String,
        }

        let etcd_response: EtcdRangeResponse =
            response
                .json()
                .await
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to parse etcd response: {}", e),
                })?;

        if let Some(kvs) = etcd_response.kvs {
            if let Some(kv) = kvs.first() {
                let decoded =
                    BASE64_STANDARD.decode(&kv.value).map_err(|e| StorageError::SerializationError {
                        message: format!("Failed to decode base64: {}", e),
                    })?;

                let entry: VaultEntry = serde_json::from_slice(&decoded).map_err(|e| {
                    StorageError::SerializationError {
                        message: format!("Failed to deserialize entry: {}", e),
                    }
                })?;

                // Update cache
                let mut cache = self.cache.write().await;
                cache.insert(path.to_string(), entry.clone());

                return Ok(Some(entry));
            }
        }

        Ok(None)
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        if let Some(entry) = self.get_by_id(id).await? {
            self.delete_by_path(&entry.path).await
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let full_key = self.build_key(path);
        let url = self.build_url("kv/deleterange");

        let request_body = serde_json::json!({
            "key": BASE64_STANDARD.encode(&full_key),
        });

        let request = self.client.post(&url).json(&request_body);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to etcd: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "etcd".to_string(),
                message: format!("etcd returned error: {}", response.status()),
            });
        }

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(path);

        Ok(response.status().is_success())
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        let prefix = params.path_prefix.as_deref().unwrap_or("");
        let full_prefix = self.build_key(prefix);
        let url = self.build_url("kv/range");

        // Create range end for prefix scan
        let range_end = format!("{}\0", full_prefix);

        let request_body = serde_json::json!({
            "key": BASE64_STANDARD.encode(&full_prefix),
            "range_end": BASE64_STANDARD.encode(&range_end),
        });

        let request = self.client.post(&url).json(&request_body);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to etcd: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "etcd".to_string(),
                message: format!("etcd returned error: {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct EtcdRangeResponse {
            kvs: Option<Vec<EtcdKV>>,
        }

        #[derive(Deserialize)]
        struct EtcdKV {
            value: String,
        }

        let etcd_response: EtcdRangeResponse =
            response
                .json()
                .await
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to parse etcd response: {}", e),
                })?;

        let mut entries = Vec::new();
        if let Some(kvs) = etcd_response.kvs {
            for kv in kvs {
                let decoded =
                    BASE64_STANDARD.decode(&kv.value).map_err(|e| StorageError::SerializationError {
                        message: format!("Failed to decode value: {}", e),
                    })?;

                let entry: VaultEntry = serde_json::from_slice(&decoded).map_err(|e| {
                    StorageError::SerializationError {
                        message: format!("Failed to deserialize entry: {}", e),
                    }
                })?;

                // Apply filters
                if let Some(owner) = params.owner_id {
                    if entry.owner_id != owner {
                        continue;
                    }
                }
                if !params.include_expired && entry.is_expired() {
                    continue;
                }

                entries.push(entry);
            }
        }

        // Apply limit
        if let Some(limit) = params.limit {
            entries.truncate(limit as usize);
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
        // etcd supports transactions but for simplicity, return mock
        Ok(Box::new(crate::MockTransaction))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();
        let url = format!("{}/health", self.get_endpoint().trim_end_matches('/'));

        let result = self.client.get(&url).send().await;
        let duration = start.elapsed().as_millis() as f64;

        match result {
            Ok(response) if response.status().is_success() => Ok(HealthStatus {
                is_healthy: true,
                response_time_ms: duration,
                connections_active: 1,
                connections_idle: 0,
                last_error: None,
                uptime_seconds: 0,
            }),
            Ok(response) => Ok(HealthStatus {
                is_healthy: false,
                response_time_ms: duration,
                connections_active: 0,
                connections_idle: 0,
                last_error: Some(format!("HTTP {}", response.status())),
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
        // etcd doesn't require migrations
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_etcd_config_default() {
        let config = EtcdStorageConfig::default();
        assert_eq!(config.endpoints.len(), 1);
        assert_eq!(config.endpoints[0], "http://localhost:2379");
        assert_eq!(config.prefix, "/vault/");
        assert_eq!(config.timeout, 30);
    }

    #[test]
    fn test_build_key() {
        let config = EtcdStorageConfig::default();
        let storage = EtcdStorage {
            config,
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let key = storage.build_key("/test/key");
        assert_eq!(key, "/vault/test/key");
    }

    #[tokio::test]
    async fn test_etcd_storage_creation() {
        let config = EtcdStorageConfig::default();
        let result = EtcdStorage::new(config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_etcd_config_multiple_endpoints() {
        let config = EtcdStorageConfig {
            endpoints: vec![
                "http://etcd1:2379".to_string(),
                "http://etcd2:2379".to_string(),
                "http://etcd3:2379".to_string(),
            ],
            ..Default::default()
        };

        assert_eq!(config.endpoints.len(), 3);
    }
}
