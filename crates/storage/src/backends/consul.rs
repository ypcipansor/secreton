use crate::{
    HealthStatus, QueryParams, SecretEntry, StorageBackend, StorageError, StorageResult,
    StorageStats, StorageTransaction,
};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Consul storage backend configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulStorageConfig {
    /// Consul server address
    pub address: String,
    /// Consul datacenter
    pub datacenter: Option<String>,
    /// Consul token for authentication
    pub token: Option<String>,
    /// Key prefix for all vault data
    pub path: String,
    /// TLS configuration
    pub tls_enabled: bool,
    /// TLS CA certificate
    pub tls_ca_cert: Option<String>,
    /// Connection timeout in seconds
    pub timeout: u64,
    /// Maximum number of retries
    pub max_retries: u32,
}

impl Default for ConsulStorageConfig {
    fn default() -> Self {
        Self {
            address: "http://localhost:8500".to_string(),
            datacenter: None,
            token: None,
            path: "vault/".to_string(),
            tls_enabled: false,
            tls_ca_cert: None,
            timeout: 30,
            max_retries: 3,
        }
    }
}

/// Consul storage backend
pub struct ConsulStorage {
    config: ConsulStorageConfig,
    client: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, SecretEntry>>>,
}

/// Consul transaction implementation
pub struct ConsulTransaction {
    operations: Vec<ConsulOperation>,
    committed: bool,
}

enum ConsulOperation {
    Store(()),
    Update(()),
    Delete(()),
}

impl ConsulTransaction {
    pub fn new() -> Self {
        Self {
            operations: Vec::new(),
            committed: false,
        }
    }
}

#[async_trait]
impl StorageTransaction for ConsulTransaction {
    async fn store(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(ConsulOperation::Store(()));
        Ok(())
    }

    async fn update(&mut self, _entry: &SecretEntry) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(ConsulOperation::Update(()));
        Ok(())
    }

    async fn delete(&mut self, _id: Uuid) -> StorageResult<bool> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }
        self.operations.push(ConsulOperation::Delete(()));
        Ok(true)
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        if self.committed {
            return Err(StorageError::TransactionFailed {
                message: "Transaction already committed".to_string(),
            });
        }

        // In a real Consul implementation, operations would be executed
        // Consul doesn't support transactions natively, so operations would be atomic individually
        // For now, we just mark as committed since we don't have a real connection
        self.committed = true;
        Ok(())
    }

    async fn rollback(mut self: Box<Self>) -> StorageResult<()> {
        self.operations.clear();
        Ok(())
    }
}

impl ConsulStorage {
    /// Create new Consul storage backend
    pub async fn new(config: ConsulStorageConfig) -> Result<Self, StorageError> {
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

    /// Build Consul KV API URL
    fn build_url(&self, key: &str) -> String {
        let base = self.config.address.trim_end_matches('/');
        let path = self.config.path.trim_matches('/');
        let key = key.trim_matches('/');

        let mut url = format!("{}/v1/kv/{}/{}", base, path, key);

        if let Some(dc) = &self.config.datacenter {
            url.push_str(&format!("?dc={}", dc));
        }

        url
    }

    /// Add Consul token to request if configured
    fn add_auth(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.config.token {
            request.header("X-Consul-Token", token)
        } else {
            request
        }
    }
}

#[async_trait]
impl StorageBackend for ConsulStorage {
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let key = &entry.path;
        let url = self.build_url(key);

        // Serialize entry
        let serialized =
            serde_json::to_vec(&entry).map_err(|e| StorageError::SerializationError {
                message: format!("Failed to serialize entry: {}", e),
            })?;

        let encoded = STANDARD.encode(&serialized);

        let request = self.client.put(&url).body(encoded);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to Consul: {}", e),
            })?;

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "consul".to_string(),
                message: format!("Consul returned error: {}", response.status()),
            });
        }

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(key.clone(), entry.clone());

        Ok(())
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        // For Consul, we need to list all entries and find by ID
        // This is not efficient - in production you'd maintain an ID index
        let entries = self.list(&QueryParams::default()).await?;
        Ok(entries.into_iter().find(|e| e.id == id))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        // Check cache first
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(path) {
                return Ok(Some(entry.clone()));
            }
        }

        // Fetch from Consul
        let url = self.build_url(path);
        let request = self.client.get(&url);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to Consul: {}", e),
            })?;

        if response.status() == 404 {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "consul".to_string(),
                message: format!("Consul returned error: {}", response.status()),
            });
        }

        #[derive(Deserialize)]
        struct ConsulKVResponse {
            #[serde(rename = "Value")]
            value: String,
        }

        let kv_response: Vec<ConsulKVResponse> =
            response
                .json()
                .await
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to parse Consul response: {}", e),
                })?;

        if let Some(kv) = kv_response.first() {
            let decoded =
                STANDARD
                    .decode(&kv.value)
                    .map_err(|e| StorageError::SerializationError {
                        message: format!("Failed to decode base64: {}", e),
                    })?;

            let entry: SecretEntry =
                serde_json::from_slice(&decoded).map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to deserialize entry: {}", e),
                })?;

            // Update cache
            let mut cache = self.cache.write().await;
            cache.insert(path.to_string(), entry.clone());

            Ok(Some(entry))
        } else {
            Ok(None)
        }
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        // For Consul, update is the same as store (PUT operation)
        self.store(entry).await
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        // Find entry by ID first
        if let Some(entry) = self.get_by_id(id).await? {
            self.delete_by_path(&entry.path).await
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        let url = self.build_url(path);
        let request = self.client.delete(&url);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to Consul: {}", e),
            })?;

        if !response.status().is_success() && response.status() != 404 {
            return Err(StorageError::BackendError {
                backend: "consul".to_string(),
                message: format!("Consul returned error: {}", response.status()),
            });
        }

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(path);

        Ok(response.status().is_success())
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<SecretEntry>> {
        let prefix = params.path_prefix.as_deref().unwrap_or("");
        let url = format!("{}?keys&separator=/", self.build_url(prefix));
        let request = self.client.get(&url);
        let request = self.add_auth(request);

        let response = request
            .send()
            .await
            .map_err(|e| StorageError::ConnectionFailed {
                message: format!("Failed to connect to Consul: {}", e),
            })?;

        if response.status() == 404 {
            return Ok(Vec::new());
        }

        if !response.status().is_success() {
            return Err(StorageError::BackendError {
                backend: "consul".to_string(),
                message: format!("Consul returned error: {}", response.status()),
            });
        }

        let keys: Vec<String> =
            response
                .json()
                .await
                .map_err(|e| StorageError::SerializationError {
                    message: format!("Failed to parse Consul response: {}", e),
                })?;

        // Fetch each entry
        let mut entries = Vec::new();
        for key in keys {
            if let Some(entry) = self.get_by_path(&key).await? {
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
        Ok(Box::new(ConsulTransaction::new()))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();
        let url = format!(
            "{}/v1/status/leader",
            self.config.address.trim_end_matches('/')
        );

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
        // Consul doesn't require migrations
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consul_config_default() {
        let config = ConsulStorageConfig::default();
        assert_eq!(config.address, "http://localhost:8500");
        assert_eq!(config.path, "vault/");
        assert_eq!(config.timeout, 30);
        assert_eq!(config.max_retries, 3);
    }

    #[test]
    fn test_build_url() {
        let config = ConsulStorageConfig::default();
        let storage = ConsulStorage {
            config: config.clone(),
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let url = storage.build_url("test/key");
        assert!(url.contains("/v1/kv/vault/test/key"));
    }

    #[test]
    fn test_build_url_with_datacenter() {
        let mut config = ConsulStorageConfig::default();
        config.datacenter = Some("dc1".to_string());

        let storage = ConsulStorage {
            config,
            client: reqwest::Client::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        let url = storage.build_url("test/key");
        assert!(url.contains("?dc=dc1"));
    }

    #[tokio::test]
    async fn test_consul_storage_creation() {
        let config = ConsulStorageConfig::default();
        let result = ConsulStorage::new(config).await;
        assert!(result.is_ok());
    }
}
