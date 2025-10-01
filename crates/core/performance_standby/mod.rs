//! Performance Standby Nodes - Read-only replicas for improved scalability
//!
//! Performance standby nodes provide read-only access to secrets data,
//! improving scalability and performance by offloading read operations
//! from the primary cluster.

use crate::{storage::StorageEngine, AppError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Notify};
use uuid::Uuid;

/// Performance standby node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceStandbyConfig {
    /// Node identifier
    pub node_id: String,
    /// Primary cluster address
    pub primary_address: String,
    /// Replication token for authentication
    pub replication_token: String,
    /// Sync interval for data replication
    pub sync_interval: Duration,
    /// Maximum lag allowed before marking node as stale
    pub max_lag_seconds: u64,
    /// Enable local caching
    pub enable_caching: bool,
    /// Cache TTL for read operations
    pub cache_ttl: Duration,
}

/// Node status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    /// Node is initializing
    Initializing,
    /// Node is syncing with primary
    Syncing,
    /// Node is ready to serve read requests
    Ready,
    /// Node is stale (too far behind primary)
    Stale,
    /// Node is in error state
    Error,
    /// Node is shutting down
    ShuttingDown,
}

/// Replication statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStats {
    /// Last sync timestamp
    pub last_sync: DateTime<Utc>,
    /// Number of keys synced in last operation
    pub keys_synced: u64,
    /// Sync duration in milliseconds
    pub sync_duration_ms: u64,
    /// Current lag behind primary in seconds
    pub lag_seconds: u64,
    /// Total keys in local storage
    pub total_keys: u64,
    /// Sync errors count
    pub sync_errors: u64,
}

/// Performance standby node
pub struct PerformanceStandbyNode {
    config: PerformanceStandbyConfig,
    storage: Arc<dyn StorageEngine>,
    status: Arc<RwLock<NodeStatus>>,
    stats: Arc<RwLock<ReplicationStats>>,
    cache: Arc<RwLock<HashMap<String, CachedValue>>>,
    shutdown_notify: Arc<Notify>,
    _sync_handle: Option<tokio::task::JoinHandle<()>>,
}

#[derive(Debug, Clone)]
struct CachedValue {
    value: Value,
    expires_at: Instant,
}

/// Cached value with TTL support
impl CachedValue {
    fn new(value: Value, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

impl PerformanceStandbyNode {
    pub fn new(config: PerformanceStandbyConfig, storage: Arc<dyn StorageEngine>) -> Self {
        let now = Utc::now();

        Self {
            config,
            storage,
            status: Arc::new(RwLock::new(NodeStatus::Initializing)),
            stats: Arc::new(RwLock::new(ReplicationStats {
                last_sync: now,
                keys_synced: 0,
                sync_duration_ms: 0,
                lag_seconds: 0,
                total_keys: 0,
                sync_errors: 0,
            })),
            cache: Arc::new(RwLock::new(HashMap::new())),
            shutdown_notify: Arc::new(Notify::new()),
            _sync_handle: None,
        }
    }

    /// Start the performance standby node
    pub async fn start(&mut self) -> Result<(), AppError> {
        *self.status.write().await = NodeStatus::Syncing;

        // Start the sync loop
        let sync_handle = self.start_sync_loop().await;
        self._sync_handle = Some(sync_handle);

        // Initial sync
        self.perform_sync().await?;

        *self.status.write().await = NodeStatus::Ready;

        Ok(())
    }

    /// Stop the performance standby node
    pub async fn stop(&self) -> Result<(), AppError> {
        *self.status.write().await = NodeStatus::ShuttingDown;
        self.shutdown_notify.notify_waiters();
        Ok(())
    }

    /// Get node status
    pub async fn get_status(&self) -> NodeStatus {
        self.status.read().await.clone()
    }

    /// Get replication statistics
    pub async fn get_stats(&self) -> ReplicationStats {
        self.stats.read().await.clone()
    }

    /// Read a secret (read-only operation)
    pub async fn read_secret(&self, path: &str) -> Result<Option<Value>, AppError> {
        // Check if node is ready
        let status = self.get_status().await;
        if status != NodeStatus::Ready {
            return Err(AppError::ServiceUnavailable(
                "Node is not ready for read operations".to_string(),
            ));
        }

        // Check cache first if enabled
        if self.config.enable_caching {
            if let Some(cached) = self.get_cached_value(path).await {
                if !cached.is_expired() {
                    return Ok(Some(cached.value));
                }
            }
        }

        // Read from local storage
        match self.storage.get(path).await {
            Ok(Some(entry)) => {
                let value: Value = serde_json::from_slice(&entry.value)
                    .map_err(|e| AppError::InternalError(format!("Failed to deserialize value: {}", e)))?;

                // Cache the value if caching is enabled
                if self.config.enable_caching {
                    self.set_cached_value(path, value.clone(), self.config.cache_ttl).await;
                }

                Ok(Some(value))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(AppError::InternalError(format!("Storage error: {}", e))),
        }
    }

    /// List secrets under a path (read-only operation)
    pub async fn list_secrets(&self, path: &str) -> Result<Vec<String>, AppError> {
        let status = self.get_status().await;
        if status != NodeStatus::Ready {
            return Err(AppError::ServiceUnavailable(
                "Node is not ready for read operations".to_string(),
            ));
        }

        self.storage
            .list(path)
            .await
            .map_err(|e| AppError::InternalError(format!("Storage error: {}", e)))
    }

    /// Get cached value
    async fn get_cached_value(&self, key: &str) -> Option<CachedValue> {
        let cache = self.cache.read().await;
        cache.get(key).cloned()
    }

    /// Set cached value
    async fn set_cached_value(&self, key: &str, value: Value, ttl: Duration) {
        let mut cache = self.cache.write().await;
        cache.insert(key.to_string(), CachedValue::new(value, ttl));
    }

    /// Start the sync loop
    async fn start_sync_loop(&self) -> tokio::task::JoinHandle<()> {
        let storage = self.storage.clone();
        let stats = self.stats.clone();
        let status = self.status.clone();
        let shutdown_notify = self.shutdown_notify.clone();
        let sync_interval = self.config.sync_interval;

        tokio::spawn(async move {
            let mut shutdown_notify = shutdown_notify.clone();

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(sync_interval) => {
                        if let Err(e) = Self::perform_sync_static(&storage, &stats, &status).await {
                            eprintln!("Sync error: {}", e);
                        }
                    }
                    _ = shutdown_notify.notified() => {
                        break;
                    }
                }
            }
        })
    }

    /// Perform synchronization with primary
    async fn perform_sync(&self) -> Result<(), AppError> {
        Self::perform_sync_static(&self.storage, &self.stats, &self.status).await
    }

    /// Static sync method for use in spawned tasks
    async fn perform_sync_static(
        storage: &Arc<dyn StorageEngine>,
        stats: &Arc<RwLock<ReplicationStats>>,
        status: &Arc<RwLock<NodeStatus>>,
    ) -> Result<(), AppError> {
        let sync_start = Instant::now();
        *status.write().await = NodeStatus::Syncing;

        // In a real implementation, this would:
        // 1. Connect to primary cluster
        // 2. Fetch latest data changes
        // 3. Apply changes to local storage
        // 4. Update replication statistics

        // For now, we'll simulate some sync activity
        tokio::time::sleep(Duration::from_millis(100)).await;

        let sync_duration = sync_start.elapsed();
        let mut stats_guard = stats.write().await;

        stats_guard.last_sync = Utc::now();
        stats_guard.sync_duration_ms = sync_duration.as_millis() as u64;
        stats_guard.keys_synced = 0; // Would be actual count in real implementation

        // Check lag (simulated)
        stats_guard.lag_seconds = 5; // Simulated 5 second lag

        // Update total keys count
        if let Ok(keys) = storage.list("").await {
            stats_guard.total_keys = keys.len() as u64;
        }

        // Check if lag is too high
        if stats_guard.lag_seconds > 60 { // 60 second threshold
            *status.write().await = NodeStatus::Stale;
        } else {
            *status.write().await = NodeStatus::Ready;
        }

        Ok(())
    }

    /// Clean expired cache entries
    pub async fn cleanup_cache(&self) -> usize {
        let mut cache = self.cache.write().await;
        let initial_size = cache.len();

        cache.retain(|_, cached_value| !cached_value.is_expired());

        initial_size - cache.len()
    }

    /// Force a manual sync
    pub async fn force_sync(&self) -> Result<(), AppError> {
        self.perform_sync().await
    }
}

/// Performance standby manager for managing multiple nodes
pub struct PerformanceStandbyManager {
    nodes: Arc<RwLock<HashMap<String, Arc<PerformanceStandbyNode>>>>,
    primary_address: String,
}

impl PerformanceStandbyManager {
    pub fn new(primary_address: String) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            primary_address,
        }
    }

    /// Add a performance standby node
    pub async fn add_node(
        &self,
        node_id: String,
        replication_token: String,
        storage: Arc<dyn StorageEngine>,
    ) -> Result<Arc<PerformanceStandbyNode>, AppError> {
        let config = PerformanceStandbyConfig {
            node_id: node_id.clone(),
            primary_address: self.primary_address.clone(),
            replication_token,
            sync_interval: Duration::from_secs(30),
            max_lag_seconds: 60,
            enable_caching: true,
            cache_ttl: Duration::from_secs(300),
        };

        let mut node = PerformanceStandbyNode::new(config, storage);
        node.start().await?;

        let node_arc = Arc::new(node);
        let mut nodes = self.nodes.write().await;
        nodes.insert(node_id, node_arc.clone());

        Ok(node_arc)
    }

    /// Remove a performance standby node
    pub async fn remove_node(&self, node_id: &str) -> Result<(), AppError> {
        let mut nodes = self.nodes.write().await;

        if let Some(node) = nodes.remove(node_id) {
            node.stop().await?;
        }

        Ok(())
    }

    /// Get a performance standby node
    pub async fn get_node(&self, node_id: &str) -> Option<Arc<PerformanceStandbyNode>> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// List all performance standby nodes
    pub async fn list_nodes(&self) -> Vec<String> {
        let nodes = self.nodes.read().await;
        nodes.keys().cloned().collect()
    }

    /// Get statistics for all nodes
    pub async fn get_all_stats(&self) -> HashMap<String, ReplicationStats> {
        let nodes = self.nodes.read().await;
        let mut all_stats = HashMap::new();

        for (node_id, node) in nodes.iter() {
            all_stats.insert(node_id.clone(), node.get_stats().await);
        }

        all_stats
    }

    /// Cleanup cache on all nodes
    pub async fn cleanup_all_caches(&self) -> HashMap<String, usize> {
        let nodes = self.nodes.read().await;
        let mut cleanup_results = HashMap::new();

        for (node_id, node) in nodes.iter() {
            let cleaned_count = node.cleanup_cache().await;
            cleanup_results.insert(node_id.clone(), cleaned_count);
        }

        cleanup_results
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageEntry;

    #[derive(Debug)]
    struct TestStorageEngine {
        data: Arc<std::sync::RwLock<HashMap<String, StorageEntry>>>,
    }

    #[async_trait::async_trait]
    impl StorageEngine for TestStorageEngine {
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data.get(key).cloned())
        }

        async fn put(&self, entry: StorageEntry) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    async fn create_test_node() -> (PerformanceStandbyNode, Arc<dyn StorageEngine>) {
        let storage: Arc<dyn StorageEngine> = Arc::new(TestStorageEngine {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
        });

        let config = PerformanceStandbyConfig {
            node_id: "test-node-1".to_string(),
            primary_address: "https://primary.example.com:8200".to_string(),
            replication_token: "test-token".to_string(),
            sync_interval: Duration::from_secs(1),
            max_lag_seconds: 60,
            enable_caching: true,
            cache_ttl: Duration::from_secs(60),
        };

        (PerformanceStandbyNode::new(config, storage.clone()), storage)
    }

    #[tokio::test]
    async fn test_node_creation() {
        let (node, _storage) = create_test_node().await;

        assert_eq!(node.get_status().await, NodeStatus::Initializing);
    }

    #[tokio::test]
    async fn test_node_start() {
        let (mut node, _storage) = create_test_node().await;

        let result = node.start().await;
        assert!(result.is_ok());

        assert_eq!(node.get_status().await, NodeStatus::Ready);
    }

    #[tokio::test]
    async fn test_read_operations() {
        let (node, storage) = create_test_node().await;

        // Add some test data to storage
        let test_entry = StorageEntry {
            key: "test/secret".to_string(),
            value: serde_json::to_vec(&serde_json::json!({"key": "value"})).unwrap(),
            metadata: HashMap::new(),
        };
        storage.put(test_entry).await.unwrap();

        // Start the node
        let mut node = node;
        node.start().await.unwrap();

        // Test read operation
        let result = node.read_secret("test/secret").await;
        assert!(result.is_ok());

        if let Some(value) = result.unwrap() {
            assert_eq!(value["key"], "value");
        } else {
            panic!("Expected to find secret");
        }
    }

    #[tokio::test]
    async fn test_list_operations() {
        let (node, storage) = create_test_node().await;

        // Add some test data to storage
        let entries = vec![
            StorageEntry {
                key: "test/secret1".to_string(),
                value: serde_json::to_vec(&serde_json::json!({"key": "value1"})).unwrap(),
                metadata: HashMap::new(),
            },
            StorageEntry {
                key: "test/secret2".to_string(),
                value: serde_json::to_vec(&serde_json::json!({"key": "value2"})).unwrap(),
                metadata: HashMap::new(),
            },
        ];

        for entry in entries {
            storage.put(entry).await.unwrap();
        }

        // Start the node
        let mut node = node;
        node.start().await.unwrap();

        // Test list operation
        let result = node.list_secrets("test").await;
        assert!(result.is_ok());

        let keys = result.unwrap();
        assert!(keys.contains(&"test/secret1".to_string()));
        assert!(keys.contains(&"test/secret2".to_string()));
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let (node, storage) = create_test_node().await;

        // Add test data
        let test_entry = StorageEntry {
            key: "cached/secret".to_string(),
            value: serde_json::to_vec(&serde_json::json!({"cached": "data"})).unwrap(),
            metadata: HashMap::new(),
        };
        storage.put(test_entry).await.unwrap();

        // Start node
        let mut node = node;
        node.start().await.unwrap();

        // First read should populate cache
        let result1 = node.read_secret("cached/secret").await;
        assert!(result1.is_ok());

        // Second read should use cache
        let result2 = node.read_secret("cached/secret").await;
        assert!(result2.is_ok());

        assert_eq!(result1.unwrap(), result2.unwrap());
    }
}
