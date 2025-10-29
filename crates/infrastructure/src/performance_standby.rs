// Performance Standby - Read replicas for scaling reads
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum StandbyError {
    #[error("Standby node not found: {0}")]
    NotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Not in standby mode")]
    NotInStandbyMode,
    #[error("Sync failed: {0}")]
    SyncFailed(String),
    #[error("Standby not ready")]
    NotReady,
}

pub type Result<T> = std::result::Result<T, StandbyError>;

/// Standby node state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StandbyState {
    /// Standby is initializing
    Initializing,
    /// Performing initial sync
    Syncing,
    /// Ready to serve read requests
    Active,
    /// Sync failed, retrying
    Error { reason: String },
    /// Standby is being shut down
    ShuttingDown,
}

/// Standby node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandbyConfig {
    pub node_id: String,
    pub primary_address: String,
    pub sync_interval_seconds: u64,
    pub read_only: bool,
    pub enable_caching: bool,
    pub cache_ttl_seconds: u64,
    pub max_sync_lag_seconds: u64,
}

/// Standby node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandbyNode {
    pub node_id: String,
    pub config: StandbyConfig,
    pub state: StandbyState,
    pub last_sync: Option<DateTime<Utc>>,
    pub next_sync: Option<DateTime<Utc>>,
    pub sync_lag_ms: u64,
    pub sync_count: u64,
    pub failed_syncs: u64,
    pub read_requests_served: u64,
    pub created_at: DateTime<Utc>,
}

/// Cached data entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub cached_at: DateTime<Utc>,
    pub ttl_seconds: u64,
}

impl CacheEntry {
    pub fn is_expired(&self) -> bool {
        let elapsed = Utc::now() - self.cached_at;
        elapsed.num_seconds() >= self.ttl_seconds as i64
    }
}

/// Sync operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResult {
    pub node_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub items_synced: u64,
    pub bytes_synced: u64,
    pub success: bool,
    pub error: Option<String>,
}

/// Read request statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadStats {
    pub node_id: String,
    pub total_reads: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub average_latency_ms: u64,
    pub last_request: Option<DateTime<Utc>>,
}

impl ReadStats {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            total_reads: 0,
            cache_hits: 0,
            cache_misses: 0,
            average_latency_ms: 0,
            last_request: None,
        }
    }

    pub fn record_read(&mut self, cache_hit: bool, latency_ms: u64) {
        self.total_reads += 1;
        self.last_request = Some(Utc::now());

        if cache_hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }

        // Update average latency
        self.average_latency_ms =
            ((self.average_latency_ms * (self.total_reads - 1)) + latency_ms) / self.total_reads;
    }

    pub fn cache_hit_rate(&self) -> f64 {
        if self.total_reads == 0 {
            return 0.0;
        }
        self.cache_hits as f64 / self.total_reads as f64
    }
}

impl StandbyConfig {
    pub fn new(node_id: String, primary_address: String) -> Self {
        Self {
            node_id,
            primary_address,
            sync_interval_seconds: 5,
            read_only: true,
            enable_caching: true,
            cache_ttl_seconds: 60,
            max_sync_lag_seconds: 30,
        }
    }

    pub fn with_sync_interval(mut self, interval_seconds: u64) -> Self {
        self.sync_interval_seconds = interval_seconds;
        self
    }

    pub fn with_cache_ttl(mut self, ttl_seconds: u64) -> Self {
        self.cache_ttl_seconds = ttl_seconds;
        self
    }

    pub fn with_max_lag(mut self, max_lag_seconds: u64) -> Self {
        self.max_sync_lag_seconds = max_lag_seconds;
        self
    }
}

impl StandbyNode {
    pub fn new(config: StandbyConfig) -> Self {
        Self {
            node_id: config.node_id.clone(),
            config,
            state: StandbyState::Initializing,
            last_sync: None,
            next_sync: None,
            sync_lag_ms: 0,
            sync_count: 0,
            failed_syncs: 0,
            read_requests_served: 0,
            created_at: Utc::now(),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == StandbyState::Active
    }

    pub fn is_sync_lagging(&self) -> bool {
        if let Some(last_sync) = self.last_sync {
            let elapsed = Utc::now() - last_sync;
            elapsed.num_seconds() > self.config.max_sync_lag_seconds as i64
        } else {
            true // Never synced
        }
    }

    pub fn update_sync_success(&mut self, _items: u64, _bytes: u64, duration_ms: u64) {
        self.last_sync = Some(Utc::now());
        self.next_sync =
            Some(Utc::now() + chrono::Duration::seconds(self.config.sync_interval_seconds as i64));
        self.sync_count += 1;
        self.sync_lag_ms = duration_ms;
        self.state = StandbyState::Active;
    }

    pub fn update_sync_failure(&mut self, reason: String) {
        self.failed_syncs += 1;
        self.state = StandbyState::Error { reason };
    }

    pub fn increment_reads(&mut self) {
        self.read_requests_served += 1;
    }
}

/// Performance standby service
pub struct PerformanceStandbyService {
    standby_nodes: Arc<RwLock<HashMap<String, StandbyNode>>>,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    read_stats: Arc<RwLock<HashMap<String, ReadStats>>>,
    sync_history: Arc<RwLock<Vec<SyncResult>>>,
}

impl PerformanceStandbyService {
    pub fn new() -> Self {
        Self {
            standby_nodes: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(HashMap::new())),
            read_stats: Arc::new(RwLock::new(HashMap::new())),
            sync_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register a new standby node
    pub async fn register_standby(&self, config: StandbyConfig) -> Result<StandbyNode> {
        let node_id = config.node_id.clone();
        let standby = StandbyNode::new(config);

        let mut nodes = self.standby_nodes.write().await;
        nodes.insert(node_id.clone(), standby.clone());

        // Initialize read stats
        drop(nodes);
        let mut stats = self.read_stats.write().await;
        stats.insert(node_id, ReadStats::new(standby.node_id.clone()));

        Ok(standby)
    }

    /// Start standby mode for a node
    pub async fn start_standby(&self, node_id: &str) -> Result<()> {
        let mut nodes = self.standby_nodes.write().await;
        let standby = nodes
            .get_mut(node_id)
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))?;

        standby.state = StandbyState::Syncing;
        standby.next_sync = Some(Utc::now());

        Ok(())
    }

    /// Perform synchronization from primary
    pub async fn sync_from_primary(&self, node_id: &str) -> Result<SyncResult> {
        let start_time = Utc::now();

        let mut nodes = self.standby_nodes.write().await;
        let standby = nodes
            .get_mut(node_id)
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))?;

        // Simulate sync operation (in production, would fetch from primary)
        let (success, items, bytes) = self.simulate_sync(&standby.config.primary_address).await;

        let duration_ms = (Utc::now() - start_time).num_milliseconds() as u64;

        let result = if success {
            standby.update_sync_success(items, bytes, duration_ms);

            SyncResult {
                node_id: node_id.to_string(),
                started_at: start_time,
                completed_at: Utc::now(),
                items_synced: items,
                bytes_synced: bytes,
                success: true,
                error: None,
            }
        } else {
            let error_msg = "Simulated sync failure".to_string();
            standby.update_sync_failure(error_msg.clone());

            SyncResult {
                node_id: node_id.to_string(),
                started_at: start_time,
                completed_at: Utc::now(),
                items_synced: 0,
                bytes_synced: 0,
                success: false,
                error: Some(error_msg),
            }
        };

        // Record sync history
        drop(nodes);
        let mut history = self.sync_history.write().await;
        history.push(result.clone());

        Ok(result)
    }

    /// Read data from standby (with caching)
    pub async fn read(&self, node_id: &str, key: &str) -> Result<Option<Vec<u8>>> {
        let start_time = Utc::now();

        // Check if standby is ready
        let nodes = self.standby_nodes.read().await;
        let standby = nodes
            .get(node_id)
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))?;

        if !standby.is_ready() {
            return Err(StandbyError::NotReady);
        }

        let enable_caching = standby.config.enable_caching;
        drop(nodes);

        let mut cache_hit = false;
        let result = if enable_caching {
            // Try cache first
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(key) {
                if !entry.is_expired() {
                    cache_hit = true;
                    Some(entry.value.clone())
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        let latency_ms = (Utc::now() - start_time).num_milliseconds() as u64;

        // Update stats
        let mut stats = self.read_stats.write().await;
        if let Some(stat) = stats.get_mut(node_id) {
            stat.record_read(cache_hit, latency_ms);
        }

        // Increment read counter
        let mut nodes = self.standby_nodes.write().await;
        if let Some(standby) = nodes.get_mut(node_id) {
            standby.increment_reads();
        }

        Ok(result)
    }

    /// Write to cache (called after reading from primary)
    pub async fn cache_write(&self, key: String, value: Vec<u8>, ttl_seconds: u64) -> Result<()> {
        let mut cache = self.cache.write().await;

        cache.insert(
            key.clone(),
            CacheEntry {
                key,
                value,
                cached_at: Utc::now(),
                ttl_seconds,
            },
        );

        Ok(())
    }

    /// Invalidate cache entry
    pub async fn invalidate_cache(&self, key: &str) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.remove(key);
        Ok(())
    }

    /// Clear all cache
    pub async fn clear_cache(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.clear();
        Ok(())
    }

    /// Get standby node information
    pub async fn get_standby(&self, node_id: &str) -> Result<StandbyNode> {
        let nodes = self.standby_nodes.read().await;
        nodes
            .get(node_id)
            .cloned()
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))
    }

    /// List all standby nodes
    pub async fn list_standbys(&self) -> Vec<StandbyNode> {
        let nodes = self.standby_nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get read statistics
    pub async fn get_read_stats(&self, node_id: &str) -> Result<ReadStats> {
        let stats = self.read_stats.read().await;
        stats
            .get(node_id)
            .cloned()
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))
    }

    /// Get sync history
    pub async fn get_sync_history(&self, node_id: Option<&str>, limit: usize) -> Vec<SyncResult> {
        let history = self.sync_history.read().await;

        history
            .iter()
            .filter(|h| node_id.map_or(true, |id| h.node_id == id))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Check if sync is needed
    pub async fn should_sync(&self, node_id: &str) -> Result<bool> {
        let nodes = self.standby_nodes.read().await;
        let standby = nodes
            .get(node_id)
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))?;

        if let Some(next_sync) = standby.next_sync {
            Ok(Utc::now() >= next_sync)
        } else {
            Ok(true) // Never synced, sync needed
        }
    }

    /// Stop standby mode
    pub async fn stop_standby(&self, node_id: &str) -> Result<()> {
        let mut nodes = self.standby_nodes.write().await;
        let standby = nodes
            .get_mut(node_id)
            .ok_or_else(|| StandbyError::NotFound(node_id.to_string()))?;

        standby.state = StandbyState::ShuttingDown;
        Ok(())
    }

    /// Simulate sync from primary (placeholder)
    async fn simulate_sync(&self, _primary_address: &str) -> (bool, u64, u64) {
        // In production, would make HTTP request to primary
        // Returns (success, items_synced, bytes_synced)
        (true, 100, 10240)
    }

    /// Cleanup expired cache entries
    pub async fn cleanup_cache(&self) -> u64 {
        let mut cache = self.cache.write().await;
        let initial_count = cache.len();

        cache.retain(|_, entry| !entry.is_expired());

        (initial_count - cache.len()) as u64
    }
}

impl Default for PerformanceStandbyService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_standby() {
        let service = PerformanceStandbyService::new();

        let config = StandbyConfig::new("standby-1".to_string(), "http://primary:8200".to_string());

        let standby = service.register_standby(config).await.unwrap();
        assert_eq!(standby.node_id, "standby-1");
        assert_eq!(standby.state, StandbyState::Initializing);
    }

    #[tokio::test]
    async fn test_standby_sync() {
        let service = PerformanceStandbyService::new();

        let config = StandbyConfig::new("standby-1".to_string(), "http://primary:8200".to_string());

        service.register_standby(config).await.unwrap();
        service.start_standby("standby-1").await.unwrap();

        let result = service.sync_from_primary("standby-1").await.unwrap();
        assert!(result.success);
        assert!(result.items_synced > 0);

        let standby = service.get_standby("standby-1").await.unwrap();
        assert_eq!(standby.state, StandbyState::Active);
        assert_eq!(standby.sync_count, 1);
    }

    #[tokio::test]
    async fn test_read_with_caching() {
        let service = PerformanceStandbyService::new();

        let config = StandbyConfig::new("standby-1".to_string(), "http://primary:8200".to_string());

        service.register_standby(config).await.unwrap();
        service.start_standby("standby-1").await.unwrap();
        service.sync_from_primary("standby-1").await.unwrap();

        // Write to cache
        service
            .cache_write("key1".to_string(), b"value1".to_vec(), 60)
            .await
            .unwrap();

        // Read from cache
        let result = service.read("standby-1", "key1").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), b"value1");

        // Check stats
        let stats = service.get_read_stats("standby-1").await.unwrap();
        assert_eq!(stats.total_reads, 1);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_hit_rate(), 1.0);
    }

    #[tokio::test]
    async fn test_cache_expiration() {
        let mut entry = CacheEntry {
            key: "test".to_string(),
            value: b"data".to_vec(),
            cached_at: Utc::now() - chrono::Duration::seconds(120),
            ttl_seconds: 60,
        };

        assert!(entry.is_expired());

        entry.cached_at = Utc::now();
        assert!(!entry.is_expired());
    }

    #[tokio::test]
    async fn test_sync_lag_detection() {
        let config = StandbyConfig::new("standby-1".to_string(), "http://primary:8200".to_string())
            .with_max_lag(10);

        let mut standby = StandbyNode::new(config);

        // Just synced - not lagging
        standby.last_sync = Some(Utc::now());
        assert!(!standby.is_sync_lagging());

        // Old sync - lagging
        standby.last_sync = Some(Utc::now() - chrono::Duration::seconds(20));
        assert!(standby.is_sync_lagging());
    }

    #[tokio::test]
    async fn test_read_stats() {
        let mut stats = ReadStats::new("standby-1".to_string());

        stats.record_read(true, 10);
        stats.record_read(true, 20);
        stats.record_read(false, 30);

        assert_eq!(stats.total_reads, 3);
        assert_eq!(stats.cache_hits, 2);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.cache_hit_rate(), 2.0 / 3.0);
        assert_eq!(stats.average_latency_ms, 20);
    }
}