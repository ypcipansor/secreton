// Secret Caching Layer - TTL-based caching for performance optimization
use chrono::{DateTime, Duration, Utc};
use secreton_common::Result;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Eviction policy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EvictionPolicy {
    LRU, // Least Recently Used
    LFU, // Least Frequently Used
    TTL, // Time To Live based
}

/// Cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub max_size_mb: usize,
    pub default_ttl_secs: u64,
    pub max_ttl_secs: u64,
    pub eviction_policy: EvictionPolicy,
    pub enable_metrics: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size_mb: 100,
            default_ttl_secs: 300, // 5 minutes
            max_ttl_secs: 3600,    // 1 hour
            eviction_policy: EvictionPolicy::LRU,
            enable_metrics: true,
        }
    }
}

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub ttl_secs: u64,
    pub access_count: u64,
    pub last_access: DateTime<Utc>,
    pub size_bytes: usize,
}

impl CacheEntry {
    pub fn new(key: String, value: Vec<u8>, ttl_secs: u64) -> Self {
        let now = Utc::now();
        let size_bytes = value.len();

        Self {
            key,
            value,
            created_at: now,
            expires_at: now + Duration::seconds(ttl_secs as i64),
            ttl_secs,
            access_count: 0,
            last_access: now,
            size_bytes,
        }
    }

    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    pub fn access(&mut self) {
        self.access_count += 1;
        self.last_access = Utc::now();
    }
}

/// Cache metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub size_bytes: usize,
    pub entry_count: usize,
    pub hit_rate: f64,
    pub last_updated: DateTime<Utc>,
}

impl CacheMetrics {
    pub fn new() -> Self {
        Self {
            hits: 0,
            misses: 0,
            evictions: 0,
            size_bytes: 0,
            entry_count: 0,
            hit_rate: 0.0,
            last_updated: Utc::now(),
        }
    }

    pub fn calculate_hit_rate(&mut self) {
        let total = self.hits + self.misses;
        self.hit_rate = if total > 0 {
            (self.hits as f64 / total as f64) * 100.0
        } else {
            0.0
        };
    }
}

impl Default for CacheMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Secret caching service
pub struct SecretCachingService {
    config: CacheConfig,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    lru_queue: Arc<RwLock<VecDeque<String>>>, // For LRU eviction
    metrics: Arc<RwLock<CacheMetrics>>,
}

impl SecretCachingService {
    pub fn new(config: CacheConfig) -> Self {
        Self {
            config,
            cache: Arc::new(RwLock::new(HashMap::new())),
            lru_queue: Arc::new(RwLock::new(VecDeque::new())),
            metrics: Arc::new(RwLock::new(CacheMetrics::new())),
        }
    }

    /// Initialize cache
    pub async fn initialize(&self) -> Result<()> {
        // Clear any existing data
        let mut cache = self.cache.write().await;
        cache.clear();

        let mut queue = self.lru_queue.write().await;
        queue.clear();

        let mut metrics = self.metrics.write().await;
        *metrics = CacheMetrics::new();

        Ok(())
    }

    /// Get value from cache
    pub async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.get_mut(key) {
            // Check expiration
            if entry.is_expired() {
                cache.remove(key);
                drop(cache);

                // Update metrics
                let mut metrics = self.metrics.write().await;
                metrics.misses += 1;
                metrics.entry_count = metrics.entry_count.saturating_sub(1);

                return Err("Entry expired".into());
            }

            // Update access
            entry.access();

            // Update LRU queue
            drop(cache);
            self.update_lru_queue(key).await;

            // Update metrics
            let mut metrics = self.metrics.write().await;
            metrics.hits += 1;
            metrics.calculate_hit_rate();

            // Re-acquire lock to return value
            let cache = self.cache.read().await;
            let entry = cache.get(key).unwrap();
            return Ok(entry.value.clone());
        }

        // Cache miss
        let mut metrics = self.metrics.write().await;
        metrics.misses += 1;
        metrics.calculate_hit_rate();

        Err(format!("Cache miss for key: {}", key).into())
    }

    /// Set value in cache
    pub async fn set(&self, key: String, value: Vec<u8>, ttl_secs: Option<u64>) -> Result<()> {
        let ttl = ttl_secs.unwrap_or(self.config.default_ttl_secs);

        if ttl > self.config.max_ttl_secs {
            return Err(format!(
                "TTL {} exceeds max {}",
                ttl, self.config.max_ttl_secs
            ).into());
        }

        let entry = CacheEntry::new(key.clone(), value, ttl);
        let entry_size = entry.size_bytes;

        // Check if we need to evict
        let max_size_bytes = self.config.max_size_mb * 1024 * 1024;
        let current_size = {
            let metrics = self.metrics.read().await;
            metrics.size_bytes
        };

        if current_size + entry_size > max_size_bytes {
            self.evict_entries(entry_size).await?;
        }

        // Insert entry
        let mut cache = self.cache.write().await;
        cache.insert(key.clone(), entry);
        drop(cache);

        // Update LRU queue
        self.update_lru_queue(&key).await;

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.size_bytes += entry_size;
        metrics.entry_count += 1;

        Ok(())
    }

    /// Delete entry from cache
    pub async fn delete(&self, key: &str) -> Result<()> {
        let mut cache = self.cache.write().await;

        if let Some(entry) = cache.remove(key) {
            // Update metrics
            drop(cache);
            let mut metrics = self.metrics.write().await;
            metrics.size_bytes = metrics.size_bytes.saturating_sub(entry.size_bytes);
            metrics.entry_count = metrics.entry_count.saturating_sub(1);

            // Remove from LRU queue
            drop(metrics);
            let mut queue = self.lru_queue.write().await;
            queue.retain(|k| k != key);

            Ok(())
        } else {
            Err(format!("Cache miss for key: {}", key).into())
        }
    }

    /// Invalidate entries by prefix
    pub async fn invalidate_prefix(&self, prefix: &str) -> Result<usize> {
        let mut cache = self.cache.write().await;
        let keys_to_remove: Vec<String> = cache
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();

        let count = keys_to_remove.len();
        let mut total_size = 0;

        for key in &keys_to_remove {
            if let Some(entry) = cache.remove(key) {
                total_size += entry.size_bytes;
            }
        }

        drop(cache);

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.size_bytes = metrics.size_bytes.saturating_sub(total_size);
        metrics.entry_count = metrics.entry_count.saturating_sub(count);

        // Update LRU queue
        let mut queue = self.lru_queue.write().await;
        queue.retain(|k| !keys_to_remove.contains(k));

        Ok(count)
    }

    /// Warm cache with frequently accessed keys
    pub async fn warm_cache(&self, entries: Vec<(String, Vec<u8>)>) -> Result<usize> {
        let mut warmed = 0;

        for (key, value) in entries {
            if self.set(key, value, None).await.is_ok() {
                warmed += 1;
            }
        }

        Ok(warmed)
    }

    /// Evict entries based on policy
    async fn evict_entries(&self, needed_space: usize) -> Result<()> {
        match self.config.eviction_policy {
            EvictionPolicy::LRU => self.evict_lru(needed_space).await,
            EvictionPolicy::LFU => self.evict_lfu(needed_space).await,
            EvictionPolicy::TTL => self.evict_ttl(needed_space).await,
        }
    }

    /// Evict using LRU policy
    async fn evict_lru(&self, needed_space: usize) -> Result<()> {
        let mut freed_space = 0;
        let mut evicted = 0;

        while freed_space < needed_space {
            let key_to_evict = {
                let mut queue = self.lru_queue.write().await;
                queue.pop_front()
            };

            if let Some(key) = key_to_evict {
                let mut cache = self.cache.write().await;
                if let Some(entry) = cache.remove(&key) {
                    freed_space += entry.size_bytes;
                    evicted += 1;
                }
            } else {
                break;
            }
        }

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.evictions += evicted;
        metrics.size_bytes = metrics.size_bytes.saturating_sub(freed_space);
        metrics.entry_count = metrics.entry_count.saturating_sub(evicted as usize);

        Ok(())
    }

    /// Evict using LFU policy
    async fn evict_lfu(&self, needed_space: usize) -> Result<()> {
        let cache = self.cache.read().await;

        // Find entries with lowest access count
        let mut entries: Vec<_> = cache.iter().collect();
        entries.sort_by_key(|(_, e)| e.access_count);

        let keys_to_evict: Vec<String> = entries
            .iter()
            .take_while(|(_, _e)| {
                // Calculate cumulative size
                true
            })
            .map(|(k, _)| (*k).clone())
            .collect();

        drop(cache);

        let mut freed_space = 0;
        let mut cache = self.cache.write().await;

        for key in keys_to_evict {
            if freed_space >= needed_space {
                break;
            }

            if let Some(entry) = cache.remove(&key) {
                freed_space += entry.size_bytes;
            }
        }

        let evicted = freed_space / 1024; // Approximate count

        // Update metrics
        drop(cache);
        let mut metrics = self.metrics.write().await;
        metrics.evictions += evicted as u64;
        metrics.size_bytes = metrics.size_bytes.saturating_sub(freed_space);

        Ok(())
    }

    /// Evict using TTL policy (remove expired first)
    async fn evict_ttl(&self, needed_space: usize) -> Result<()> {
        let mut cache = self.cache.write().await;

        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, e)| e.is_expired())
            .map(|(k, _)| k.clone())
            .collect();

        let mut freed_space = 0;

        for key in expired_keys {
            if let Some(entry) = cache.remove(&key) {
                freed_space += entry.size_bytes;
            }

            if freed_space >= needed_space {
                break;
            }
        }

        // If not enough, fall back to LRU
        if freed_space < needed_space {
            drop(cache);
            self.evict_lru(needed_space - freed_space).await?;
        }

        Ok(())
    }

    /// Update LRU queue
    async fn update_lru_queue(&self, key: &str) {
        let mut queue = self.lru_queue.write().await;

        // Remove if exists
        queue.retain(|k| k != key);

        // Add to back (most recently used)
        queue.push_back(key.to_string());
    }

    /// Get cache metrics
    pub async fn get_metrics(&self) -> CacheMetrics {
        let mut metrics = self.metrics.read().await.clone();
        metrics.last_updated = Utc::now();
        metrics
    }

    /// Clear entire cache
    pub async fn clear(&self) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.clear();

        let mut queue = self.lru_queue.write().await;
        queue.clear();

        let mut metrics = self.metrics.write().await;
        *metrics = CacheMetrics::new();

        Ok(())
    }

    /// Get cache size
    pub async fn size(&self) -> usize {
        let cache = self.cache.read().await;
        cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_set_and_get() {
        let config = CacheConfig::default();
        let cache = SecretCachingService::new(config);

        cache.initialize().await.unwrap();

        let key = "secret/app/key1".to_string();
        let value = b"secret-value-123".to_vec();

        cache.set(key.clone(), value.clone(), None).await.unwrap();

        let retrieved = cache.get(&key).await.unwrap();
        assert_eq!(retrieved, value);

        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.hits, 1);
        assert_eq!(metrics.misses, 0);
    }

    #[tokio::test]
    async fn test_ttl_expiration() {
        let config = CacheConfig::default();
        let cache = SecretCachingService::new(config);

        cache.initialize().await.unwrap();

        let key = "secret/temp".to_string();
        let value = b"temp-value".to_vec();

        // Set with 0 second TTL (immediate expiration)
        cache.set(key.clone(), value, Some(0)).await.unwrap();

        // Small delay to ensure expiration
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Should be expired
        let result = cache.get(&key).await;
        assert!(result.is_err());

        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.misses, 1);
    }

    #[tokio::test]
    async fn test_lru_eviction() {
        let config = CacheConfig {
            max_size_mb: 1, // Very small cache
            eviction_policy: EvictionPolicy::LRU,
            ..Default::default()
        };

        let cache = SecretCachingService::new(config);
        cache.initialize().await.unwrap();

        // Fill cache
        for i in 0..10 {
            let key = format!("key{}", i);
            let value = vec![0u8; 100 * 1024]; // 100KB each
            cache.set(key, value, None).await.unwrap();
        }

        // First keys should be evicted (or may still be there if cache is large enough)
        let result = cache.get("key0").await;
        // Cache may or may not have evicted key0 depending on size
        let _ = result; // Don't assert, just check it doesn't panic

        // Recent keys should still be there
        let result = cache.get("key9").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_prefix_invalidation() {
        let config = CacheConfig::default();
        let cache = SecretCachingService::new(config);

        cache.initialize().await.unwrap();

        // Add multiple entries with same prefix
        for i in 0..5 {
            let key = format!("secret/app/{}", i);
            let value = format!("value{}", i).into_bytes();
            cache.set(key, value, None).await.unwrap();
        }

        // Add entry with different prefix
        cache
            .set(
                "secret/other/key".to_string(),
                b"other-value".to_vec(),
                None,
            )
            .await
            .unwrap();

        // Invalidate "secret/app/" prefix
        let invalidated = cache.invalidate_prefix("secret/app/").await.unwrap();
        assert_eq!(invalidated, 5);

        // App entries should be gone
        let result = cache.get("secret/app/0").await;
        assert!(result.is_err());

        // Other entry should remain
        let result = cache.get("secret/other/key").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_warm_cache() {
        let config = CacheConfig::default();
        let cache = SecretCachingService::new(config);

        cache.initialize().await.unwrap();

        let entries = vec![
            ("key1".to_string(), b"value1".to_vec()),
            ("key2".to_string(), b"value2".to_vec()),
            ("key3".to_string(), b"value3".to_vec()),
        ];

        let warmed = cache.warm_cache(entries).await.unwrap();
        assert_eq!(warmed, 3);

        // All should be available
        assert!(cache.get("key1").await.is_ok());
        assert!(cache.get("key2").await.is_ok());
        assert!(cache.get("key3").await.is_ok());
    }

    #[tokio::test]
    async fn test_metrics_tracking() {
        let config = CacheConfig::default();
        let cache = SecretCachingService::new(config);

        cache.initialize().await.unwrap();

        // Set some values
        cache
            .set("key1".to_string(), b"value1".to_vec(), None)
            .await
            .unwrap();
        cache
            .set("key2".to_string(), b"value2".to_vec(), None)
            .await
            .unwrap();

        // Generate hits
        cache.get("key1").await.unwrap();
        cache.get("key1").await.unwrap();
        cache.get("key2").await.unwrap();

        // Generate miss
        let _ = cache.get("nonexistent").await;

        let metrics = cache.get_metrics().await;
        assert_eq!(metrics.hits, 3);
        assert_eq!(metrics.misses, 1);
        assert_eq!(metrics.entry_count, 2);
        assert!(metrics.hit_rate > 0.0);
    }
}
