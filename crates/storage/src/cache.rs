//! Cache abstraction for storage layer

use crate::{SecretEntry, StorageResult};
use async_trait::async_trait;
use secreton_domain::OAuthState;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

/// Cache backend trait
#[async_trait]
pub trait CacheBackend: std::fmt::Debug + Send + Sync {
    /// Get an entry from cache
    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>>;

    /// Set an entry in cache
    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> StorageResult<()>;

    /// Delete an entry from cache
    async fn delete(&self, key: &str) -> StorageResult<bool>;

    /// Check if key exists
    async fn exists(&self, key: &str) -> StorageResult<bool>;

    /// Clear all cache entries
    async fn clear(&self) -> StorageResult<()>;

    /// Get cache statistics
    async fn stats(&self) -> StorageResult<CacheStats>;
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub hit_count: u64,
    pub miss_count: u64,
    pub hit_rate: f64,
    pub entry_count: u64,
    pub memory_usage_bytes: u64,
    pub eviction_count: u64,
}

/// In-memory cache implementation for development/testing
#[derive(Debug)]
pub struct InMemoryCache {
    data: std::sync::RwLock<std::collections::HashMap<String, CacheEntry>>,
    stats: std::sync::RwLock<CacheStats>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    data: Vec<u8>,
    expires_at: Option<std::time::Instant>,
}

impl InMemoryCache {
    pub fn new() -> Self {
        Self {
            data: std::sync::RwLock::new(std::collections::HashMap::new()),
            stats: std::sync::RwLock::new(CacheStats {
                hit_count: 0,
                miss_count: 0,
                hit_rate: 0.0,
                entry_count: 0,
                memory_usage_bytes: 0,
                eviction_count: 0,
            }),
        }
    }

    fn cleanup_expired(&self) {
        let now = std::time::Instant::now();
        let mut data = self.data.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        let original_count = data.len();
        data.retain(|_, entry| entry.expires_at.is_none_or(|expires| expires > now));

        let evicted_count = original_count - data.len();
        stats.eviction_count += evicted_count as u64;
        stats.entry_count = data.len() as u64;
    }
}

impl Default for InMemoryCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl CacheBackend for InMemoryCache {
    async fn get(&self, key: &str) -> StorageResult<Option<Vec<u8>>> {
        self.cleanup_expired();

        let data = self.data.read().unwrap();
        let mut stats = self.stats.write().unwrap();

        match data.get(key) {
            Some(entry) => {
                if let Some(expires_at) = entry.expires_at
                    && std::time::Instant::now() > expires_at
                {
                    stats.miss_count += 1;
                    return Ok(None);
                }

                stats.hit_count += 1;
                Ok(Some(entry.data.clone()))
            }
            None => {
                stats.miss_count += 1;
                Ok(None)
            }
        }
    }

    async fn set(&self, key: &str, value: Vec<u8>, ttl: Option<Duration>) -> StorageResult<()> {
        let expires_at = ttl.map(|duration| std::time::Instant::now() + duration);

        let mut data = self.data.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        let entry = CacheEntry {
            data: value.clone(),
            expires_at,
        };

        let memory_delta = if let Some(old_entry) = data.get(key) {
            value.len() as i64 - old_entry.data.len() as i64
        } else {
            value.len() as i64 + key.len() as i64
        };

        data.insert(key.to_string(), entry);
        stats.entry_count = data.len() as u64;
        stats.memory_usage_bytes = (stats.memory_usage_bytes as i64 + memory_delta) as u64;

        Ok(())
    }

    async fn delete(&self, key: &str) -> StorageResult<bool> {
        let mut data = self.data.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        if let Some(entry) = data.remove(key) {
            stats.entry_count = data.len() as u64;
            stats.memory_usage_bytes = stats
                .memory_usage_bytes
                .saturating_sub(entry.data.len() as u64 + key.len() as u64);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn exists(&self, key: &str) -> StorageResult<bool> {
        let result = self.get(key).await?;
        Ok(result.is_some())
    }

    async fn clear(&self) -> StorageResult<()> {
        let mut data = self.data.write().unwrap();
        let mut stats = self.stats.write().unwrap();

        data.clear();
        stats.entry_count = 0;
        stats.memory_usage_bytes = 0;

        Ok(())
    }

    async fn stats(&self) -> StorageResult<CacheStats> {
        self.cleanup_expired();

        let mut stats = self.stats.write().unwrap();
        let total_requests = stats.hit_count + stats.miss_count;
        stats.hit_rate = if total_requests > 0 {
            stats.hit_count as f64 / total_requests as f64
        } else {
            0.0
        };

        Ok(stats.clone())
    }
}

/// Cached storage wrapper that adds caching to any storage backend
#[derive(Debug)]
pub struct CachedStorage<S: crate::StorageBackend, C: CacheBackend> {
    storage: S,
    cache: C,
    default_ttl: Duration,
}

impl<S, C> CachedStorage<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    pub fn new(storage: S, cache: C, default_ttl: Duration) -> Self {
        Self {
            storage,
            cache,
            default_ttl,
        }
    }

    fn cache_key_for_id(id: Uuid) -> String {
        format!("entry:id:{}", id)
    }

    fn cache_key_for_path(path: &str) -> String {
        format!("entry:path:{}", path)
    }
}

#[async_trait]
impl<S, C> crate::StorageBackend for CachedStorage<S, C>
where
    S: crate::StorageBackend,
    C: CacheBackend,
{
    async fn store(&self, entry: &SecretEntry) -> StorageResult<()> {
        let result = self.storage.store(entry).await;

        if result.is_ok() {
            // Cache the entry on successful store
            let serialized = bincode::serde::encode_to_vec(entry, bincode::config::standard())
                .unwrap_or_default();
            let _ = self
                .cache
                .set(
                    &Self::cache_key_for_id(entry.id),
                    serialized.clone(),
                    Some(self.default_ttl),
                )
                .await;
            let _ = self
                .cache
                .set(
                    &Self::cache_key_for_path(&entry.path),
                    serialized,
                    Some(self.default_ttl),
                )
                .await;
        }

        result
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<SecretEntry>> {
        let cache_key = Self::cache_key_for_id(id);

        // Try cache first
        if let Ok(Some(cached_data)) = self.cache.get(&cache_key).await
            && let Ok((entry, _)) = bincode::serde::decode_from_slice::<SecretEntry, _>(
                &cached_data,
                bincode::config::standard(),
            )
        {
            return Ok(Some(entry));
        }

        // Fall back to storage
        let entry = self.storage.get_by_id(id).await?;

        // Cache the result if found
        if let Some(ref entry) = entry
            && let Ok(serialized) =
                bincode::serde::encode_to_vec(entry, bincode::config::standard())
        {
            let _ = self
                .cache
                .set(&cache_key, serialized, Some(self.default_ttl))
                .await;
        }

        Ok(entry)
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<SecretEntry>> {
        let cache_key = Self::cache_key_for_path(path);

        // Try cache first
        if let Ok(Some(cached_data)) = self.cache.get(&cache_key).await
            && let Ok((entry, _)) = bincode::serde::decode_from_slice::<SecretEntry, _>(
                &cached_data,
                bincode::config::standard(),
            )
        {
            return Ok(Some(entry));
        }

        // Fall back to storage
        let entry = self.storage.get_by_path(path).await?;

        // Cache the result if found
        if let Some(ref entry) = entry
            && let Ok(serialized) =
                bincode::serde::encode_to_vec(entry, bincode::config::standard())
        {
            let _ = self
                .cache
                .set(&cache_key, serialized, Some(self.default_ttl))
                .await;
        }

        Ok(entry)
    }

    async fn update(&self, entry: &SecretEntry) -> StorageResult<()> {
        let result = self.storage.update(entry).await;

        if result.is_ok() {
            // Update cache
            if let Ok(serialized) =
                bincode::serde::encode_to_vec(entry, bincode::config::standard())
            {
                let _ = self
                    .cache
                    .set(
                        &Self::cache_key_for_id(entry.id),
                        serialized.clone(),
                        Some(self.default_ttl),
                    )
                    .await;
                let _ = self
                    .cache
                    .set(
                        &Self::cache_key_for_path(&entry.path),
                        serialized,
                        Some(self.default_ttl),
                    )
                    .await;
            }
        }

        result
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        // Get the entry first to find the path for cache invalidation
        let entry = self.storage.get_by_id(id).await?;

        let result = self.storage.delete_by_id(id).await?;

        if result {
            // Invalidate cache
            let _ = self.cache.delete(&Self::cache_key_for_id(id)).await;
            if let Some(entry) = entry {
                let _ = self
                    .cache
                    .delete(&Self::cache_key_for_path(&entry.path))
                    .await;
            }
        }

        Ok(result)
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        // Get the entry first to find the ID for cache invalidation
        let entry = self.storage.get_by_path(path).await?;

        let result = self.storage.delete_by_path(path).await?;

        if result {
            // Invalidate cache
            let _ = self.cache.delete(&Self::cache_key_for_path(path)).await;
            if let Some(entry) = entry {
                let _ = self.cache.delete(&Self::cache_key_for_id(entry.id)).await;
            }
        }

        Ok(result)
    }

    // For operations that return multiple entries, we don't cache them as they can be large
    // and the cache keys would be complex to manage
    async fn list(&self, params: &crate::QueryParams) -> StorageResult<Vec<SecretEntry>> {
        self.storage.list(params).await
    }

    async fn count(&self, params: &crate::QueryParams) -> StorageResult<u64> {
        self.storage.count(params).await
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        // Check cache first
        if self
            .cache
            .exists(&Self::cache_key_for_path(path))
            .await
            .unwrap_or(false)
        {
            return Ok(true);
        }

        self.storage.exists(path).await
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn crate::StorageTransaction>> {
        self.storage.begin_transaction().await
    }

    async fn health_check(&self) -> StorageResult<crate::HealthStatus> {
        self.storage.health_check().await
    }

    async fn get_stats(&self) -> StorageResult<crate::StorageStats> {
        self.storage.get_stats().await
    }

    async fn migrate(&self) -> StorageResult<()> {
        self.storage.migrate().await
    }

    async fn store_oauth_state(&self, state: &OAuthState) -> StorageResult<()> {
        self.storage.store_oauth_state(state).await
    }

    async fn get_oauth_state(&self, state: &str) -> StorageResult<Option<OAuthState>> {
        self.storage.get_oauth_state(state).await
    }

    async fn delete_expired_oauth_states(&self) -> StorageResult<u64> {
        self.storage.delete_expired_oauth_states().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_in_memory_cache_set_get_and_stats() {
        let cache = InMemoryCache::new();
        let key = "secreton:test";

        // Miss before value set
        assert!(cache.get(key).await.unwrap().is_none());

        cache
            .set(key, b"encrypted-data".to_vec(), None)
            .await
            .unwrap();

        let cached = cache.get(key).await.unwrap();
        assert_eq!(cached, Some(b"encrypted-data".to_vec()));

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.hit_count, 1);
        assert_eq!(stats.miss_count, 1);
        assert_eq!(stats.entry_count, 1);
        assert!(stats.hit_rate > 0.0);
    }

    #[tokio::test]
    async fn test_in_memory_cache_expiration() {
        let cache = InMemoryCache::new();
        let key = "secreton:expiring";

        cache
            .set(key, b"temp".to_vec(), Some(Duration::from_millis(50)))
            .await
            .unwrap();

        assert!(cache.get(key).await.unwrap().is_some());

        sleep(Duration::from_millis(60)).await;

        assert!(cache.get(key).await.unwrap().is_none());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.entry_count, 0);
        assert!(stats.eviction_count >= 1);
    }

    #[tokio::test]
    async fn test_in_memory_cache_exists_and_clear() {
        let cache = InMemoryCache::new();
        let key = "secreton:clear";

        cache.set(key, b"value".to_vec(), None).await.unwrap();
        assert!(cache.exists(key).await.unwrap());

        cache.clear().await.unwrap();
        assert!(!cache.exists(key).await.unwrap());

        let stats = cache.stats().await.unwrap();
        assert_eq!(stats.entry_count, 0);
        assert_eq!(stats.memory_usage_bytes, 0);
    }
}
