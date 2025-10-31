//! Key store trait and implementations
//!
//! This module defines the KeyStore trait and provides in-memory and persistent implementations.

use super::types::{KeyConfig, KeyEntry};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Trait for key storage backends
///
/// Implementations of this trait provide persistent storage for cryptographic keys
/// with support for key versioning, rotation, and lifecycle management.
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Store a key entry
    async fn store_key(&self, entry: KeyEntry) -> Result<(), anyhow::Error>;

    /// Retrieve a key by ID
    async fn get_key(&self, key_id: &str) -> Result<Option<KeyEntry>, anyhow::Error>;

    /// List all keys
    async fn list_keys(&self) -> Result<Vec<KeyEntry>, anyhow::Error>;

    /// Delete a key
    async fn delete_key(&self, key_id: &str) -> Result<(), anyhow::Error>;

    /// Get the active key
    async fn get_active_key(&self) -> Result<Option<KeyEntry>, anyhow::Error>;

    /// Set a key as active
    async fn set_active_key(&self, key_id: &str) -> Result<(), anyhow::Error>;

    /// Get keys that need rotation based on config
    async fn get_keys_due_for_rotation(
        &self,
        config: &KeyConfig,
    ) -> Result<Vec<KeyEntry>, anyhow::Error>;

    /// Get expired keys that should be cleaned up
    async fn get_expired_keys(&self, config: &KeyConfig) -> Result<Vec<KeyEntry>, anyhow::Error>;
}

/// In-memory key store implementation
///
/// This implementation stores keys in memory and is suitable for testing
/// or single-instance deployments. Keys are lost when the process terminates.
#[derive(Debug, Clone)]
pub struct MemoryKeyStore {
    keys: Arc<RwLock<HashMap<String, KeyEntry>>>,
}

impl MemoryKeyStore {
    /// Create a new empty memory key store
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl KeyStore for MemoryKeyStore {
    async fn store_key(&self, entry: KeyEntry) -> Result<(), anyhow::Error> {
        let mut keys = self.keys.write().await;
        keys.insert(entry.id.clone(), entry);
        Ok(())
    }

    async fn get_key(&self, key_id: &str) -> Result<Option<KeyEntry>, anyhow::Error> {
        let keys = self.keys.read().await;
        Ok(keys.get(key_id).cloned())
    }

    async fn list_keys(&self) -> Result<Vec<KeyEntry>, anyhow::Error> {
        let keys = self.keys.read().await;
        Ok(keys.values().cloned().collect())
    }

    async fn delete_key(&self, key_id: &str) -> Result<(), anyhow::Error> {
        let mut keys = self.keys.write().await;
        keys.remove(key_id);
        Ok(())
    }

    async fn get_active_key(&self) -> Result<Option<KeyEntry>, anyhow::Error> {
        let keys = self.keys.read().await;
        Ok(keys.values().find(|k| k.active).cloned())
    }

    async fn set_active_key(&self, key_id: &str) -> Result<(), anyhow::Error> {
        let mut keys = self.keys.write().await;
        // Deactivate all keys
        for key in keys.values_mut() {
            key.active = false;
        }
        // Activate the specified key
        if let Some(key) = keys.get_mut(key_id) {
            key.active = true;
        }
        Ok(())
    }

    async fn get_keys_due_for_rotation(
        &self,
        config: &KeyConfig,
    ) -> Result<Vec<KeyEntry>, anyhow::Error> {
        let keys = self.keys.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let due_keys = keys
            .values()
            .filter(|key| {
                let time_since_rotation = now.saturating_sub(key.rotated_at);
                time_since_rotation >= config.rotation_interval
            })
            .cloned()
            .collect();

        Ok(due_keys)
    }

    async fn get_expired_keys(&self, config: &KeyConfig) -> Result<Vec<KeyEntry>, anyhow::Error> {
        let keys = self.keys.read().await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expired_keys = keys
            .values()
            .filter(|key| {
                if key.expires_at == 0 {
                    return false;
                }
                let retention_cutoff = key.expires_at + config.key_retention_period;
                now > retention_cutoff
            })
            .cloned()
            .collect();

        Ok(expired_keys)
    }
}
