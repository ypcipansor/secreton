use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::RwLock;

use super::{StorageEngine, StorageEntry};
use crate::error::CoreError;

/// In-memory implementation of StorageEngine for testing
#[derive(Default)]
pub struct InMemoryStorage {
    data: RwLock<HashMap<String, StorageEntry>>,
}

impl InMemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl StorageEngine for InMemoryStorage {
    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError> {
        let mut data_map = self.data.write().await;
        data_map.insert(entry.key.clone(), entry);
        Ok(())
    }

    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError> {
        let data_map = self.data.read().await;
        Ok(data_map.get(key).cloned())
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        let mut data_map = self.data.write().await;
        data_map.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
        let data_map = self.data.read().await;
        let mut results = Vec::new();

        for key in data_map.keys() {
            if key.starts_with(prefix) {
                results.push(key.clone());
            }
        }

        results.sort();
        Ok(results)
    }
}
