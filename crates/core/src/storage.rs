//! Storage module

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// Import macros
use anyhow::anyhow;
use tracing::{error, info};

// Import error types
use crate::error::CoreError;

/// Storage key-value pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: HashMap<String, String>,
}

/// Storage engine trait
#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError>;
    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError>;
    async fn delete(&self, key: &str) -> Result<(), CoreError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError>;
}

/// In-memory storage implementation
pub struct MemoryStorage {
    data: std::sync::RwLock<HashMap<String, StorageEntry>>,
}

impl MemoryStorage {
    pub fn new() -> Self {
        Self {
            data: std::sync::RwLock::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl StorageEngine for MemoryStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError> {
        let data = self.data.read().unwrap();
        Ok(data.get(key).cloned())
    }

    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError> {
        let mut data = self.data.write().unwrap();
        data.insert(entry.key.clone(), entry);
        Ok(())
    }

    async fn delete(&self, key: &str) -> Result<(), CoreError> {
        let mut data = self.data.write().unwrap();
        data.remove(key);
        Ok(())
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
        let data = self.data.read().unwrap();
        let keys: Vec<String> = data
            .keys()
            .filter(|k| k.starts_with(prefix))
            .cloned()
            .collect();
        Ok(keys)
    }
}

// Re-export main types
pub use MemoryStorage as Storage;
