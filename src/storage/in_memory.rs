use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::secret::SecretStorage;

/// In-memory implementation of SecretStorage for testing
#[derive(Default)]
pub struct InMemoryStorage {
    data: RwLock<HashMap<String, (Value, u32)>>,
    versions: RwLock<HashMap<String, Vec<(Value, u32)>>>,
    counter: AtomicU32,
}

impl InMemoryStorage {
    /// Create a new in-memory storage instance
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl SecretStorage for InMemoryStorage {
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32> {
        let version = self.counter.fetch_add(1, Ordering::SeqCst) + 1;
        
        let mut data_map = self.data.write().await;
        data_map.insert(path.to_string(), (data.clone(), version));
        
        let mut versions = self.versions.write().await;
        let entry = versions.entry(path.to_string()).or_default();
        entry.push((data.clone(), version));
        
        Ok(version)
    }

    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>> {
        let data_map = self.data.read().await;
        Ok(data_map.get(path).cloned())
    }

    async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let data_map = self.data.read().await;
        let mut results = Vec::new();
        
        for key in data_map.keys() {
            if key.starts_with(path) {
                results.push(key.clone());
            }
        }
        
        Ok(results)
    }

    async fn delete_secret(&self, path: &str) -> Result<()> {
        let mut data_map = self.data.write().await;
        data_map.remove(path);
        
        let mut versions = self.versions.write().await;
        versions.remove(path);
        
        Ok(())
    }

    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()> {
        let mut versions = self.versions.write().await;
        if let Some(secret_versions) = versions.get_mut(path) {
            secret_versions.retain(|(_, v)| *v != version);
            
            // Update the latest version if needed
            if let Some(latest) = secret_versions.last() {
                let mut data_map = self.data.write().await;
                data_map.insert(path.to_string(), latest.clone());
            } else {
                let mut data_map = self.data.write().await;
                data_map.remove(path);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_store_and_retrieve_secret() {
        let storage = InMemoryStorage::new();
        let path = "test/secret";
        let data = json!({ "key": "value" });
        
        // Store secret
        let version = storage.store_secret_versioned(path, &data)
            .await
            .expect("Failed to store secret");
            
        assert_eq!(version, 1);
        
        // Retrieve secret
        let (retrieved_data, retrieved_version) = storage.get_latest_secret(path)
            .await
            .expect("Failed to get secret")
            .expect("Secret not found");
            
        assert_eq!(retrieved_data, data);
        assert_eq!(retrieved_version, version);
    }
    
    #[tokio::test]
    async fn test_list_secrets() {
        let storage = InMemoryStorage::new();
        
        // Store multiple secrets
        storage.store_secret_versioned("test/secret1", &json!({}))
            .await
            .unwrap();
            
        storage.store_secret_versioned("test/secret2", &json!({}))
            .await
            .unwrap();
            
        storage.store_secret_versioned("other/secret", &json!({}))
            .await
            .unwrap();
        
        // List secrets under test/
        let secrets = storage.list_secrets("test/")
            .await
            .expect("Failed to list secrets");
            
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains(&"test/secret1".to_string()));
        assert!(secrets.contains(&"test/secret2".to_string()));
    }
    
    #[tokio::test]
    async fn test_delete_secret() {
        let storage = InMemoryStorage::new();
        let path = "test/secret";
        
        // Store secret
        storage.store_secret_versioned(path, &json!({}))
            .await
            .unwrap();
            
        // Delete secret
        storage.delete_secret(path)
            .await
            .expect("Failed to delete secret");
            
        // Verify secret is deleted
        let result = storage.get_latest_secret(path).await.unwrap();
        assert!(result.is_none());
    }
}
