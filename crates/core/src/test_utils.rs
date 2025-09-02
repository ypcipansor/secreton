// Test utilities for SecretOn Core
use std::collections::HashMap;
use std::sync::Arc;
use crate::storage::{StorageEngine, StorageEntry};
use crate::error::CoreError;

/// Create a test storage implementation for unit tests
pub async fn create_test_storage() -> Arc<dyn StorageEngine> {
    #[derive(Debug)]
    struct TestStorage {
        data: Arc<tokio::sync::RwLock<HashMap<String, StorageEntry>>>,
    }
    
    #[async_trait::async_trait]
    impl StorageEngine for TestStorage {
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError> {
            let data = self.data.read().await;
            Ok(data.get(key).cloned())
        }
        
        async fn put(&self, entry: StorageEntry) -> Result<(), CoreError> {
            let mut data = self.data.write().await;
            data.insert(entry.key.clone(), entry);
            Ok(())
        }
        
        async fn delete(&self, key: &str) -> Result<(), CoreError> {
            let mut data = self.data.write().await;
            data.remove(key);
            Ok(())
        }
        
        async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError> {
            let data = self.data.read().await;
            Ok(data.keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }
    
    Arc::new(TestStorage {
        data: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
    })
}
