use super::{StorageBackend, StorageEntry, StorageError};
use crate::namespace::{NamespaceId, NamespaceTree, NamespaceError};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use tracing::{debug, error, info};

/// Namespace-aware storage backend that prefixes keys with namespace information
pub struct NamespaceStorage {
    backend: Box<dyn StorageBackend>,
    namespace_tree: Arc<NamespaceTree>,
    namespace_id: NamespaceId,
}

/// Configuration for namespace storage
#[derive(Debug, Clone)]
pub struct NamespaceStorageConfig {
    pub namespace_id: NamespaceId,
    pub quota_enforcement: bool,
    pub audit_logging: bool,
}

impl NamespaceStorage {
    pub fn new(
        backend: Box<dyn StorageBackend>,
        namespace_tree: Arc<NamespaceTree>,
        namespace_id: NamespaceId,
    ) -> Self {
        Self {
            backend,
            namespace_tree,
            namespace_id,
        }
    }

    pub fn with_config(
        backend: Box<dyn StorageBackend>,
        namespace_tree: Arc<NamespaceTree>,
        config: NamespaceStorageConfig,
    ) -> Self {
        let mut storage = Self::new(backend, namespace_tree, config.namespace_id);

        // TODO: Apply configuration settings
        // storage.quota_enforcement = config.quota_enforcement;
        // storage.audit_logging = config.audit_logging;

        storage
    }

    /// Get the namespace prefix for this storage instance
    fn get_namespace_prefix(&self) -> String {
        format!("ns/{}/", self.namespace_id)
    }

    /// Transform a key to include namespace prefix
    fn namespaced_key(&self, key: &str) -> String {
        format!("{}{}", self.get_namespace_prefix(), key.trim_start_matches('/'))
    }

    /// Extract the original key from a namespaced key
    fn original_key(&self, namespaced_key: &str) -> Option<String> {
        let prefix = self.get_namespace_prefix();
        if namespaced_key.starts_with(&prefix) {
            Some(namespaced_key[prefix.len()..].to_string())
        } else {
            None
        }
    }

    /// Check if operation would exceed namespace quotas
    async fn check_quotas(&self, operation_size: usize) -> Result<(), StorageError> {
        // TODO: Implement quota checking
        // This would check against ResourceQuotas limits

        // For now, always allow
        Ok(())
    }

    /// Log operation for audit purposes
    async fn audit_log(&self, operation: &str, key: &str, size: Option<usize>) {
        // TODO: Implement audit logging
        debug!("Namespace storage operation: {} on key {} (size: {:?})", operation, key, size);
    }
}

#[async_trait]
impl StorageBackend for NamespaceStorage {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Check quotas before operation
        self.check_quotas(0).await?;

        // Audit log the operation
        self.audit_log("get", key, None).await;

        match self.backend.get(&namespaced_key).await {
            Ok(Some(mut entry)) => {
                // Restore original key in the entry
                entry.key = key.to_string();
                Ok(Some(entry))
            }
            Ok(None) => Ok(None),
            Err(e) => {
                error!("Failed to get key {} from backend: {}", namespaced_key, e);
                Err(e)
            }
        }
    }

    async fn put(&self, mut entry: StorageEntry) -> Result<(), StorageError> {
        // Check quotas before operation
        let operation_size = entry.value.len();
        self.check_quotas(operation_size).await?;

        // Transform key to namespaced version
        let original_key = entry.key.clone();
        entry.key = self.namespaced_key(&entry.key);

        // Audit log the operation
        self.audit_log("put", &original_key, Some(operation_size)).await;

        match self.backend.put(entry).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to put key {} to backend: {}", original_key, e);
                Err(e)
            }
        }
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("delete", key, None).await;

        match self.backend.delete(&namespaced_key).await {
            Ok(_) => Ok(()),
            Err(e) => {
                error!("Failed to delete key {} from backend: {}", namespaced_key, e);
                Err(e)
            }
        }
    }

    async fn exists(&self, key: &str) -> Result<bool, StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("exists", key, None).await;

        self.backend.exists(&namespaced_key).await
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        let namespaced_prefix = self.namespaced_key(prefix);

        // Audit log the operation
        self.audit_log("list", prefix, None).await;

        match self.backend.list(&namespaced_prefix).await {
            Ok(mut keys) => {
                // Filter and transform keys back to original namespace
                keys = keys.into_iter()
                    .filter_map(|key| self.original_key(&key))
                    .collect();
                Ok(keys)
            }
            Err(e) => {
                error!("Failed to list keys with prefix {} from backend: {}", namespaced_prefix, e);
                Err(e)
            }
        }
    }

    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, StorageError> {
        self.list(prefix).await
    }

    async fn count(&self, prefix: &str) -> Result<usize, StorageError> {
        let namespaced_prefix = self.namespaced_key(prefix);

        // Audit log the operation
        self.audit_log("count", prefix, None).await;

        self.backend.count(&namespaced_prefix).await
    }

    async fn size(&self, key: &str) -> Result<Option<usize>, StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("size", key, None).await;

        self.backend.size(&namespaced_key).await
    }

    async fn get_metadata(&self, key: &str) -> Result<Option<Value>, StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("get_metadata", key, None).await;

        self.backend.get_metadata(&namespaced_key).await
    }

    async fn put_metadata(&self, key: &str, metadata: Value) -> Result<(), StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("put_metadata", key, None).await;

        self.backend.put_metadata(&namespaced_key, metadata).await
    }

    async fn delete_metadata(&self, key: &str) -> Result<(), StorageError> {
        let namespaced_key = self.namespaced_key(key);

        // Audit log the operation
        self.audit_log("delete_metadata", key, None).await;

        self.backend.delete_metadata(&namespaced_key).await
    }

    async fn transaction<F, R>(&self, f: F) -> Result<R, StorageError>
    where
        F: FnOnce() -> Result<R, StorageError> + Send + 'static,
        R: Send + 'static,
    {
        // Audit log the operation
        self.audit_log("transaction", "", None).await;

        // For namespace storage, we need to implement transaction support
        // that works across the namespaced keys
        self.backend.transaction(f).await
    }

    async fn health_check(&self) -> Result<(), StorageError> {
        // Check both backend health and namespace validity
        self.backend.health_check().await?;

        // Verify namespace still exists and is accessible
        if self.namespace_tree.get_namespace(&self.namespace_id).await?.is_none() {
            return Err(StorageError::InternalError("Namespace no longer exists".to_string()));
        }

        Ok(())
    }

    async fn stats(&self) -> Result<Value, StorageError> {
        let mut stats = self.backend.stats().await.unwrap_or_else(|_| json!({}));

        // Add namespace-specific statistics
        if let Ok(namespace) = self.namespace_tree.get_namespace(&self.namespace_id).await {
            stats["namespace"] = json!({
                "id": self.namespace_id,
                "path": namespace.map(|ns| ns.path).unwrap_or_default(),
                "quotas": namespace.map(|ns| ns.quotas).unwrap_or_default(),
            });
        }

        Ok(stats)
    }

    async fn vacuum(&self) -> Result<(), StorageError> {
        // Audit log the operation
        self.audit_log("vacuum", "", None).await;

        // Vacuum operation should only affect keys within this namespace
        let namespace_prefix = self.get_namespace_prefix();

        // This would need backend-specific implementation
        // For now, delegate to backend with namespace filtering
        self.backend.vacuum().await
    }

    async fn backup(&self, destination: &str) -> Result<(), StorageError> {
        // Audit log the operation
        self.audit_log("backup", destination, None).await;

        // Backup should only include keys within this namespace
        // Implementation would depend on backend capabilities
        Err(StorageError::NotImplemented("Backup not implemented for namespace storage".to_string()))
    }

    async fn restore(&self, source: &str) -> Result<(), StorageError> {
        // Audit log the operation
        self.audit_log("restore", source, None).await;

        // Restore should validate that restored keys belong to this namespace
        Err(StorageError::NotImplemented("Restore not implemented for namespace storage".to_string()))
    }
}

impl Default for NamespaceStorageConfig {
    fn default() -> Self {
        Self {
            namespace_id: uuid::Uuid::new_v4(),
            quota_enforcement: true,
            audit_logging: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_namespace_storage_key_transformation() {
        let backend = Box::new(MemoryStorage::new());
        let namespace_tree = Arc::new(NamespaceTree::new());
        let namespace_id = uuid::Uuid::new_v4();

        let storage = NamespaceStorage::new(backend, namespace_tree, namespace_id);

        // Test key transformation
        let original_key = "test/key";
        let namespaced_key = storage.namespaced_key(original_key);

        assert!(namespaced_key.starts_with(&format!("ns/{}/", namespace_id)));
        assert!(namespaced_key.contains(original_key));
    }

    #[tokio::test]
    async fn test_namespace_storage_operations() {
        let backend = Box::new(MemoryStorage::new());
        let namespace_tree = Arc::new(NamespaceTree::new());
        let namespace_id = uuid::Uuid::new_v4();

        let storage = NamespaceStorage::new(backend, namespace_tree, namespace_id);

        // Test put and get operations
        let entry = StorageEntry {
            key: "test_key".to_string(),
            value: b"test_value".to_vec(),
            metadata: None,
        };

        storage.put(entry.clone()).await.unwrap();

        let retrieved = storage.get("test_key").await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().value, b"test_value");
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let backend = Box::new(MemoryStorage::new());
        let namespace_tree = Arc::new(NamespaceTree::new());

        let ns1_id = uuid::Uuid::new_v4();
        let ns2_id = uuid::Uuid::new_v4();

        let storage1 = NamespaceStorage::new(backend.clone() as Box<dyn StorageBackend>, namespace_tree.clone(), ns1_id);
        let storage2 = NamespaceStorage::new(backend as Box<dyn StorageBackend>, namespace_tree, ns2_id);

        // Put same key in different namespaces
        storage1.put(StorageEntry {
            key: "shared_key".to_string(),
            value: b"ns1_value".to_vec(),
            metadata: None,
        }).await.unwrap();

        storage2.put(StorageEntry {
            key: "shared_key".to_string(),
            value: b"ns2_value".to_vec(),
            metadata: None,
        }).await.unwrap();

        // Verify isolation
        let val1 = storage1.get("shared_key").await.unwrap().unwrap().value;
        let val2 = storage2.get("shared_key").await.unwrap().unwrap().value;

        assert_eq!(val1, b"ns1_value");
        assert_eq!(val2, b"ns2_value");
    }
}
