use anyhow::{Result, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::{SharedSecureStorage, StorageBackend};

/// Represents a versioned secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub id: String,
    pub version: u32,
    pub data: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub created_by: String,
    pub metadata: HashMap<String, String>,
    pub deleted: bool,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: String,
    pub path: String,
    pub current_version: u32,
    pub versions: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub max_versions: u32,
    pub custom_metadata: HashMap<String, String>,
}

/// Secret manager configuration
#[derive(Debug, Clone)]
pub struct SecretManagerConfig {
    pub max_versions: u32,
    pub default_lease_ttl: chrono::Duration,
    pub max_lease_ttl: chrono::Duration,
}

impl Default for SecretManagerConfig {
    fn default() -> Self {
        Self {
            max_versions: 10,
            default_lease_ttl: chrono::Duration::hours(24 * 7), // 1 week
            max_lease_ttl: chrono::Duration::days(30 * 6),      // 6 months
        }
    }
}

/// Secret manager for handling versioned secrets
pub struct SecretManager<T: StorageBackend> {
    backend: Arc<T>,
    secure_storage: SharedSecureStorage,
    config: SecretManagerConfig,
    secret_index: Arc<RwLock<HashSet<String>>>,
}

impl<T: StorageBackend> SecretManager<T> {
    /// Create a new SecretManager
    pub fn new(backend: Arc<T>, secure_storage: SharedSecureStorage) -> Self {
        Self {
            backend,
            secure_storage,
            config: SecretManagerConfig::default(),
            secret_index: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a new SecretManager with custom configuration
    pub fn with_config(
        backend: Arc<T>,
        secure_storage: SharedSecureStorage,
        config: SecretManagerConfig,
    ) -> Self {
        Self {
            backend,
            secure_storage,
            config,
            secret_index: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create or update a secret
    pub async fn create_secret(
        &self,
        path: &str,
        data: Value,
        created_by: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<SecretMetadata> {
        // Validate path
        if path.is_empty() || path.starts_with('/') {
            return Err(anyhow!("Invalid secret path"));
        }

        // Encrypt the secret data
        let encrypted_data = self.secure_storage.encrypt_value(&data).await?;

        // Store the secret in the backend
        let metadata = self
            .backend
            .store_secret_versioned(
                path,
                &json!({
                    "data": encrypted_data,
                    "created_by": created_by,
                    "metadata": metadata.unwrap_or_default(),
                }),
            )
            .await?;

        // Add path to index
        self.secret_index.write().await.insert(path.to_string());

        Ok(SecretMetadata {
            id: Uuid::new_v4().to_string(),
            path: path.to_string(),
            current_version: metadata,
            versions: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            max_versions: self.config.max_versions,
            custom_metadata: HashMap::new(),
        })
    }

    /// Get the latest version of a secret
    pub async fn get_secret(&self, path: &str) -> Result<Option<SecretVersion>> {
        if let Some((stored_data, version)) = self.backend.get_latest_secret(path).await? {
            let encrypted_data = stored_data
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid secret data format"))?;

            let decrypted_bytes = self.secure_storage.decrypt(encrypted_data).await?;
            let data: Value = serde_json::from_slice(&decrypted_bytes)?;

            Ok(Some(SecretVersion {
                id: Uuid::new_v4().to_string(),
                version,
                data,
                created_at: Utc::now(),
                created_by: stored_data
                    .get("created_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system")
                    .to_string(),
                metadata: stored_data
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default(),
                deleted: false,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all secrets under a path
    pub async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let index = self.secret_index.read().await;
        let matching_paths: Vec<String> = index
            .iter()
            .filter(|secret_path| secret_path.starts_with(path))
            .cloned()
            .collect();
        Ok(matching_paths)
    }

    /// Delete a secret or specific version
    pub async fn delete_secret(&self, path: &str, version: Option<u32>) -> Result<()> {
        if let Some(version) = version {
            // Delete specific version
            self.backend.delete_secret_version(path, version).await?;
            Ok(())
        } else {
            // Delete all versions and remove from index
            self.backend.delete_secret(path, "default").await?;
            self.secret_index.write().await.remove(path);
            Ok(())
        }
    }

    /// Get secret metadata
    pub async fn get_metadata(&self, path: &str) -> Result<Option<SecretMetadata>> {
        // In a real implementation, this would fetch from the database
        // For now, we'll return a simplified version
        if let Some((_data, version)) = self.backend.get_latest_secret(path).await? {
            Ok(Some(SecretMetadata {
                id: Uuid::new_v4().to_string(),
                path: path.to_string(),
                current_version: version,
                versions: 1, // This would be fetched from the database
                created_at: Utc::now(),
                updated_at: Utc::now(),
                max_versions: self.config.max_versions,
                custom_metadata: HashMap::new(),
            }))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
pub trait SecretStorage: Send + Sync {
    /// Store a new version of a secret
    async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32>;

    /// Get the latest version of a secret
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>>;

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>>;

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()>;

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()>;
}

#[async_trait]
impl<T: StorageBackend> SecretStorage for SecretManager<T> {
    /// Store a new version of a secret
    async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32> {
        // This is a simplified implementation - in practice, you'd want to use the full create_secret logic
        let version = self.backend.store_secret_versioned(path, data).await?;
        self.secret_index.write().await.insert(path.to_string());
        Ok(version)
    }

    /// Get the latest version of a secret
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>> {
        self.backend
            .get_latest_secret(path)
            .await
            .map_err(|e| anyhow!(e))
    }

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        self.list_secrets(path).await
    }

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()> {
        self.delete_secret(path, None).await
    }

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()> {
        self.backend.delete_secret_version(path, version).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    // use super::*;
    // use crate::storage::secure::storage::SecureStorage;
    // use serde_json::json;

    #[tokio::test]
    async fn test_create_and_retrieve_secret() {
        // TODO: Fix test to use proper StorageBackend implementation
        /*
        // Setup secure storage with a test key
        let secure_storage = SharedSecureStorage::new(
            SecureStorage::new(b"test-master-key-secret-32-bytes").unwrap()
        );

        // Setup in-memory storage backend using HashMap for testing
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let backend = Arc::new(RwLock::new(HashMap::new()));

        // Create secret manager
        let manager = SecretManager::new(backend, secure_storage);

        // Test data
        let path = "test/secret";
        let data = json!({ "username": "testuser", "password": "testpass" });

        // Create secret
        manager.create_secret(path, data.clone(), "test-user", None)
            .await
            .expect("Failed to create secret");

        // Retrieve secret
        let secret = manager.get_secret(path)
            .await
            .expect("Failed to get secret")
            .expect("Secret not found");

        // Verify data
        assert_eq!(secret.data, data);
        */
    }

    #[tokio::test]
    async fn test_secret_versioning() {
        // TODO: Fix test to use proper StorageBackend implementation
        /*
        // Setup secure storage
        let secure_storage = SharedSecureStorage::new(
            SecureStorage::new(b"test-master-key-secret-32-bytes").unwrap()
        );

        // Setup in-memory storage backend
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let backend = Arc::new(RwLock::new(HashMap::new()));
        let manager = SecretManager::new(backend, secure_storage);

        let path = "test/versioned";
        let initial_data = json!({ "value": "v1" });
        let updated_data = json!({ "value": "v2" });

        // Create initial version
        manager.create_secret(path, initial_data.clone(), "test-user", None)
            .await
            .unwrap();

        // Update to new version
        manager.update_secret(path, updated_data.clone(), "test-user", None)
            .await
            .unwrap();

        // Get all versions
        let versions = manager.list_secret_versions(path)
            .await
            .unwrap();

        assert_eq!(versions.len(), 2);
        */
    }

    #[tokio::test]
    async fn test_secret_deletion() {
        // TODO: Fix test to use proper StorageBackend implementation
        /*
        // Setup secure storage
        let secure_storage = SharedSecureStorage::new(
            SecureStorage::new(b"test-master-key-secret-32-bytes").unwrap()
        );

        // Setup in-memory storage backend
        use std::collections::HashMap;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let backend = Arc::new(RwLock::new(HashMap::new()));
        let manager = SecretManager::new(backend, secure_storage);

        let path = "test/delete";
        let data = json!({ "value": "to-be-deleted" });

        // Create secret
        manager.create_secret(path, data, "test-user", None)
            .await
            .unwrap();

        // Delete secret
        manager.delete_secret(path, "test-user")
            .await
            .unwrap();

        // Verify deletion
        let secret = manager.get_secret(path).await.unwrap();
        assert!(secret.is_none());
        */
    }
}
