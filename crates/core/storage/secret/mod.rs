use std::collections::HashMap;
use std::sync::Arc;
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::{
    secure::{SharedSecureStorage, SecureStorage},
    StorageBackend,
};

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
}

impl<T: StorageBackend> SecretManager<T> {
    /// Create a new SecretManager
    pub fn new(backend: Arc<T>, secure_storage: SharedSecureStorage) -> Self {
        Self {
            backend,
            secure_storage,
            config: SecretManagerConfig::default(),
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
        let metadata = self.backend.store_secret_versioned(
            path,
            &json!({
                "data": encrypted_data,
                "created_by": created_by,
                "metadata": metadata.unwrap_or_default(),
            }),
        ).await?;

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
        if let Some((data, version)) = self.backend.get_latest_secret(path).await? {
            let encrypted_data = data.get("data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid secret data format"))?;

            let data = self.secure_storage.decrypt(encrypted_data).await?;
            let data: Value = serde_json::from_slice(&data)?;

            Ok(Some(SecretVersion {
                id: Uuid::new_v4().to_string(),
                version,
                data,
                created_at: Utc::now(),
                created_by: data.get("created_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system")
                    .to_string(),
                metadata: data.get("metadata")
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
        self.backend.list_secrets(path).await
    }

    /// Delete a secret or specific version
    pub async fn delete_secret(
        &self,
        path: &str,
        version: Option<u32>,
    ) -> Result<()> {
        if let Some(version) = version {
            // Soft delete specific version
            self.backend.delete_secret_version(path, version).await
        } else {
            // Soft delete all versions
            self.backend.delete_secret(path).await
        }
    }

    /// Get secret metadata
    pub async fn get_metadata(&self, path: &str) -> Result<Option<SecretMetadata>> {
        // In a real implementation, this would fetch from the database
        // For now, we'll return a simplified version
        if let Some((data, version)) = self.backend.get_latest_secret(path).await? {
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
    async fn store_secret_versioned(
        &self,
        path: &str,
        data: &serde_json::Value,
    ) -> Result<u32>;

    /// Get the latest version of a secret
    async fn get_latest_secret(
        &self,
        path: &str,
    ) -> Result<Option<(serde_json::Value, u32)>>;

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>>;

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()>;

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::in_memory::InMemoryStorage;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_and_retrieve_secret() {
        // Setup secure storage with a test key
        let secure_storage = SharedSecureStorage::new(
            SecureStorage::new(b"test-master-key", None).unwrap()
        );
        
        // Setup in-memory storage backend
        let backend = Arc::new(InMemoryStorage::new());
        
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
        assert_eq!(secret.created_by, "test-user");
    }
}
