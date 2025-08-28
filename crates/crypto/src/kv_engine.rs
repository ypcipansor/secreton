//! Key-Value Secrets Engine
//!
//! Provides secure storage and retrieval of key-value secrets with versioning

use crate::error::{CryptoError, CryptoResult};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Secret data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretData {
    pub data: HashMap<String, String>,
    pub metadata: SecretMetadata,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub version: u32,
    pub created_time: DateTime<Utc>,
    pub updated_time: DateTime<Utc>,
    pub destroyed: bool,
    pub delete_time: Option<DateTime<Utc>>,
}

/// Secret version entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub data: HashMap<String, String>,
    pub metadata: SecretMetadata,
}

/// KV Engine for storing secrets
pub struct KVEngine {
    /// Path -> Versions (version_number -> SecretVersion)
    secrets: Arc<RwLock<HashMap<String, HashMap<u32, SecretVersion>>>>,
}

impl KVEngine {
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Store or update a secret at the given path
    pub async fn put_secret(&self, path: &str, data: HashMap<String, String>) -> CryptoResult<u32> {
        let mut secrets = self.secrets.write().unwrap();
        let path_secrets = secrets.entry(path.to_string()).or_default();

        // Get the next version number
        let version = if path_secrets.is_empty() {
            1
        } else {
            path_secrets.keys().max().unwrap() + 1
        };

        let now = Utc::now();
        let metadata = SecretMetadata {
            version,
            created_time: now,
            updated_time: now,
            destroyed: false,
            delete_time: None,
        };

        let secret_version = SecretVersion { data, metadata };

        path_secrets.insert(version, secret_version);
        Ok(version)
    }

    /// Get a secret from the given path
    pub async fn get_secret(&self, path: &str, version: Option<u32>) -> CryptoResult<SecretData> {
        let secrets = self.secrets.read().unwrap();
        let path_secrets = secrets
            .get(path)
            .ok_or_else(|| CryptoError::KeyNotFound(path.to_string()))?;

        let secret_version = if let Some(v) = version {
            path_secrets
                .get(&v)
                .ok_or_else(|| CryptoError::KeyNotFound(format!("{}@v{}", path, v)))?
        } else {
            // Get the latest version
            let latest_version = path_secrets
                .keys()
                .max()
                .ok_or_else(|| CryptoError::KeyNotFound(path.to_string()))?;
            path_secrets.get(latest_version).unwrap()
        };

        if secret_version.metadata.destroyed {
            return Err(CryptoError::KeyNotFound(format!("{} (destroyed)", path)));
        }

        Ok(SecretData {
            data: secret_version.data.clone(),
            metadata: secret_version.metadata.clone(),
        })
    }

    /// List all secret paths
    pub async fn list_secrets(&self) -> Vec<String> {
        let secrets = self.secrets.read().unwrap();
        secrets.keys().cloned().collect()
    }

    /// Delete a specific version of a secret
    pub async fn delete_secret(&self, path: &str, version: Option<u32>) -> CryptoResult<()> {
        let mut secrets = self.secrets.write().unwrap();
        let path_secrets = secrets
            .get_mut(path)
            .ok_or_else(|| CryptoError::KeyNotFound(path.to_string()))?;

        if let Some(v) = version {
            if let Some(secret) = path_secrets.get_mut(&v) {
                secret.metadata.destroyed = true;
                secret.metadata.delete_time = Some(Utc::now());
            } else {
                return Err(CryptoError::KeyNotFound(format!("{}@v{}", path, v)));
            }
        } else {
            // Delete all versions
            for secret in path_secrets.values_mut() {
                secret.metadata.destroyed = true;
                secret.metadata.delete_time = Some(Utc::now());
            }
        }

        Ok(())
    }

    /// Get metadata for a secret path
    pub async fn get_metadata(&self, path: &str) -> CryptoResult<HashMap<u32, SecretMetadata>> {
        let secrets = self.secrets.read().unwrap();
        let path_secrets = secrets
            .get(path)
            .ok_or_else(|| CryptoError::KeyNotFound(path.to_string()))?;

        let metadata: HashMap<u32, SecretMetadata> = path_secrets
            .iter()
            .map(|(v, secret)| (*v, secret.metadata.clone()))
            .collect();

        Ok(metadata)
    }

    /// Permanently destroy a secret version (unrecoverable)
    pub async fn destroy_secret(&self, path: &str, version: u32) -> CryptoResult<()> {
        let mut secrets = self.secrets.write().unwrap();
        let path_secrets = secrets
            .get_mut(path)
            .ok_or_else(|| CryptoError::KeyNotFound(path.to_string()))?;

        path_secrets
            .remove(&version)
            .ok_or_else(|| CryptoError::KeyNotFound(format!("{}@v{}", path, version)))?;

        // If no versions left, remove the path entirely
        if path_secrets.is_empty() {
            secrets.remove(path);
        }

        Ok(())
    }
}

impl Default for KVEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio;

    #[tokio::test]
    async fn test_put_and_get_secret() {
        let kv = KVEngine::new();

        let mut data = HashMap::new();
        data.insert("username".to_string(), "admin".to_string());
        data.insert("password".to_string(), "secret123".to_string());

        let version = kv.put_secret("myapp/db", data.clone()).await.unwrap();
        assert_eq!(version, 1);

        let retrieved = kv.get_secret("myapp/db", None).await.unwrap();
        assert_eq!(retrieved.data, data);
        assert_eq!(retrieved.metadata.version, 1);
    }

    #[tokio::test]
    async fn test_versioning() {
        let kv = KVEngine::new();

        // First version
        let mut data1 = HashMap::new();
        data1.insert("key".to_string(), "value1".to_string());
        let v1 = kv.put_secret("test/path", data1.clone()).await.unwrap();
        assert_eq!(v1, 1);

        // Second version
        let mut data2 = HashMap::new();
        data2.insert("key".to_string(), "value2".to_string());
        let v2 = kv.put_secret("test/path", data2.clone()).await.unwrap();
        assert_eq!(v2, 2);

        // Get specific versions
        let secret_v1 = kv.get_secret("test/path", Some(1)).await.unwrap();
        assert_eq!(secret_v1.data, data1);

        let secret_v2 = kv.get_secret("test/path", Some(2)).await.unwrap();
        assert_eq!(secret_v2.data, data2);

        // Get latest version
        let secret_latest = kv.get_secret("test/path", None).await.unwrap();
        assert_eq!(secret_latest.data, data2);
        assert_eq!(secret_latest.metadata.version, 2);
    }

    #[tokio::test]
    async fn test_delete_and_destroy() {
        let kv = KVEngine::new();

        let mut data = HashMap::new();
        data.insert("sensitive".to_string(), "data".to_string());

        kv.put_secret("secret/path", data).await.unwrap();

        // Delete (soft delete)
        kv.delete_secret("secret/path", Some(1)).await.unwrap();

        // Should be marked as destroyed
        let result = kv.get_secret("secret/path", Some(1)).await;
        assert!(result.is_err());

        // Destroy permanently
        kv.destroy_secret("secret/path", 1).await.unwrap();

        // Should be completely gone
        let result = kv.get_secret("secret/path", Some(1)).await;
        assert!(result.is_err());
    }
}
