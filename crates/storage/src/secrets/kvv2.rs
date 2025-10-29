//! KV v2 Secrets Engine with Versioning
//!
//! Key-Value secrets engine with full version control, soft delete,
//! undelete, and metadata management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// KV v2 errors
#[derive(Debug, thiserror::Error)]
pub enum Kvv2Error {
    #[error("Secret not found: {0}")]
    SecretNotFound(String),

    #[error("Version not found: {0} version {1}")]
    VersionNotFound(String, u64),

    #[error("Version deleted: {0} version {1}")]
    VersionDeleted(String, u64),

    #[error("Version destroyed: {0} version {1}")]
    VersionDestroyed(String, u64),

    #[error("Check-and-set mismatch")]
    CasMismatch,

    #[error("Max versions exceeded")]
    MaxVersionsExceeded,
}

/// Secret version data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Version number
    pub version: u64,

    /// Secret data
    pub data: HashMap<String, Value>,

    /// Created time
    pub created_time: DateTime<Utc>,

    /// Soft deleted
    pub deleted: bool,

    /// Deletion time
    pub deletion_time: Option<DateTime<Utc>>,

    /// Permanently destroyed
    pub destroyed: bool,

    /// Destruction time
    pub destruction_time: Option<DateTime<Utc>>,
}

impl SecretVersion {
    /// Create new version
    pub fn new(version: u64, data: HashMap<String, Value>) -> Self {
        Self {
            version,
            data,
            created_time: Utc::now(),
            deleted: false,
            deletion_time: None,
            destroyed: false,
            destruction_time: None,
        }
    }

    /// Soft delete
    pub fn delete(&mut self) {
        self.deleted = true;
        self.deletion_time = Some(Utc::now());
    }

    /// Undelete
    pub fn undelete(&mut self) {
        self.deleted = false;
        self.deletion_time = None;
    }

    /// Permanently destroy
    pub fn destroy(&mut self) {
        self.destroyed = true;
        self.destruction_time = Some(Utc::now());
        self.data.clear(); // Wipe data
    }
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Path
    pub path: String,

    /// Current version
    pub current_version: u64,

    /// Oldest version
    pub oldest_version: u64,

    /// Created time
    pub created_time: DateTime<Utc>,

    /// Updated time
    pub updated_time: DateTime<Utc>,

    /// Max versions to keep (0 = unlimited)
    pub max_versions: u64,

    /// Check-and-Set required
    pub cas_required: bool,

    /// Delete version after (0 = never)
    pub delete_version_after: u64,

    /// Custom metadata
    pub custom_metadata: HashMap<String, String>,
}

impl SecretMetadata {
    /// Create new metadata
    pub fn new(path: String) -> Self {
        Self {
            path,
            current_version: 0,
            oldest_version: 1,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            max_versions: 10, // Default keep 10 versions
            cas_required: false,
            delete_version_after: 0,
            custom_metadata: HashMap::new(),
        }
    }
}

/// Complete secret with all versions
#[derive(Debug, Clone)]
struct Secret {
    metadata: SecretMetadata,
    versions: HashMap<u64, SecretVersion>,
}

impl Secret {
    fn new(path: String) -> Self {
        Self {
            metadata: SecretMetadata::new(path),
            versions: HashMap::new(),
        }
    }
}

/// KV v2 secrets engine
pub struct Kvv2Engine {
    secrets: Arc<RwLock<HashMap<String, Secret>>>,
}

impl Kvv2Engine {
    /// Create new KV v2 engine
    pub fn new() -> Self {
        Self {
            secrets: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Write secret (create new version)
    pub async fn write(
        &self,
        path: &str,
        data: HashMap<String, Value>,
        cas: Option<u64>,
    ) -> Result<SecretVersion, Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let secret = secrets
            .entry(path.to_string())
            .or_insert_with(|| Secret::new(path.to_string()));

        // Check CAS if required
        if secret.metadata.cas_required {
            if let Some(expected_version) = cas {
                if expected_version != secret.metadata.current_version {
                    return Err(Kvv2Error::CasMismatch);
                }
            } else {
                return Err(Kvv2Error::CasMismatch);
            }
        }

        // Increment version
        secret.metadata.current_version += 1;
        let version_num = secret.metadata.current_version;

        // Create new version
        let version = SecretVersion::new(version_num, data);
        secret.versions.insert(version_num, version.clone());

        // Update metadata
        secret.metadata.updated_time = Utc::now();

        // Enforce max versions
        if secret.metadata.max_versions > 0 {
            let versions_to_keep = secret.metadata.max_versions;
            if secret.versions.len() > versions_to_keep as usize {
                let oldest = version_num.saturating_sub(versions_to_keep);
                secret.versions.retain(|v, _| *v > oldest);
                secret.metadata.oldest_version = oldest + 1;
            }
        }

        Ok(version)
    }

    /// Read secret (latest or specific version)
    pub async fn read(&self, path: &str, version: Option<u64>) -> Result<SecretVersion, Kvv2Error> {
        let secrets = self.secrets.read().await;

        let secret = secrets
            .get(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        let version_num = version.unwrap_or(secret.metadata.current_version);

        let ver = secret
            .versions
            .get(&version_num)
            .ok_or_else(|| Kvv2Error::VersionNotFound(path.to_string(), version_num))?;

        if ver.destroyed {
            return Err(Kvv2Error::VersionDestroyed(path.to_string(), version_num));
        }

        if ver.deleted {
            return Err(Kvv2Error::VersionDeleted(path.to_string(), version_num));
        }

        Ok(ver.clone())
    }

    /// Soft delete versions
    pub async fn delete(&self, path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        for version_num in versions {
            if let Some(version) = secret.versions.get_mut(&version_num) {
                version.delete();
            }
        }

        Ok(())
    }

    /// Undelete versions
    pub async fn undelete(&self, path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        for version_num in versions {
            if let Some(version) = secret.versions.get_mut(&version_num) {
                if !version.destroyed {
                    version.undelete();
                }
            }
        }

        Ok(())
    }

    /// Permanently destroy versions
    pub async fn destroy(&self, path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        for version_num in versions {
            if let Some(version) = secret.versions.get_mut(&version_num) {
                version.destroy();
            }
        }

        Ok(())
    }

    /// Get metadata
    pub async fn get_metadata(&self, path: &str) -> Result<SecretMetadata, Kvv2Error> {
        let secrets = self.secrets.read().await;

        let secret = secrets
            .get(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        Ok(secret.metadata.clone())
    }

    /// Update metadata
    pub async fn update_metadata(
        &self,
        path: &str,
        max_versions: Option<u64>,
        cas_required: Option<bool>,
        delete_version_after: Option<u64>,
        custom_metadata: Option<HashMap<String, String>>,
    ) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let secret = secrets
            .get_mut(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        if let Some(max) = max_versions {
            secret.metadata.max_versions = max;
        }

        if let Some(cas) = cas_required {
            secret.metadata.cas_required = cas;
        }

        if let Some(delete_after) = delete_version_after {
            secret.metadata.delete_version_after = delete_after;
        }

        if let Some(custom) = custom_metadata {
            secret.metadata.custom_metadata = custom;
        }

        Ok(())
    }

    /// List secrets
    pub async fn list(&self, prefix: &str) -> Vec<String> {
        let secrets = self.secrets.read().await;

        secrets
            .keys()
            .filter(|path| path.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// Delete metadata and all versions
    pub async fn delete_metadata(&self, path: &str) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        secrets
            .remove(path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(path.to_string()))?;

        Ok(())
    }
}

impl Default for Kvv2Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write_read() {
        let kv = Kvv2Engine::new();

        let mut data = HashMap::new();
        data.insert(
            "password".to_string(),
            Value::String("secret123".to_string()),
        );

        let version = kv.write("secret/myapp", data.clone(), None).await.unwrap();
        assert_eq!(version.version, 1);

        let read = kv.read("secret/myapp", None).await.unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(
            read.data.get("password"),
            Some(&Value::String("secret123".to_string()))
        );
    }

    #[tokio::test]
    async fn test_versions() {
        let kv = Kvv2Engine::new();

        // Write version 1
        let mut data1 = HashMap::new();
        data1.insert("key".to_string(), Value::String("value1".to_string()));
        kv.write("secret/test", data1, None).await.unwrap();

        // Write version 2
        let mut data2 = HashMap::new();
        data2.insert("key".to_string(), Value::String("value2".to_string()));
        kv.write("secret/test", data2, None).await.unwrap();

        // Read latest (v2)
        let latest = kv.read("secret/test", None).await.unwrap();
        assert_eq!(latest.version, 2);

        // Read specific version (v1)
        let v1 = kv.read("secret/test", Some(1)).await.unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(
            v1.data.get("key"),
            Some(&Value::String("value1".to_string()))
        );
    }

    #[tokio::test]
    async fn test_delete_undelete() {
        let kv = Kvv2Engine::new();

        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));
        kv.write("secret/test", data, None).await.unwrap();

        // Soft delete
        kv.delete("secret/test", vec![1]).await.unwrap();

        // Should fail to read
        let result = kv.read("secret/test", Some(1)).await;
        assert!(result.is_err());

        // Undelete
        kv.undelete("secret/test", vec![1]).await.unwrap();

        // Should succeed now
        let read = kv.read("secret/test", Some(1)).await;
        assert!(read.is_ok());
    }

    #[tokio::test]
    async fn test_cas() {
        let kv = Kvv2Engine::new();

        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));
        kv.write("secret/test", data.clone(), None).await.unwrap();

        // Enable CAS
        kv.update_metadata("secret/test", None, Some(true), None, None)
            .await
            .unwrap();

        // Write with correct CAS should succeed
        kv.write("secret/test", data.clone(), Some(1))
            .await
            .unwrap();

        // Write with wrong CAS should fail
        let result = kv.write("secret/test", data, Some(1)).await;
        assert!(result.is_err());
    }
}
