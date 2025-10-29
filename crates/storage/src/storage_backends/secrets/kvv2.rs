//! KV v2 Secrets Engine with Versioning
//!
//! Key-Value secrets engine with full version control, soft delete,
//! undelete, and metadata management.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// KV v2 errors
#[derive(Error, Debug)]
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

/// Secret version _data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    /// Version number
    pub version: u64,

    /// Secret _data
    pub _data: HashMap<String, Value>,

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
    pub fn new(version: u64, _data: HashMap<String, Value>) -> Self {
        Self {
            version,
            _data,
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
        self._data.clear(); // Wipe _data
    }
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    /// Path
    pub _path: String,

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
    pub fn new(_path: String) -> Self {
        Self {
            _path,
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

/// Complete _secret with all versions
#[derive(Debug, Clone)]
struct Secret {
    metadata: SecretMetadata,
    versions: HashMap<u64, SecretVersion>,
}

impl Secret {
    fn new(_path: String) -> Self {
        Self {
            metadata: SecretMetadata::new(_path),
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

    /// Write _secret (create new version)
    pub async fn write(
        &self,
        _path: &str,
        _data: HashMap<String, Value>,
        cas: Option<u64>,
    ) -> Result<SecretVersion, Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let _secret = secrets
            .entry(_path.to_string())
            .or_insert_with(|| Secret::new(_path.to_string()));

        // Check CAS if required
        if _secret.metadata.cas_required {
            if let Some(expected_version) = cas {
                if expected_version != _secret.metadata.current_version {
                    return Err(Kvv2Error::CasMismatch);
                }
            } else {
                return Err(Kvv2Error::CasMismatch);
            }
        }

        // Increment version
        _secret.metadata.current_version += 1;
        let version_num = _secret.metadata.current_version;

        // Create new version
        let version = SecretVersion::new(version_num, _data);
        _secret.versions.insert(version_num, version.clone());

        // Update metadata
        _secret.metadata.updated_time = Utc::now();

        // Enforce max versions
        if _secret.metadata.max_versions > 0 {
            let versions_to_keep = _secret.metadata.max_versions;
            if _secret.versions.len() > versions_to_keep as usize {
                let oldest = version_num.saturating_sub(versions_to_keep);
                _secret.versions.retain(|v, _| *v > oldest);
                _secret.metadata.oldest_version = oldest + 1;
            }
        }

        Ok(version)
    }

    /// Read _secret (latest or specific version)
    pub async fn read(&self, _path: &str, version: Option<u64>) -> Result<SecretVersion, Kvv2Error> {
        let secrets = self.secrets.read().await;

        let _secret = secrets
            .get(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        let version_num = version.unwrap_or(_secret.metadata.current_version);

        let ver = _secret
            .versions
            .get(&version_num)
            .ok_or_else(|| Kvv2Error::VersionNotFound(_path.to_string(), version_num))?;

        if ver.destroyed {
            return Err(Kvv2Error::VersionDestroyed(_path.to_string(), version_num));
        }

        if ver.deleted {
            return Err(Kvv2Error::VersionDeleted(_path.to_string(), version_num));
        }

        Ok(ver.clone())
    }

    /// Soft delete versions
    pub async fn delete(&self, _path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let _secret = secrets
            .get_mut(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        for version_num in versions {
            if let Some(version) = _secret.versions.get_mut(&version_num) {
                version.delete();
            }
        }

        Ok(())
    }

    /// Undelete versions
    pub async fn undelete(&self, _path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let _secret = secrets
            .get_mut(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        for version_num in versions {
            if let Some(version) = _secret.versions.get_mut(&version_num)
                && !version.destroyed
            {
                version.undelete();
            }
        }

        Ok(())
    }

    /// Permanently destroy versions
    pub async fn destroy(&self, _path: &str, versions: Vec<u64>) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let _secret = secrets
            .get_mut(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        for version_num in versions {
            if let Some(version) = _secret.versions.get_mut(&version_num) {
                version.destroy();
            }
        }

        Ok(())
    }

    /// Get metadata
    pub async fn get_metadata(&self, _path: &str) -> Result<SecretMetadata, Kvv2Error> {
        let secrets = self.secrets.read().await;

        let _secret = secrets
            .get(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        Ok(_secret.metadata.clone())
    }

    /// Update metadata
    pub async fn update_metadata(
        &self,
        _path: &str,
        max_versions: Option<u64>,
        cas_required: Option<bool>,
        delete_version_after: Option<u64>,
        custom_metadata: Option<HashMap<String, String>>,
    ) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        let _secret = secrets
            .get_mut(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

        if let Some(max) = max_versions {
            _secret.metadata.max_versions = max;
        }

        if let Some(cas) = cas_required {
            _secret.metadata.cas_required = cas;
        }

        if let Some(delete_after) = delete_version_after {
            _secret.metadata.delete_version_after = delete_after;
        }

        if let Some(custom) = custom_metadata {
            _secret.metadata.custom_metadata = custom;
        }

        Ok(())
    }

    /// List secrets
    pub async fn list(&self, prefix: &str) -> Vec<String> {
        let secrets = self.secrets.read().await;

        secrets
            .keys()
            .filter(|_path| _path.starts_with(prefix))
            .cloned()
            .collect()
    }

    /// Delete metadata and all versions
    pub async fn delete_metadata(&self, _path: &str) -> Result<(), Kvv2Error> {
        let mut secrets = self.secrets.write().await;

        secrets
            .remove(_path)
            .ok_or_else(|| Kvv2Error::SecretNotFound(_path.to_string()))?;

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

        let mut _data = HashMap::new();
        _data.insert(
            "_password".to_string(),
            Value::String("secret123".to_string()),
        );

        let version = kv.write("_secret/myapp", _data.clone(), None).await.unwrap();
        assert_eq!(version.version, 1);

        let read = kv.read("_secret/myapp", None).await.unwrap();
        assert_eq!(read.version, 1);
        assert_eq!(
            read._data.get("_password"),
            Some(&Value::String("secret123".to_string()))
        );
    }

    #[tokio::test]
    async fn test_versions() {
        let kv = Kvv2Engine::new();

        // Write version 1
        let mut data1 = HashMap::new();
        data1.insert("_key".to_string(), Value::String("value1".to_string()));
        kv.write("_secret/test", data1, None).await.unwrap();

        // Write version 2
        let mut data2 = HashMap::new();
        data2.insert("_key".to_string(), Value::String("value2".to_string()));
        kv.write("_secret/test", data2, None).await.unwrap();

        // Read latest (v2)
        let latest = kv.read("_secret/test", None).await.unwrap();
        assert_eq!(latest.version, 2);

        // Read specific version (v1)
        let v1 = kv.read("_secret/test", Some(1)).await.unwrap();
        assert_eq!(v1.version, 1);
        assert_eq!(
            v1._data.get("_key"),
            Some(&Value::String("value1".to_string()))
        );
    }

    #[tokio::test]
    async fn test_delete_undelete() {
        let kv = Kvv2Engine::new();

        let mut _data = HashMap::new();
        _data.insert("_key".to_string(), Value::String("value".to_string()));
        kv.write("_secret/test", _data, None).await.unwrap();

        // Soft delete
        kv.delete("_secret/test", vec![1]).await.unwrap();

        // Should fail to read
        let result = kv.read("_secret/test", Some(1)).await;
        assert!(result.is_err());

        // Undelete
        kv.undelete("_secret/test", vec![1]).await.unwrap();

        // Should succeed now
        let read = kv.read("_secret/test", Some(1)).await;
        assert!(read.is_ok());
    }

    #[tokio::test]
    async fn test_cas() {
        let kv = Kvv2Engine::new();

        let mut _data = HashMap::new();
        _data.insert("_key".to_string(), Value::String("value".to_string()));
        kv.write("_secret/test", _data.clone(), None).await.unwrap();

        // Enable CAS
        kv.update_metadata("_secret/test", None, Some(true), None, None)
            .await
            .unwrap();

        // Write with correct CAS should succeed
        kv.write("_secret/test", _data.clone(), Some(1))
            .await
            .unwrap();

        // Write with wrong CAS should fail
        let result = kv.write("_secret/test", _data, Some(1)).await;
        assert!(result.is_err());
    }
}
