// Secret Versioning System - Version control for secrets with rollback
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum VersionError {
    #[error("Version error: {0}")]
    VersionError(String),
    #[error("Version not found: {0}")]
    VersionNotFound(u64),
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    #[error("Invalid version: {0}")]
    InvalidVersion(String),
}

pub type Result<T> = std::result::Result<T, VersionError>;

/// Version configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionConfig {
    pub max_versions: u64,
    pub retention_days: u64,
    pub enable_diff: bool,
    pub auto_prune: bool,
}

/// Change type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ChangeType {
    Create,
    Update,
    Delete,
}

/// Version metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionMetadata {
    pub change_type: ChangeType,
    pub change_reason: Option<String>,
    pub tags: Vec<String>,
    pub approved_by: Option<String>,
}

/// Secret version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version_id: u64,
    pub secret_path: String,
    pub _data: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub metadata: VersionMetadata,
    pub checksum: String, // SHA256
    pub is_deleted: bool,
}

/// Version diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionDiff {
    pub version_from: u64,
    pub version_to: u64,
    pub added_keys: Vec<String>,
    pub removed_keys: Vec<String>,
    pub modified_keys: Vec<KeyDiff>,
}

/// Key diff
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDiff {
    pub _key: String,
    pub old_value: String,
    pub new_value: String,
}

/// Version history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionHistory {
    pub secret_path: String,
    pub versions: Vec<SecretVersion>,
    pub current_version: u64,
}

/// Secret Versioning System
pub struct SecretVersioning {
    _config: Arc<RwLock<VersionConfig>>,
    histories: Arc<RwLock<HashMap<String, VersionHistory>>>,
}

impl SecretVersioning {
    pub fn new(_config: VersionConfig) -> Self {
        Self {
            _config: Arc::new(RwLock::new(_config)),
            histories: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create new version
    pub async fn create_version(
        &self,
        secret_path: &str,
        _data: HashMap<String, String>,
        created_by: &str,
        metadata: VersionMetadata,
    ) -> Result<SecretVersion> {
        let checksum = self.calculate_checksum(&_data);

        let mut histories = self.histories.write().await;
        let history = histories
            .entry(secret_path.to_string())
            .or_insert_with(|| VersionHistory {
                secret_path: secret_path.to_string(),
                versions: Vec::new(),
                current_version: 0,
            });

        let version_id = history.current_version + 1;

        let version = SecretVersion {
            version_id,
            secret_path: secret_path.to_string(),
            _data,
            created_at: Utc::now(),
            created_by: created_by.to_string(),
            metadata,
            checksum,
            is_deleted: false,
        };

        history.versions.push(version.clone());
        history.current_version = version_id;

        // Auto-prune if enabled
        let _config = self._config.read().await;
        if _config.auto_prune {
            self.prune_old_versions_internal(history, _config.max_versions)
                .await;
        }
        drop(_config);

        Ok(version)
    }

    /// Get specific version
    pub async fn get_version(&self, secret_path: &str, version_id: u64) -> Result<SecretVersion> {
        let histories = self.histories.read().await;
        let history = histories
            .get(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        history
            .versions
            .iter()
            .find(|v| v.version_id == version_id)
            .cloned()
            .ok_or(VersionError::VersionNotFound(version_id))
    }

    /// List all versions for _secret
    pub async fn list_versions(&self, secret_path: &str) -> Result<Vec<SecretVersion>> {
        let histories = self.histories.read().await;
        let history = histories
            .get(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        Ok(history.versions.clone())
    }

    /// Rollback to previous version
    pub async fn rollback_to_version(
        &self,
        secret_path: &str,
        version_id: u64,
        rolled_back_by: &str,
    ) -> Result<SecretVersion> {
        // Get the target version
        let target_version = self.get_version(secret_path, version_id).await?;

        // Create new version with old _data
        let metadata = VersionMetadata {
            change_type: ChangeType::Update,
            change_reason: Some(format!("Rolled back to version {}", version_id)),
            tags: vec!["rollback".to_string()],
            approved_by: Some(rolled_back_by.to_string()),
        };

        self.create_version(
            secret_path,
            target_version._data.clone(),
            rolled_back_by,
            metadata,
        )
        .await
    }

    /// Diff two versions
    pub async fn diff_versions(
        &self,
        secret_path: &str,
        version_from: u64,
        version_to: u64,
    ) -> Result<VersionDiff> {
        let from = self.get_version(secret_path, version_from).await?;
        let to = self.get_version(secret_path, version_to).await?;

        let mut added_keys = Vec::new();
        let mut removed_keys = Vec::new();
        let mut modified_keys = Vec::new();

        // Find added and modified keys
        for (_key, new_value) in &to._data {
            match from._data.get(_key) {
                Some(old_value) => {
                    if old_value != new_value {
                        modified_keys.push(KeyDiff {
                            _key: _key.clone(),
                            old_value: old_value.clone(),
                            new_value: new_value.clone(),
                        });
                    }
                }
                None => added_keys.push(_key.clone()),
            }
        }

        // Find removed keys
        for _key in from._data.keys() {
            if !to._data.contains_key(_key) {
                removed_keys.push(_key.clone());
            }
        }

        Ok(VersionDiff {
            version_from,
            version_to,
            added_keys,
            removed_keys,
            modified_keys,
        })
    }

    /// Delete old versions
    pub async fn delete_old_versions(&self, secret_path: &str) -> Result<usize> {
        let _config = self._config.read().await;
        let retention_days = _config.retention_days;
        let max_versions = _config.max_versions;
        drop(_config);

        let mut histories = self.histories.write().await;
        let history = histories
            .get_mut(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
        let original_count = history.versions.len();

        // Keep max_versions most recent versions
        if history.versions.len() > max_versions as usize {
            let keep_from = history.versions.len() - max_versions as usize;
            history.versions.drain(..keep_from);
        }

        // Delete versions older than retention period (but keep at least one)
        if history.versions.len() > 1 {
            history.versions.retain(|v| v.created_at > cutoff);

            // Ensure at least one version remains
            if history.versions.is_empty() {
                return Err(VersionError::VersionError(
                    "Cannot delete all versions".to_string(),
                ));
            }
        }

        let deleted_count = original_count - history.versions.len();
        Ok(deleted_count)
    }

    async fn prune_old_versions_internal(&self, history: &mut VersionHistory, max_versions: u64) {
        if history.versions.len() > max_versions as usize {
            let keep_from = history.versions.len() - max_versions as usize;
            history.versions.drain(..keep_from);
        }
    }

    /// Get version metadata
    pub async fn get_version_metadata(
        &self,
        secret_path: &str,
        version_id: u64,
    ) -> Result<VersionMetadata> {
        let version = self.get_version(secret_path, version_id).await?;
        Ok(version.metadata)
    }

    /// Compare version with current
    pub async fn compare_with_current(
        &self,
        secret_path: &str,
        version_id: u64,
    ) -> Result<VersionDiff> {
        let histories = self.histories.read().await;
        let history = histories
            .get(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        let current_version = history.current_version;
        drop(histories);

        self.diff_versions(secret_path, version_id, current_version)
            .await
    }

    /// Export version history
    pub async fn export_version_history(&self, secret_path: &str) -> Result<String> {
        let histories = self.histories.read().await;
        let history = histories
            .get(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        serde_json::to_string_pretty(history)
            .map_err(|_e| VersionError::VersionError(_e.to_string()))
    }

    /// Get current version
    pub async fn get_current_version(&self, secret_path: &str) -> Result<SecretVersion> {
        let histories = self.histories.read().await;
        let history = histories
            .get(secret_path)
            .ok_or_else(|| VersionError::SecretNotFound(secret_path.to_string()))?;

        self.get_version(secret_path, history.current_version).await
    }

    fn calculate_checksum(&self, _data: &HashMap<String, String>) -> String {
        // Mock SHA256 checksum
        // Real implementation would use sha2 crate
        let serialized = format!("{:?}", _data);
        format!("{:064x}", serialized.len() * 123456789)
    }
}

impl Default for SecretVersioning {
    fn default() -> Self {
        let _config = VersionConfig {
            max_versions: 10,
            retention_days: 90,
            enable_diff: true,
            auto_prune: true,
        };

        Self::new(_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_data_v1() -> HashMap<String, String> {
        let mut _data = HashMap::new();
        _data.insert("_username".to_string(), "admin".to_string());
        _data.insert("_password".to_string(), "secret123".to_string());
        _data
    }

    fn create_test_data_v2() -> HashMap<String, String> {
        let mut _data = HashMap::new();
        _data.insert("_username".to_string(), "admin".to_string());
        _data.insert("_password".to_string(), "newsecret456".to_string());
        _data.insert("api_key".to_string(), "key789".to_string());
        _data
    }

    #[tokio::test]
    async fn test_create_versions() {
        let versioning = SecretVersioning::default();

        let metadata = VersionMetadata {
            change_type: ChangeType::Create,
            change_reason: Some("Initial creation".to_string()),
            tags: vec!["production".to_string()],
            approved_by: None,
        };

        let v1 = versioning
            .create_version("/_secret/db", create_test_data_v1(), "user1", metadata)
            .await
            .unwrap();

        assert_eq!(v1.version_id, 1);
        assert_eq!(v1.created_by, "user1");

        let metadata2 = VersionMetadata {
            change_type: ChangeType::Update,
            change_reason: Some("Password rotation".to_string()),
            tags: vec![],
            approved_by: None,
        };

        let v2 = versioning
            .create_version("/_secret/db", create_test_data_v2(), "user2", metadata2)
            .await
            .unwrap();

        assert_eq!(v2.version_id, 2);
    }

    #[tokio::test]
    async fn test_rollback_to_version() {
        let versioning = SecretVersioning::default();

        let metadata = VersionMetadata {
            change_type: ChangeType::Create,
            change_reason: None,
            tags: vec![],
            approved_by: None,
        };

        versioning
            .create_version(
                "/_secret/db",
                create_test_data_v1(),
                "user1",
                metadata.clone(),
            )
            .await
            .unwrap();

        versioning
            .create_version(
                "/_secret/db",
                create_test_data_v2(),
                "user2",
                metadata.clone(),
            )
            .await
            .unwrap();

        let rolled_back = versioning
            .rollback_to_version("/_secret/db", 1, "admin")
            .await
            .unwrap();

        assert_eq!(rolled_back.version_id, 3);
        assert_eq!(rolled_back._data, create_test_data_v1());
        assert_eq!(rolled_back.created_by, "admin");
    }

    #[tokio::test]
    async fn test_diff_versions() {
        let versioning = SecretVersioning::default();

        let metadata = VersionMetadata {
            change_type: ChangeType::Create,
            change_reason: None,
            tags: vec![],
            approved_by: None,
        };

        versioning
            .create_version(
                "/_secret/db",
                create_test_data_v1(),
                "user1",
                metadata.clone(),
            )
            .await
            .unwrap();

        versioning
            .create_version("/_secret/db", create_test_data_v2(), "user2", metadata)
            .await
            .unwrap();

        let diff = versioning.diff_versions("/_secret/db", 1, 2).await.unwrap();

        assert_eq!(diff.added_keys, vec!["api_key"]);
        assert_eq!(diff.removed_keys.len(), 0);
        assert_eq!(diff.modified_keys.len(), 1);
        assert_eq!(diff.modified_keys[0]._key, "_password");
        assert_eq!(diff.modified_keys[0].old_value, "secret123");
        assert_eq!(diff.modified_keys[0].new_value, "newsecret456");
    }

    #[tokio::test]
    async fn test_version_pruning() {
        let _config = VersionConfig {
            max_versions: 3,
            retention_days: 90,
            enable_diff: true,
            auto_prune: true,
        };

        let versioning = SecretVersioning::new(_config);

        let metadata = VersionMetadata {
            change_type: ChangeType::Create,
            change_reason: None,
            tags: vec![],
            approved_by: None,
        };

        // Create 5 versions
        for i in 1..=5 {
            let mut _data = HashMap::new();
            _data.insert("version".to_string(), i.to_string());

            versioning
                .create_version("/_secret/db", _data, "_user", metadata.clone())
                .await
                .unwrap();
        }

        let versions = versioning.list_versions("/_secret/db").await.unwrap();

        // Should keep only max_versions (3)
        assert_eq!(versions.len(), 3);
        assert_eq!(versions[0].version_id, 3);
        assert_eq!(versions[2].version_id, 5);
    }

    #[tokio::test]
    async fn test_version_metadata() {
        let versioning = SecretVersioning::default();

        let metadata = VersionMetadata {
            change_type: ChangeType::Update,
            change_reason: Some("Security update".to_string()),
            tags: vec!["urgent".to_string(), "security".to_string()],
            approved_by: Some("security_team".to_string()),
        };

        versioning
            .create_version("/_secret/db", create_test_data_v1(), "user1", metadata)
            .await
            .unwrap();

        let retrieved_metadata = versioning
            .get_version_metadata("/_secret/db", 1)
            .await
            .unwrap();

        assert_eq!(retrieved_metadata.change_type, ChangeType::Update);
        assert_eq!(retrieved_metadata.tags.len(), 2);
        assert_eq!(
            retrieved_metadata.approved_by,
            Some("security_team".to_string())
        );
    }
}
