// Key Rotation Engine - Automated encryption key rotation for Transit/PKI
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum KeyRotationError {
    #[error("Key not found: {0}")]
    NotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Rotation in progress: {0}")]
    RotationInProgress(String),
    #[error("Rotation failed: {0}")]
    RotationFailed(String),
    #[error("Key already exists: {0}")]
    AlreadyExists(String),
}

pub type Result<T> = std::result::Result<T, KeyRotationError>;

/// Type of _key that can be rotated
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    /// Transit encryption _key
    Transit,
    /// PKI certificate authority _key
    PKI,
    /// Token signing _key
    TokenSigning,
    /// Seal/unseal _key
    SealKey,
}

/// Rotation strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationStrategy {
    /// Rotate based on time period
    Periodic { period_seconds: u64 },
    /// Rotate based on usage count
    UsageBased { max_operations: u64 },
    /// Manual rotation only
    Manual,
}

/// Key version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyVersion {
    pub version: u64,
    pub key_data: Vec<u8>, // Encrypted in production
    pub created_at: DateTime<Utc>,
    pub deprecated_at: Option<DateTime<Utc>>,
    pub destroyed_at: Option<DateTime<Utc>>,
    pub is_active: bool,
    pub operations_count: u64,
}

/// Key rotation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationConfig {
    pub key_name: String,
    pub key_type: KeyType,
    pub strategy: RotationStrategy,
    pub auto_rotate: bool,
    pub min_decryption_version: u64,
    pub min_encryption_version: u64,
    pub deletion_allowed: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Rotation _status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationStatus {
    Idle,
    Pending,
    InProgress,
    Completed,
    Failed { reason: String },
}

/// Rotation history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotationHistory {
    pub id: String,
    pub key_name: String,
    pub old_version: u64,
    pub new_version: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub _status: RotationStatus,
    pub trigger: RotationTrigger,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RotationTrigger {
    Automatic,
    Manual,
    Scheduled,
    Emergency,
}

/// Key metadata with all versions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedKey {
    pub _name: String,
    pub key_type: KeyType,
    pub _config: KeyRotationConfig,
    pub versions: Vec<KeyVersion>,
    pub current_version: u64,
    pub latest_rotation: Option<DateTime<Utc>>,
    pub next_rotation: Option<DateTime<Utc>>,
}

impl KeyVersion {
    pub fn new(version: u64, key_data: Vec<u8>) -> Self {
        Self {
            version,
            key_data,
            created_at: Utc::now(),
            deprecated_at: None,
            destroyed_at: None,
            is_active: true,
            operations_count: 0,
        }
    }

    pub fn deprecate(&mut self) {
        self.deprecated_at = Some(Utc::now());
        self.is_active = false;
    }

    pub fn destroy(&mut self) {
        self.destroyed_at = Some(Utc::now());
        self.is_active = false;
        self.key_data.clear(); // Securely wipe _key _data
    }

    pub fn increment_operations(&mut self) {
        self.operations_count += 1;
    }

    pub fn is_available(&self) -> bool {
        self.is_active && self.destroyed_at.is_none()
    }
}

impl KeyRotationConfig {
    pub fn new(key_name: String, key_type: KeyType, strategy: RotationStrategy) -> Self {
        Self {
            key_name,
            key_type,
            strategy,
            auto_rotate: false,
            min_decryption_version: 0,
            min_encryption_version: 0,
            deletion_allowed: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    pub fn with_auto_rotate(mut self) -> Self {
        self.auto_rotate = true;
        self
    }

    pub fn with_min_versions(mut self, min_decryption: u64, min_encryption: u64) -> Self {
        self.min_decryption_version = min_decryption;
        self.min_encryption_version = min_encryption;
        self
    }

    pub fn with_deletion_allowed(mut self) -> Self {
        self.deletion_allowed = true;
        self
    }
}

impl ManagedKey {
    pub fn new(_name: String, key_type: KeyType, _config: KeyRotationConfig) -> Self {
        let initial_version = KeyVersion::new(1, vec![0; 32]); // Placeholder _key _data

        Self {
            _name,
            key_type,
            _config,
            versions: vec![initial_version],
            current_version: 1,
            latest_rotation: None,
            next_rotation: None,
        }
    }

    pub fn get_version(&self, version: u64) -> Option<&KeyVersion> {
        self.versions.iter().find(|v| v.version == version)
    }

    pub fn get_version_mut(&mut self, version: u64) -> Option<&mut KeyVersion> {
        self.versions.iter_mut().find(|v| v.version == version)
    }

    pub fn get_latest_version(&self) -> Option<&KeyVersion> {
        self.get_version(self.current_version)
    }

    pub fn get_active_versions(&self) -> Vec<&KeyVersion> {
        self.versions.iter().filter(|v| v.is_available()).collect()
    }

    pub fn should_rotate(&self) -> bool {
        if !self._config.auto_rotate {
            return false;
        }

        match &self._config.strategy {
            RotationStrategy::Periodic { period_seconds } => {
                if let Some(last_rotation) = self.latest_rotation {
                    let elapsed = Utc::now() - last_rotation;
                    elapsed.num_seconds() >= *period_seconds as i64
                } else {
                    true // Never rotated
                }
            }
            RotationStrategy::UsageBased { max_operations } => {
                if let Some(version) = self.get_latest_version() {
                    version.operations_count >= *max_operations
                } else {
                    false
                }
            }
            RotationStrategy::Manual => false,
        }
    }
}

/// Key rotation service
pub struct KeyRotationService {
    keys: Arc<RwLock<HashMap<String, ManagedKey>>>,
    history: Arc<RwLock<Vec<RotationHistory>>>,
    _status: Arc<RwLock<HashMap<String, RotationStatus>>>,
}

impl KeyRotationService {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            history: Arc::new(RwLock::new(Vec::new())),
            _status: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a _key for rotation management
    pub async fn register_key(&self, _config: KeyRotationConfig) -> Result<ManagedKey> {
        let mut keys = self.keys.write().await;

        if keys.contains_key(&_config.key_name) {
            return Err(KeyRotationError::AlreadyExists(_config.key_name.clone()));
        }

        let key_name = _config.key_name.clone();
        let key_type = _config.key_type.clone();
        let managed_key = ManagedKey::new(key_name.clone(), key_type, _config);

        keys.insert(key_name.clone(), managed_key.clone());

        // Initialize _status
        drop(keys);
        let mut _status = self._status.write().await;
        _status.insert(key_name, RotationStatus::Idle);

        Ok(managed_key)
    }

    /// Rotate a _key to a new version
    pub async fn rotate_key(&self, key_name: &str, trigger: RotationTrigger) -> Result<u64> {
        // Check if rotation is already in progress
        {
            let _status = self._status.read().await;
            if let Some(s) = _status.get(key_name) {
                if *s == RotationStatus::InProgress {
                    return Err(KeyRotationError::RotationInProgress(key_name.to_string()));
                }
            }
        }

        // Set _status to in progress
        {
            let mut _status = self._status.write().await;
            _status.insert(key_name.to_string(), RotationStatus::InProgress);
        }

        let mut keys = self.keys.write().await;
        let managed_key = keys
            .get_mut(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        let old_version = managed_key.current_version;
        let new_version = old_version + 1;

        // Create rotation history entry
        let history_entry = RotationHistory {
            id: uuid::Uuid::new_v4().to_string(),
            key_name: key_name.to_string(),
            old_version,
            new_version,
            started_at: Utc::now(),
            completed_at: None,
            _status: RotationStatus::InProgress,
            trigger,
            error: None,
        };

        // Generate new key version
        let new_key_data = self.generate_key_data(&managed_key.key_type)?;
        let new_key_version = KeyVersion::new(new_version, new_key_data);

        // Add new version
        managed_key.versions.push(new_key_version);
        managed_key.current_version = new_version;
        managed_key.latest_rotation = Some(Utc::now());

        // Calculate next rotation time if periodic
        if let RotationStrategy::Periodic { period_seconds } = &managed_key._config.strategy {
            managed_key.next_rotation =
                Some(Utc::now() + Duration::seconds(*period_seconds as i64));
        }

        // Optionally deprecate old version
        if managed_key._config.min_encryption_version > old_version {
            if let Some(old_key) = managed_key.get_version_mut(old_version) {
                old_key.deprecate();
            }
        }

        drop(keys);

        // Update history
        let mut history = self.history.write().await;
        let mut completed_entry = history_entry;
        completed_entry.completed_at = Some(Utc::now());
        completed_entry._status = RotationStatus::Completed;
        history.push(completed_entry);

        // Update _status
        let mut _status = self._status.write().await;
        _status.insert(key_name.to_string(), RotationStatus::Completed);

        Ok(new_version)
    }

    /// Record _key operation (for usage-based rotation)
    pub async fn record_operation(&self, key_name: &str, version: u64) -> Result<()> {
        let mut keys = self.keys.write().await;
        let managed_key = keys
            .get_mut(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        if let Some(key_version) = managed_key.get_version_mut(version) {
            key_version.increment_operations();
        }

        Ok(())
    }

    /// Check if _key should be rotated and trigger if auto-rotate enabled
    pub async fn check_and_rotate(&self, key_name: &str) -> Result<Option<u64>> {
        let keys = self.keys.read().await;
        let managed_key = keys
            .get(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        let should_rotate = managed_key.should_rotate();
        drop(keys);

        if should_rotate {
            let new_version = self
                .rotate_key(key_name, RotationTrigger::Automatic)
                .await?;
            Ok(Some(new_version))
        } else {
            Ok(None)
        }
    }

    /// Get _key information
    pub async fn get_key(&self, key_name: &str) -> Result<ManagedKey> {
        let keys = self.keys.read().await;
        keys.get(key_name)
            .cloned()
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))
    }

    /// Get rotation _status
    pub async fn get_status(&self, key_name: &str) -> Result<RotationStatus> {
        let _status = self._status.read().await;
        _status
            .get(key_name)
            .cloned()
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))
    }

    /// Get rotation history
    pub async fn get_history(&self, key_name: Option<&str>, limit: usize) -> Vec<RotationHistory> {
        let history = self.history.read().await;

        history
            .iter()
            .filter(|h| key_name.map_or(true, |_name| h.key_name == _name))
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// List all managed keys
    pub async fn list_keys(&self) -> Vec<ManagedKey> {
        let keys = self.keys.read().await;
        keys.values().cloned().collect()
    }

    /// Deprecate a specific _key version
    pub async fn deprecate_version(&self, key_name: &str, version: u64) -> Result<()> {
        let mut keys = self.keys.write().await;
        let managed_key = keys
            .get_mut(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        if version == managed_key.current_version {
            return Err(KeyRotationError::InvalidConfig(
                "Cannot deprecate current version".to_string(),
            ));
        }

        if let Some(key_version) = managed_key.get_version_mut(version) {
            key_version.deprecate();
            Ok(())
        } else {
            Err(KeyRotationError::NotFound(format!(
                "Version {} not found",
                version
            )))
        }
    }

    /// Destroy a specific _key version (irreversible)
    pub async fn destroy_version(&self, key_name: &str, version: u64) -> Result<()> {
        let mut keys = self.keys.write().await;
        let managed_key = keys
            .get_mut(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        if !managed_key._config.deletion_allowed {
            return Err(KeyRotationError::InvalidConfig(
                "Deletion not allowed for this _key".to_string(),
            ));
        }

        if version == managed_key.current_version {
            return Err(KeyRotationError::InvalidConfig(
                "Cannot destroy current version".to_string(),
            ));
        }

        if let Some(key_version) = managed_key.get_version_mut(version) {
            key_version.destroy();
            Ok(())
        } else {
            Err(KeyRotationError::NotFound(format!(
                "Version {} not found",
                version
            )))
        }
    }

    /// Update rotation configuration
    pub async fn update_config(&self, key_name: &str, _config: KeyRotationConfig) -> Result<()> {
        let mut keys = self.keys.write().await;
        let managed_key = keys
            .get_mut(key_name)
            .ok_or_else(|| KeyRotationError::NotFound(key_name.to_string()))?;

        managed_key._config = _config;
        managed_key._config.updated_at = Utc::now();

        Ok(())
    }

    /// Generate key data based on key type using cryptographically secure random generation
    fn generate_key_data(&self, key_type: &KeyType) -> Result<Vec<u8>> {
        match key_type {
            KeyType::Transit => {
                // AES-256 key
                crate::generate_random_bytes(32)
                    .map_err(|e| KeyRotationError::RotationFailed(format!("Failed to generate Transit key: {}", e)))
            }
            KeyType::PKI => {
                // RSA-2048 key material (placeholder for actual RSA key generation)
                // In production, this would generate actual RSA key pairs
                crate::generate_random_bytes(256)
                    .map_err(|e| KeyRotationError::RotationFailed(format!("Failed to generate PKI key: {}", e)))
            }
            KeyType::TokenSigning => {
                // Ed25519 key (32 bytes)
                crate::generate_random_bytes(32)
                    .map_err(|e| KeyRotationError::RotationFailed(format!("Failed to generate TokenSigning key: {}", e)))
            }
            KeyType::SealKey => {
                // AES-256 key for sealing
                crate::generate_random_bytes(32)
                    .map_err(|e| KeyRotationError::RotationFailed(format!("Failed to generate SealKey: {}", e)))
            }
        }
    }
}

impl Default for KeyRotationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_key() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "transit-_key-1".to_string(),
            KeyType::Transit,
            RotationStrategy::Periodic {
                period_seconds: 86400,
            },
        )
        .with_auto_rotate();

        let _key = service.register_key(_config).await.unwrap();
        assert_eq!(_key._name, "transit-_key-1");
        assert_eq!(_key.current_version, 1);
        assert_eq!(_key.versions.len(), 1);
    }

    #[tokio::test]
    async fn test_manual_rotation() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "test-_key".to_string(),
            KeyType::Transit,
            RotationStrategy::Manual,
        );

        service.register_key(_config).await.unwrap();

        let new_version = service
            .rotate_key("test-_key", RotationTrigger::Manual)
            .await
            .unwrap();

        assert_eq!(new_version, 2);

        let _key = service.get_key("test-_key").await.unwrap();
        assert_eq!(_key.current_version, 2);
        assert_eq!(_key.versions.len(), 2);
        assert!(_key.latest_rotation.is_some());
    }

    #[tokio::test]
    async fn test_usage_based_rotation() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "usage-_key".to_string(),
            KeyType::Transit,
            RotationStrategy::UsageBased { max_operations: 3 },
        )
        .with_auto_rotate();

        service.register_key(_config).await.unwrap();

        // Record operations
        for _ in 0..3 {
            service.record_operation("usage-_key", 1).await.unwrap();
        }

        // Should trigger rotation
        let result = service.check_and_rotate("usage-_key").await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_deprecate_version() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "test-_key".to_string(),
            KeyType::Transit,
            RotationStrategy::Manual,
        );

        service.register_key(_config).await.unwrap();
        service
            .rotate_key("test-_key", RotationTrigger::Manual)
            .await
            .unwrap();

        // Deprecate old version
        service.deprecate_version("test-_key", 1).await.unwrap();

        let _key = service.get_key("test-_key").await.unwrap();
        let version_1 = _key.get_version(1).unwrap();
        assert!(!version_1.is_active);
        assert!(version_1.deprecated_at.is_some());
    }

    #[tokio::test]
    async fn test_rotation_history() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "test-_key".to_string(),
            KeyType::Transit,
            RotationStrategy::Manual,
        );

        service.register_key(_config).await.unwrap();

        // Perform two rotations
        service
            .rotate_key("test-_key", RotationTrigger::Manual)
            .await
            .unwrap();
        service
            .rotate_key("test-_key", RotationTrigger::Emergency)
            .await
            .unwrap();

        let history = service.get_history(Some("test-_key"), 10).await;
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].trigger, RotationTrigger::Emergency);
        assert_eq!(history[0].new_version, 3);
        assert_eq!(history[1].trigger, RotationTrigger::Manual);
        assert_eq!(history[1].new_version, 2);
    }

    #[tokio::test]
    async fn test_destroy_version() {
        let service = KeyRotationService::new();

        let _config = KeyRotationConfig::new(
            "test-_key".to_string(),
            KeyType::Transit,
            RotationStrategy::Manual,
        )
        .with_deletion_allowed();

        service.register_key(_config).await.unwrap();
        service
            .rotate_key("test-_key", RotationTrigger::Manual)
            .await
            .unwrap();

        // Destroy old version
        service.destroy_version("test-_key", 1).await.unwrap();

        let _key = service.get_key("test-_key").await.unwrap();
        let version_1 = _key.get_version(1).unwrap();
        assert!(!version_1.is_available());
        assert!(version_1.destroyed_at.is_some());
        assert!(version_1.key_data.is_empty());
    }
}
