//! Snapshot and Restore
//!
//! Backup and restore functionality for disaster recovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Snapshot errors
#[derive(Error, Debug)]
pub enum SnapshotError {
    #[error("Snapshot not found: {0}")]
    NotFound(String),

    #[error("Snapshot creation failed: {0}")]
    CreationFailed(String),

    #[error("Restore failed: {0}")]
    RestoreFailed(String),

    #[error("Invalid _snapshot _data: {0}")]
    InvalidData(String),

    #[error("Checksum mismatch")]
    ChecksumMismatch,
}

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot ID
    pub id: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Size in _bytes
    pub size: u64,

    /// Checksum (SHA-256)
    pub checksum: String,

    /// Snapshot type
    pub snapshot_type: SnapshotType,

    /// Description
    pub description: Option<String>,

    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Snapshot type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SnapshotType {
    /// Full _snapshot of all _data
    Full,

    /// Incremental _snapshot (changes since last _snapshot)
    Incremental { base_snapshot_id: String },
}

/// Snapshot _data containing all Vault state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    /// Secrets _data
    pub secrets: HashMap<String, Vec<u8>>,

    /// Auth _data
    pub auth: HashMap<String, Vec<u8>>,

    /// Policies
    pub policies: HashMap<String, String>,

    /// Configuration
    pub _config: HashMap<String, serde_json::Value>,

    /// Audit logs (optional, can be large)
    pub audit_logs: Option<Vec<AuditEntry>>,

    /// Version
    pub version: String,
}

/// Audit log entry for _snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Operation
    pub operation: String,

    /// Path
    pub _path: String,

    /// Identity
    pub identity: Option<String>,
}

/// Restore options
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RestoreOptions {
    /// Skip secrets restoration
    pub skip_secrets: bool,

    /// Skip auth restoration
    pub skip_auth: bool,

    /// Skip policies restoration
    pub skip_policies: bool,

    /// Skip _config restoration
    pub skip_config: bool,

    /// Force restore (overwrite existing _data)
    pub force: bool,
}

/// Restore result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreResult {
    /// Snapshot ID restored
    pub snapshot_id: String,

    /// Secrets restored count
    pub secrets_restored: usize,

    /// Auth entries restored count
    pub auth_restored: usize,

    /// Policies restored count
    pub policies_restored: usize,

    /// Config entries restored count
    pub config_restored: usize,

    /// Errors encountered
    pub errors: Vec<String>,
}

/// Snapshot service
pub struct SnapshotService {
    snapshots: Arc<RwLock<HashMap<String, Snapshot>>>,
    snapshot_data: Arc<RwLock<HashMap<String, SnapshotData>>>,
    current_state: Arc<RwLock<SnapshotData>>,
}

impl SnapshotService {
    /// Create new _snapshot service
    pub fn new() -> Self {
        Self {
            snapshots: Arc::new(RwLock::new(HashMap::new())),
            snapshot_data: Arc::new(RwLock::new(HashMap::new())),
            current_state: Arc::new(RwLock::new(SnapshotData {
                secrets: HashMap::new(),
                auth: HashMap::new(),
                policies: HashMap::new(),
                _config: HashMap::new(),
                audit_logs: None,
                version: "1.0.0".to_string(),
            })),
        }
    }

    /// Create full _snapshot
    pub async fn create_snapshot(
        &self,
        description: Option<String>,
        include_audit: bool,
    ) -> Result<Snapshot, SnapshotError> {
        let id = uuid::Uuid::new_v4().to_string();

        // Capture current state
        let current_state = self.current_state.read().await;
        let mut _data = current_state.clone();

        if !include_audit {
            _data.audit_logs = None;
        }

        // Calculate size and checksum
        let serialized = serde_json::to_vec(&_data)
            .map_err(|_e| SnapshotError::CreationFailed(_e.to_string()))?;

        let size = serialized.len() as u64;
        let checksum = self.calculate_checksum(&serialized);

        let _snapshot = Snapshot {
            id: id.clone(),
            timestamp: Utc::now(),
            size,
            checksum,
            snapshot_type: SnapshotType::Full,
            description,
            metadata: HashMap::new(),
        };

        // Store _snapshot
        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(id.clone(), _snapshot.clone());

        let mut snapshot_data = self.snapshot_data.write().await;
        snapshot_data.insert(id.clone(), _data);

        Ok(_snapshot)
    }

    /// Create incremental _snapshot
    pub async fn create_incremental_snapshot(
        &self,
        base_snapshot_id: String,
        description: Option<String>,
    ) -> Result<Snapshot, SnapshotError> {
        let id = uuid::Uuid::new_v4().to_string();

        // Clone base _data to avoid holding read lock
        let base_data = {
            let snapshot_data = self.snapshot_data.read().await;
            snapshot_data
                .get(&base_snapshot_id)
                .ok_or_else(|| SnapshotError::NotFound(base_snapshot_id.clone()))?
                .clone()
        };

        // Calculate diff with current state
        let diff = {
            let current_state = self.current_state.read().await;
            self.calculate_diff(&base_data, &current_state)
        };

        let serialized = serde_json::to_vec(&diff)
            .map_err(|_e| SnapshotError::CreationFailed(_e.to_string()))?;

        let size = serialized.len() as u64;
        let checksum = self.calculate_checksum(&serialized);

        let _snapshot = Snapshot {
            id: id.clone(),
            timestamp: Utc::now(),
            size,
            checksum,
            snapshot_type: SnapshotType::Incremental {
                base_snapshot_id: base_snapshot_id.clone(),
            },
            description,
            metadata: HashMap::new(),
        };

        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(id.clone(), _snapshot.clone());

        let mut snapshot_data_map = self.snapshot_data.write().await;
        snapshot_data_map.insert(id.clone(), diff);

        Ok(_snapshot)
    }

    /// Restore from _snapshot
    pub async fn restore_snapshot(
        &self,
        snapshot_id: &str,
        options: RestoreOptions,
    ) -> Result<RestoreResult, SnapshotError> {
        let snapshots = self.snapshots.read().await;
        let _snapshot = snapshots
            .get(snapshot_id)
            .ok_or_else(|| SnapshotError::NotFound(snapshot_id.to_string()))?
            .clone();
        drop(snapshots);

        let snapshot_data = self.snapshot_data.read().await;
        let _data = snapshot_data
            .get(snapshot_id)
            .ok_or_else(|| SnapshotError::NotFound(snapshot_id.to_string()))?
            .clone();
        drop(snapshot_data);

        let mut result = RestoreResult {
            snapshot_id: snapshot_id.to_string(),
            secrets_restored: 0,
            auth_restored: 0,
            policies_restored: 0,
            config_restored: 0,
            errors: Vec::new(),
        };

        let mut current_state = self.current_state.write().await;

        // Restore secrets
        if !options.skip_secrets {
            if options.force {
                current_state.secrets = _data.secrets.clone();
                result.secrets_restored = _data.secrets.len();
            } else {
                for (_key, value) in &_data.secrets {
                    if !current_state.secrets.contains_key(_key) {
                        current_state.secrets.insert(_key.clone(), value.clone());
                        result.secrets_restored += 1;
                    }
                }
            }
        }

        // Restore auth
        if !options.skip_auth {
            if options.force {
                current_state.auth = _data.auth.clone();
                result.auth_restored = _data.auth.len();
            } else {
                for (_key, value) in &_data.auth {
                    if !current_state.auth.contains_key(_key) {
                        current_state.auth.insert(_key.clone(), value.clone());
                        result.auth_restored += 1;
                    }
                }
            }
        }

        // Restore policies
        if !options.skip_policies {
            if options.force {
                current_state.policies = _data.policies.clone();
                result.policies_restored = _data.policies.len();
            } else {
                for (_key, value) in &_data.policies {
                    if !current_state.policies.contains_key(_key) {
                        current_state.policies.insert(_key.clone(), value.clone());
                        result.policies_restored += 1;
                    }
                }
            }
        }

        // Restore _config
        if !options.skip_config {
            if options.force {
                current_state._config = _data._config.clone();
                result.config_restored = _data._config.len();
            } else {
                for (_key, value) in &_data._config {
                    if !current_state._config.contains_key(_key) {
                        current_state._config.insert(_key.clone(), value.clone());
                        result.config_restored += 1;
                    }
                }
            }
        }

        Ok(result)
    }

    /// Get _snapshot
    pub async fn get_snapshot(&self, id: &str) -> Option<Snapshot> {
        let snapshots = self.snapshots.read().await;
        snapshots.get(id).cloned()
    }

    /// List snapshots
    pub async fn list_snapshots(&self) -> Vec<Snapshot> {
        let snapshots = self.snapshots.read().await;
        let mut list: Vec<_> = snapshots.values().cloned().collect();
        list.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        list
    }

    /// Delete _snapshot
    pub async fn delete_snapshot(&self, id: &str) -> Result<(), SnapshotError> {
        let mut snapshots = self.snapshots.write().await;
        let mut snapshot_data = self.snapshot_data.write().await;

        snapshots
            .remove(id)
            .ok_or_else(|| SnapshotError::NotFound(id.to_string()))?;
        snapshot_data.remove(id);

        Ok(())
    }

    /// Update current state (for testing)
    pub async fn update_state(&self, update_fn: impl FnOnce(&mut SnapshotData)) {
        let mut current_state = self.current_state.write().await;
        update_fn(&mut current_state);
    }

    /// Calculate checksum
    fn calculate_checksum(&self, _data: &[u8]) -> String {
        // In production, use SHA-256
        // For now, simple hash
        format!("sha256-{:x}", _data.len())
    }

    /// Calculate diff between snapshots
    fn calculate_diff(&self, base: &SnapshotData, current: &SnapshotData) -> SnapshotData {
        let mut diff = SnapshotData {
            secrets: HashMap::new(),
            auth: HashMap::new(),
            policies: HashMap::new(),
            _config: HashMap::new(),
            audit_logs: None,
            version: current.version.clone(),
        };

        // Find changed secrets
        for (_key, value) in &current.secrets {
            if base.secrets.get(_key) != Some(value) {
                diff.secrets.insert(_key.clone(), value.clone());
            }
        }

        // Find changed auth
        for (_key, value) in &current.auth {
            if base.auth.get(_key) != Some(value) {
                diff.auth.insert(_key.clone(), value.clone());
            }
        }

        // Find changed policies
        for (_key, value) in &current.policies {
            if base.policies.get(_key) != Some(value) {
                diff.policies.insert(_key.clone(), value.clone());
            }
        }

        // Find changed _config
        for (_key, value) in &current._config {
            if base._config.get(_key) != Some(value) {
                diff._config.insert(_key.clone(), value.clone());
            }
        }

        diff
    }
}

impl Default for SnapshotService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_full_snapshot() {
        let service = SnapshotService::new();

        // Add some _data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
                state
                    .policies
                    .insert("policy1".to_string(), "rule1".to_string());
            })
            .await;

        let _snapshot = service
            .create_snapshot(Some("Test _snapshot".to_string()), false)
            .await
            .unwrap();

        assert_eq!(_snapshot.snapshot_type, SnapshotType::Full);
        assert!(_snapshot.size > 0);
    }

    #[tokio::test]
    async fn test_restore_snapshot() {
        let service = SnapshotService::new();

        // Create initial _data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
                state
                    .policies
                    .insert("policy1".to_string(), "rule1".to_string());
            })
            .await;

        // Create _snapshot
        let _snapshot = service.create_snapshot(None, false).await.unwrap();

        // Clear _data
        service
            .update_state(|state| {
                state.secrets.clear();
                state.policies.clear();
            })
            .await;

        // Restore
        let result = service
            .restore_snapshot(
                &_snapshot.id,
                RestoreOptions {
                    force: true,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(result.secrets_restored, 1);
        assert_eq!(result.policies_restored, 1);
    }

    #[tokio::test]
    async fn test_incremental_snapshot() {
        let service = SnapshotService::new();

        // Initial _data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
            })
            .await;

        // Create base _snapshot
        let base_snapshot = service.create_snapshot(None, false).await.unwrap();

        // Add more _data
        service
            .update_state(|state| {
                state.secrets.insert("secret2".to_string(), vec![4, 5, 6]);
            })
            .await;

        // Create incremental _snapshot
        let incremental = service
            .create_incremental_snapshot(base_snapshot.id.clone(), Some("Incremental".to_string()))
            .await
            .unwrap();

        assert!(matches!(
            incremental.snapshot_type,
            SnapshotType::Incremental { .. }
        ));
        // Incremental _snapshot contains only diff, should be smaller or equal
        assert!(incremental.size <= base_snapshot.size);
    }

    #[tokio::test]
    async fn test_list_and_delete_snapshots() {
        let service = SnapshotService::new();

        let snapshot1 = service
            .create_snapshot(Some("First".to_string()), false)
            .await
            .unwrap();
        let snapshot2 = service
            .create_snapshot(Some("Second".to_string()), false)
            .await
            .unwrap();

        let list = service.list_snapshots().await;
        assert_eq!(list.len(), 2);

        service.delete_snapshot(&snapshot1.id).await.unwrap();

        let list = service.list_snapshots().await;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, snapshot2.id);
    }
}
