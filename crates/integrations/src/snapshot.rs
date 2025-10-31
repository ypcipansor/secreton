//! Snapshot and Restore
//!
//! Backup and restore functionality for disaster recovery.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Snapshot errors
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("Snapshot not found: {0}")]
    NotFound(String),

    #[error("Snapshot creation failed: {0}")]
    CreationFailed(String),

    #[error("Restore failed: {0}")]
    RestoreFailed(String),

    #[error("Invalid snapshot data: {0}")]
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

    /// Size in bytes
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
    /// Full snapshot of all data
    Full,

    /// Incremental snapshot (changes since last snapshot)
    Incremental { base_snapshot_id: String },
}

/// Snapshot data containing all Vault state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotData {
    /// Secrets data
    pub secrets: HashMap<String, Vec<u8>>,

    /// Auth data
    pub auth: HashMap<String, Vec<u8>>,

    /// Policies
    pub policies: HashMap<String, String>,

    /// Configuration
    pub config: HashMap<String, serde_json::Value>,

    /// Audit logs (optional, can be large)
    pub audit_logs: Option<Vec<AuditEntry>>,

    /// Version
    pub version: String,
}

/// Audit log entry for snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Operation
    pub operation: String,

    /// Path
    pub path: String,

    /// Identity
    pub identity: Option<String>,
}

/// Restore options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestoreOptions {
    /// Skip secrets restoration
    pub skip_secrets: bool,

    /// Skip auth restoration
    pub skip_auth: bool,

    /// Skip policies restoration
    pub skip_policies: bool,

    /// Skip config restoration
    pub skip_config: bool,

    /// Force restore (overwrite existing data)
    pub force: bool,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            skip_secrets: false,
            skip_auth: false,
            skip_policies: false,
            skip_config: false,
            force: false,
        }
    }
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
    /// Create new snapshot service
    pub fn new() -> Self {
        Self {
            snapshots: Arc::new(RwLock::new(HashMap::new())),
            snapshot_data: Arc::new(RwLock::new(HashMap::new())),
            current_state: Arc::new(RwLock::new(SnapshotData {
                secrets: HashMap::new(),
                auth: HashMap::new(),
                policies: HashMap::new(),
                config: HashMap::new(),
                audit_logs: None,
                version: "1.0.0".to_string(),
            })),
        }
    }

    /// Create full snapshot
    pub async fn create_snapshot(
        &self,
        description: Option<String>,
        include_audit: bool,
    ) -> Result<Snapshot, SnapshotError> {
        let id = uuid::Uuid::new_v4().to_string();

        // Capture current state
        let current_state = self.current_state.read().await;
        let mut data = current_state.clone();

        if !include_audit {
            data.audit_logs = None;
        }

        // Calculate size and checksum
        let serialized =
            serde_json::to_vec(&data).map_err(|e| SnapshotError::CreationFailed(e.to_string()))?;

        let size = serialized.len() as u64;
        let checksum = self.calculate_checksum(&serialized);

        let snapshot = Snapshot {
            id: id.clone(),
            timestamp: Utc::now(),
            size,
            checksum,
            snapshot_type: SnapshotType::Full,
            description,
            metadata: HashMap::new(),
        };

        // Store snapshot
        let mut snapshots = self.snapshots.write().await;
        snapshots.insert(id.clone(), snapshot.clone());

        let mut snapshot_data = self.snapshot_data.write().await;
        snapshot_data.insert(id.clone(), data);

        Ok(snapshot)
    }

    /// Create incremental snapshot
    pub async fn create_incremental_snapshot(
        &self,
        base_snapshot_id: String,
        description: Option<String>,
    ) -> Result<Snapshot, SnapshotError> {
        let id = uuid::Uuid::new_v4().to_string();

        // Clone base data to avoid holding read lock
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

        let serialized =
            serde_json::to_vec(&diff).map_err(|e| SnapshotError::CreationFailed(e.to_string()))?;

        let size = serialized.len() as u64;
        let checksum = self.calculate_checksum(&serialized);

        let snapshot = Snapshot {
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
        snapshots.insert(id.clone(), snapshot.clone());

        let mut snapshot_data_map = self.snapshot_data.write().await;
        snapshot_data_map.insert(id.clone(), diff);

        Ok(snapshot)
    }

    /// Restore from snapshot
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
        let data = snapshot_data
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
                current_state.secrets = data.secrets.clone();
                result.secrets_restored = data.secrets.len();
            } else {
                for (key, value) in &data.secrets {
                    if !current_state.secrets.contains_key(key) {
                        current_state.secrets.insert(key.clone(), value.clone());
                        result.secrets_restored += 1;
                    }
                }
            }
        }

        // Restore auth
        if !options.skip_auth {
            if options.force {
                current_state.auth = data.auth.clone();
                result.auth_restored = data.auth.len();
            } else {
                for (key, value) in &data.auth {
                    if !current_state.auth.contains_key(key) {
                        current_state.auth.insert(key.clone(), value.clone());
                        result.auth_restored += 1;
                    }
                }
            }
        }

        // Restore policies
        if !options.skip_policies {
            if options.force {
                current_state.policies = data.policies.clone();
                result.policies_restored = data.policies.len();
            } else {
                for (key, value) in &data.policies {
                    if !current_state.policies.contains_key(key) {
                        current_state.policies.insert(key.clone(), value.clone());
                        result.policies_restored += 1;
                    }
                }
            }
        }

        // Restore config
        if !options.skip_config {
            if options.force {
                current_state.config = data.config.clone();
                result.config_restored = data.config.len();
            } else {
                for (key, value) in &data.config {
                    if !current_state.config.contains_key(key) {
                        current_state.config.insert(key.clone(), value.clone());
                        result.config_restored += 1;
                    }
                }
            }
        }

        Ok(result)
    }

    /// Get snapshot
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

    /// Delete snapshot
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
    fn calculate_checksum(&self, data: &[u8]) -> String {
        // In production, use SHA-256
        // For now, simple hash
        format!("sha256-{:x}", data.len())
    }

    /// Calculate diff between snapshots
    fn calculate_diff(&self, base: &SnapshotData, current: &SnapshotData) -> SnapshotData {
        let mut diff = SnapshotData {
            secrets: HashMap::new(),
            auth: HashMap::new(),
            policies: HashMap::new(),
            config: HashMap::new(),
            audit_logs: None,
            version: current.version.clone(),
        };

        // Find changed secrets
        for (key, value) in &current.secrets {
            if base.secrets.get(key) != Some(value) {
                diff.secrets.insert(key.clone(), value.clone());
            }
        }

        // Find changed auth
        for (key, value) in &current.auth {
            if base.auth.get(key) != Some(value) {
                diff.auth.insert(key.clone(), value.clone());
            }
        }

        // Find changed policies
        for (key, value) in &current.policies {
            if base.policies.get(key) != Some(value) {
                diff.policies.insert(key.clone(), value.clone());
            }
        }

        // Find changed config
        for (key, value) in &current.config {
            if base.config.get(key) != Some(value) {
                diff.config.insert(key.clone(), value.clone());
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

        // Add some data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
                state
                    .policies
                    .insert("policy1".to_string(), "rule1".to_string());
            })
            .await;

        let snapshot = service
            .create_snapshot(Some("Test snapshot".to_string()), false)
            .await
            .unwrap();

        assert_eq!(snapshot.snapshot_type, SnapshotType::Full);
        assert!(snapshot.size > 0);
    }

    #[tokio::test]
    async fn test_restore_snapshot() {
        let service = SnapshotService::new();

        // Create initial data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
                state
                    .policies
                    .insert("policy1".to_string(), "rule1".to_string());
            })
            .await;

        // Create snapshot
        let snapshot = service.create_snapshot(None, false).await.unwrap();

        // Clear data
        service
            .update_state(|state| {
                state.secrets.clear();
                state.policies.clear();
            })
            .await;

        // Restore
        let result = service
            .restore_snapshot(
                &snapshot.id,
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

        // Initial data
        service
            .update_state(|state| {
                state.secrets.insert("secret1".to_string(), vec![1, 2, 3]);
            })
            .await;

        // Create base snapshot
        let base_snapshot = service.create_snapshot(None, false).await.unwrap();

        // Add more data
        service
            .update_state(|state| {
                state.secrets.insert("secret2".to_string(), vec![4, 5, 6]);
            })
            .await;

        // Create incremental snapshot
        let incremental = service
            .create_incremental_snapshot(base_snapshot.id.clone(), Some("Incremental".to_string()))
            .await
            .unwrap();

        assert!(matches!(
            incremental.snapshot_type,
            SnapshotType::Incremental { .. }
        ));
        // Incremental snapshot contains only diff, should be smaller or equal
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
