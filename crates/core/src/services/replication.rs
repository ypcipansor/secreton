//! Replication System
//!
//! Disaster Recovery and Performance replication across Vault clusters.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Replication errors
#[derive(Debug, thiserror::Error)]
pub enum ReplicationError {
    #[error("Replication not configured")]
    NotConfigured,

    #[error("Already replicating")]
    AlreadyReplicating,

    #[error("Not replicating")]
    NotReplicating,

    #[error("Invalid cluster configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),
}

/// Replication mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReplicationMode {
    /// Disaster Recovery: all data replicated, secondary sealed
    DR,

    /// Performance: secrets replicated, secondary can serve requests
    Performance,
}

/// Replication state
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReplicationState {
    /// Not replicating
    Idle,

    /// Initial synchronization
    Syncing,

    /// Active replication
    Active,

    /// Error state
    Error(String),
}

/// Cluster node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    /// Node ID
    pub node_id: String,

    /// Node address
    pub address: String,

    /// Is primary node
    pub is_primary: bool,

    /// Last heartbeat
    pub last_heartbeat: DateTime<Utc>,

    /// Replication lag (seconds)
    pub replication_lag: Option<u64>,
}

/// Replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationConfig {
    /// Replication mode
    pub mode: ReplicationMode,

    /// Cluster ID
    pub cluster_id: String,

    /// Primary cluster address
    pub primary_cluster_addr: Option<String>,

    /// Secondary token for authentication
    pub secondary_token: Option<String>,

    /// Enabled
    pub enabled: bool,
}

/// Merkle tree node for state verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleNode {
    /// Path
    pub path: String,

    /// Hash of data
    pub hash: String,

    /// Version
    pub version: u64,
}

/// Write-Ahead Log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WALEntry {
    /// Entry ID (sequence number)
    pub id: u64,

    /// Operation (write, delete)
    pub operation: String,

    /// Path
    pub path: String,

    /// Data (for write operations)
    pub data: Option<Vec<u8>>,

    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// Replication status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    /// Current state
    pub state: ReplicationState,

    /// Mode
    pub mode: Option<ReplicationMode>,

    /// Cluster ID
    pub cluster_id: Option<String>,

    /// Is primary
    pub is_primary: bool,

    /// Last sync time
    pub last_sync: Option<DateTime<Utc>>,

    /// WAL index (last replicated)
    pub wal_index: u64,

    /// Connected secondaries
    pub connected_secondaries: Vec<ClusterNode>,
}

/// Replication service
pub struct ReplicationService {
    config: Arc<RwLock<Option<ReplicationConfig>>>,
    state: Arc<RwLock<ReplicationState>>,
    wal: Arc<RwLock<Vec<WALEntry>>>,
    merkle_tree: Arc<RwLock<HashMap<String, MerkleNode>>>,
    cluster_nodes: Arc<RwLock<Vec<ClusterNode>>>,
    is_primary: Arc<RwLock<bool>>,
    wal_index: Arc<RwLock<u64>>,
}

impl ReplicationService {
    /// Create new replication service
    pub fn new() -> Self {
        Self {
            config: Arc::new(RwLock::new(None)),
            state: Arc::new(RwLock::new(ReplicationState::Idle)),
            wal: Arc::new(RwLock::new(Vec::new())),
            merkle_tree: Arc::new(RwLock::new(HashMap::new())),
            cluster_nodes: Arc::new(RwLock::new(Vec::new())),
            is_primary: Arc::new(RwLock::new(true)),
            wal_index: Arc::new(RwLock::new(0)),
        }
    }

    /// Configure replication
    pub async fn configure(&self, config: ReplicationConfig) -> Result<(), ReplicationError> {
        if config.cluster_id.is_empty() {
            return Err(ReplicationError::InvalidConfiguration(
                "Cluster ID cannot be empty".to_string(),
            ));
        }

        let mut current_config = self.config.write().await;
        *current_config = Some(config);
        Ok(())
    }

    /// Start replication as primary
    pub async fn start_as_primary(&self) -> Result<(), ReplicationError> {
        let config = self.config.read().await;
        if config.is_none() {
            return Err(ReplicationError::NotConfigured);
        }
        drop(config);

        let state = self.state.read().await;
        if *state != ReplicationState::Idle {
            return Err(ReplicationError::AlreadyReplicating);
        }
        drop(state);

        let mut is_primary = self.is_primary.write().await;
        *is_primary = true;

        let mut state = self.state.write().await;
        *state = ReplicationState::Active;

        Ok(())
    }

    /// Start replication as secondary
    pub async fn start_as_secondary(&self) -> Result<(), ReplicationError> {
        let config = self.config.read().await;
        let config = config.as_ref().ok_or(ReplicationError::NotConfigured)?;

        if config.primary_cluster_addr.is_none() {
            return Err(ReplicationError::InvalidConfiguration(
                "Primary cluster address required for secondary".to_string(),
            ));
        }
        drop(config);

        let mut is_primary = self.is_primary.write().await;
        *is_primary = false;

        let mut state = self.state.write().await;
        *state = ReplicationState::Syncing;

        // Simulate initial sync
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        *state = ReplicationState::Active;

        Ok(())
    }

    /// Stop replication
    pub async fn stop(&self) -> Result<(), ReplicationError> {
        let state = self.state.read().await;
        if *state == ReplicationState::Idle {
            return Err(ReplicationError::NotReplicating);
        }
        drop(state);

        let mut state = self.state.write().await;
        *state = ReplicationState::Idle;

        Ok(())
    }

    /// Append to WAL (Write-Ahead Log)
    pub async fn append_wal(&self, operation: String, path: String, data: Option<Vec<u8>>) -> u64 {
        let mut wal = self.wal.write().await;
        let mut wal_index = self.wal_index.write().await;

        *wal_index += 1;

        let entry = WALEntry {
            id: *wal_index,
            operation,
            path: path.clone(),
            data,
            timestamp: Utc::now(),
        };

        wal.push(entry);

        // Update merkle tree
        let mut merkle = self.merkle_tree.write().await;
        merkle.insert(
            path.clone(),
            MerkleNode {
                path,
                hash: format!("hash-{}", *wal_index),
                version: *wal_index,
            },
        );

        *wal_index
    }

    /// Get WAL entries since index
    pub async fn get_wal_since(&self, since_index: u64) -> Vec<WALEntry> {
        let wal = self.wal.read().await;
        wal.iter()
            .filter(|entry| entry.id > since_index)
            .cloned()
            .collect()
    }

    /// Sync state from primary
    pub async fn sync_state(&self, entries: Vec<WALEntry>) -> Result<(), ReplicationError> {
        let is_primary = self.is_primary.read().await;
        if *is_primary {
            return Err(ReplicationError::InvalidConfiguration(
                "Cannot sync state on primary".to_string(),
            ));
        }
        drop(is_primary);

        let mut wal = self.wal.write().await;
        let mut merkle = self.merkle_tree.write().await;
        let mut wal_index = self.wal_index.write().await;

        for entry in entries {
            wal.push(entry.clone());

            merkle.insert(
                entry.path.clone(),
                MerkleNode {
                    path: entry.path,
                    hash: format!("hash-{}", entry.id),
                    version: entry.id,
                },
            );

            *wal_index = entry.id.max(*wal_index);
        }

        Ok(())
    }

    /// Get replication status
    pub async fn get_status(&self) -> ReplicationStatus {
        let config = self.config.read().await;
        let state = self.state.read().await;
        let is_primary = self.is_primary.read().await;
        let wal_index = self.wal_index.read().await;
        let nodes = self.cluster_nodes.read().await;

        let last_sync = if *state == ReplicationState::Active {
            Some(Utc::now())
        } else {
            None
        };

        ReplicationStatus {
            state: state.clone(),
            mode: config.as_ref().map(|c| c.mode.clone()),
            cluster_id: config.as_ref().map(|c| c.cluster_id.clone()),
            is_primary: *is_primary,
            last_sync,
            wal_index: *wal_index,
            connected_secondaries: nodes.clone(),
        }
    }

    /// Register secondary node
    pub async fn register_secondary(&self, node: ClusterNode) {
        let mut nodes = self.cluster_nodes.write().await;

        // Remove old entry if exists
        nodes.retain(|n| n.node_id != node.node_id);

        // Add new entry
        nodes.push(node);
    }

    /// Get merkle tree for verification
    pub async fn get_merkle_tree(&self) -> HashMap<String, MerkleNode> {
        let merkle = self.merkle_tree.read().await;
        merkle.clone()
    }

    /// Verify merkle tree matches
    pub async fn verify_merkle(&self, remote_merkle: HashMap<String, MerkleNode>) -> bool {
        let local_merkle = self.merkle_tree.read().await;

        if local_merkle.len() != remote_merkle.len() {
            return false;
        }

        for (path, local_node) in local_merkle.iter() {
            if let Some(remote_node) = remote_merkle.get(path) {
                if local_node.hash != remote_node.hash {
                    return false;
                }
            } else {
                return false;
            }
        }

        true
    }
}

impl Default for ReplicationService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_dr_replication() {
        let service = ReplicationService::new();

        let config = ReplicationConfig {
            mode: ReplicationMode::DR,
            cluster_id: "cluster-1".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        service.configure(config).await.unwrap();
        service.start_as_primary().await.unwrap();

        let status = service.get_status().await;
        assert_eq!(status.state, ReplicationState::Active);
        assert_eq!(status.mode.unwrap(), ReplicationMode::DR);
        assert!(status.is_primary);
    }

    #[tokio::test]
    async fn test_performance_replication() {
        let service = ReplicationService::new();

        let config = ReplicationConfig {
            mode: ReplicationMode::Performance,
            cluster_id: "cluster-2".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        service.configure(config).await.unwrap();
        service.start_as_primary().await.unwrap();

        let status = service.get_status().await;
        assert_eq!(status.mode.unwrap(), ReplicationMode::Performance);
    }

    #[tokio::test]
    async fn test_wal_sync() {
        let primary = ReplicationService::new();
        let secondary = ReplicationService::new();

        let config = ReplicationConfig {
            mode: ReplicationMode::DR,
            cluster_id: "cluster-3".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        primary.configure(config.clone()).await.unwrap();
        primary.start_as_primary().await.unwrap();

        // Write to primary
        primary
            .append_wal(
                "write".to_string(),
                "secret/data".to_string(),
                Some(vec![1, 2, 3]),
            )
            .await;
        primary
            .append_wal(
                "write".to_string(),
                "secret/data2".to_string(),
                Some(vec![4, 5, 6]),
            )
            .await;

        // Get WAL entries
        let entries = primary.get_wal_since(0).await;
        assert_eq!(entries.len(), 2);

        // Configure secondary
        let mut secondary_config = config;
        secondary_config.primary_cluster_addr = Some("https://primary:8200".to_string());
        secondary.configure(secondary_config).await.unwrap();
        secondary.start_as_secondary().await.unwrap();

        // Sync to secondary
        secondary.sync_state(entries).await.unwrap();

        let secondary_status = secondary.get_status().await;
        assert_eq!(secondary_status.wal_index, 2);
    }

    #[tokio::test]
    async fn test_merkle_verification() {
        let service = ReplicationService::new();

        service
            .append_wal(
                "write".to_string(),
                "secret/test".to_string(),
                Some(vec![1, 2, 3]),
            )
            .await;

        let merkle = service.get_merkle_tree().await;

        // Verify with itself
        assert!(service.verify_merkle(merkle.clone()).await);

        // Verify with modified merkle
        let mut modified_merkle = merkle;
        if let Some(node) = modified_merkle.get_mut("secret/test") {
            node.hash = "different-hash".to_string();
        }

        assert!(!service.verify_merkle(modified_merkle).await);
    }
}
