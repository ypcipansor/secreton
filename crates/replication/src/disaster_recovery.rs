//! Disaster Recovery Replication Service
//!
//! Handles disaster recovery replication across Vault clusters.
//! In DR mode, all data is replicated but the secondary cluster remains sealed.

use std::sync::{Arc, Mutex};

use crate::common::{BaseReplicationConfig, ClusterNode, ReplicationMode, ReplicationState, ReplicationStatus};
use crate::error::ReplicationError;

/// Disaster Recovery Replication Service
///
/// This service handles disaster recovery replication where:
/// - All data is replicated from primary to secondary
/// - Secondary cluster remains sealed and cannot serve requests
/// - Used for failover scenarios when primary becomes unavailable
pub struct DisasterRecoveryService {
    config: Arc<Mutex<Option<BaseReplicationConfig>>>,
    state: Arc<Mutex<ReplicationState>>,
    cluster_nodes: Arc<Mutex<Vec<ClusterNode>>>,
    is_primary: Arc<Mutex<bool>>,
}

impl DisasterRecoveryService {
    /// Create new disaster recovery replication service
    pub fn new() -> Self {
        Self {
            config: Arc::new(Mutex::new(None)),
            state: Arc::new(Mutex::new(ReplicationState::Idle)),
            cluster_nodes: Arc::new(Mutex::new(Vec::new())),
            is_primary: Arc::new(Mutex::new(true)),
        }
    }

    /// Configure disaster recovery replication
    pub async fn configure(&self, config: BaseReplicationConfig) -> Result<(), ReplicationError> {
        if config.cluster_id.is_empty() {
            return Err(ReplicationError::InvalidConfiguration(
                "Cluster ID cannot be empty".to_string(),
            ));
        }

        if config.mode != ReplicationMode::DisasterRecovery {
            return Err(ReplicationError::InvalidConfiguration(
                "Disaster recovery service requires DisasterRecovery mode".to_string(),
            ));
        }

        let mut current_config = self.config.lock().unwrap();
        *current_config = Some(config);
        Ok(())
    }

    /// Start replication as primary
    pub async fn start_as_primary(&self) -> Result<(), ReplicationError> {
        let config = self.config.lock().unwrap();
        if config.is_none() {
            return Err(ReplicationError::NotConfigured);
        }
        // Config validated, can proceed

        let state = self.state.lock().unwrap();
        if *state != ReplicationState::Idle {
            return Err(ReplicationError::AlreadyReplicating);
        }
        drop(state);

        let mut is_primary = self.is_primary.lock().unwrap();
        *is_primary = true;

        let mut state = self.state.lock().unwrap();
        *state = ReplicationState::Active;

        Ok(())
    }

    /// Start replication as secondary
    pub async fn start_as_secondary(&self) -> Result<(), ReplicationError> {
        let config = self.config.lock().unwrap();
        let config = config.as_ref().ok_or(ReplicationError::NotConfigured)?;

        if config.primary_cluster_addr.is_none() {
            return Err(ReplicationError::InvalidConfiguration(
                "Primary cluster address required for secondary".to_string(),
            ));
        }
        // Config validated, can proceed

        let mut is_primary = self.is_primary.lock().unwrap();
        *is_primary = false;

        let mut state = self.state.lock().unwrap();
        *state = ReplicationState::Syncing;

        // Simulate initial sync
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        *state = ReplicationState::Active;

        Ok(())
    }

    /// Stop replication
    pub async fn stop(&self) -> Result<(), ReplicationError> {
        let state = self.state.lock().unwrap();
        if *state == ReplicationState::Idle {
            return Err(ReplicationError::NotReplicating);
        }
        // State validated, can proceed

        let mut state = self.state.lock().unwrap();
        *state = ReplicationState::Idle;

        Ok(())
    }

    /// Get replication status
    pub async fn get_status(&self) -> ReplicationStatus {
        let state = self.state.lock().unwrap();
        let is_primary = self.is_primary.lock().unwrap();
        let config = self.config.lock().unwrap();
        let cluster_id = config.as_ref().map(|c| c.cluster_id.clone()).unwrap_or_else(|| "unknown".to_string());
        ReplicationStatus {
            state: state.clone(),
            cluster_id,
            is_primary: *is_primary,
            last_sync: None,
            connected_secondaries: vec![],
        }
    }

    /// Register secondary node
    pub async fn register_secondary(&self, node: ClusterNode) {
        let mut nodes = self.cluster_nodes.lock().unwrap();

        // Remove old entry if exists
        nodes.retain(|n| n.node_id != node.node_id);

        // Add new entry
        nodes.push(node);
    }

    /// Perform failover to secondary cluster
    ///
    /// This method unseals the secondary cluster and promotes it to primary.
    /// Should only be called when the primary cluster is confirmed down.
    pub async fn failover(&self) -> Result<(), ReplicationError> {
        {
            let is_primary = self.is_primary.lock().unwrap();
            if *is_primary {
                return Err(ReplicationError::InvalidConfiguration(
                    "Cannot failover on primary cluster".to_string(),
                ));
            }
        }

        // In a real implementation, this would:
        // 1. Verify primary is unreachable
        // 2. Unseal the secondary cluster
        // 3. Promote to primary
        // 4. Update cluster configuration

        let mut is_primary = self.is_primary.lock().unwrap();
        *is_primary = true;

        let mut state = self.state.lock().unwrap();
        *state = ReplicationState::Active;

        Ok(())
    }
}

impl Default for DisasterRecoveryService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_start_dr_replication() {
        let service = DisasterRecoveryService::new();

        let config = BaseReplicationConfig {
            mode: ReplicationMode::DisasterRecovery,
            cluster_id: "cluster-1".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        service.configure(config).await.unwrap();
        service.start_as_primary().await.unwrap();

        let status = service.get_status().await;
        assert_eq!(status.state, ReplicationState::Active);
        assert_eq!(status.cluster_id, "cluster-1");
        assert!(status.is_primary);
    }

    #[tokio::test]
    async fn test_dr_secondary_mode() {
        let service = DisasterRecoveryService::new();

        let config = BaseReplicationConfig {
            mode: ReplicationMode::DisasterRecovery,
            cluster_id: "cluster-2".to_string(),
            primary_cluster_addr: Some("https://primary:8200".to_string()),
            secondary_token: Some("token".to_string()),
            enabled: true,
        };

        service.configure(config).await.unwrap();
        service.start_as_secondary().await.unwrap();

        let status = service.get_status().await;
        assert_eq!(status.state, ReplicationState::Active);
        assert!(!status.is_primary);
    }

    #[tokio::test]
    async fn test_invalid_mode_configuration() {
        let service = DisasterRecoveryService::new();

        let config = BaseReplicationConfig {
            mode: ReplicationMode::Performance,
            cluster_id: "cluster-3".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        let result = service.configure(config).await;
        assert!(matches!(result, Err(ReplicationError::InvalidConfiguration(_))));
    }

    #[tokio::test]
    async fn test_failover() {
        let secondary = DisasterRecoveryService::new();

        let config = BaseReplicationConfig {
            mode: ReplicationMode::DisasterRecovery,
            cluster_id: "cluster-4".to_string(),
            primary_cluster_addr: Some("https://primary:8200".to_string()),
            secondary_token: Some("token".to_string()),
            enabled: true,
        };

        secondary.configure(config).await.unwrap();
        secondary.start_as_secondary().await.unwrap();

        // Verify it's secondary
        let status = secondary.get_status().await;
        assert!(!status.is_primary);

        // Perform failover
        secondary.failover().await.unwrap();

        // Verify it's now primary
        let status = secondary.get_status().await;
        assert!(status.is_primary);
    }
}