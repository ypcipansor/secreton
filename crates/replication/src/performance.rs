//! Performance Replication Service
//!
//! Handles performance replication with read replicas and eventual consistency.
//! In performance mode, secrets are replicated but secondary clusters can serve requests.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::common::{
    BaseReplicationConfig, ClusterNode, ReplicationMode, ReplicationState, ReplicationStatus,
};
use crate::error::ReplicationError;

/// Cluster status for performance replication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ClusterStatus {
    /// Cluster is active and serving requests
    Active,
    /// Cluster is syncing data
    Syncing,
    /// Cluster is degraded but still operational
    Degraded,
    /// Cluster is offline
    Offline,
}

/// Operation type for replication
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    /// Write operation
    Write,
    /// Delete operation
    Delete,
    /// Update operation
    Update,
}

/// Replication operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationOperation {
    /// Unique operation ID
    pub operation_id: String,
    /// Type of operation
    pub operation_type: OperationType,
    /// Path affected by operation
    pub path: String,
    /// Data for write operations
    pub data: Option<Vec<u8>>,
    /// Timestamp of operation
    pub timestamp: DateTime<Utc>,
    /// Clusters this operation has been replicated to
    pub replicated_to: Vec<String>,
}

/// Sync status for a replica cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncStatus {
    /// Cluster ID
    pub cluster_id: String,
    /// Number of operations pending replication
    pub operations_pending: u64,
    /// Number of operations successfully synced
    pub operations_synced: u64,
    /// Last sync timestamp
    pub last_sync_at: DateTime<Utc>,
    /// Estimated lag in milliseconds
    pub estimated_lag_ms: u64,
    /// Number of sync errors
    pub sync_errors: u64,
}

/// Performance Replication Service
///
/// This service handles performance replication where:
/// - Secrets are replicated to read replicas
/// - Secondary clusters can serve read requests
/// - Eventual consistency is maintained
/// - Lower latency for read operations across regions
pub struct PerformanceReplication {
    config: Arc<RwLock<BaseReplicationConfig>>,
    replicas: Arc<RwLock<HashMap<String, ClusterNode>>>,
    operations: Arc<RwLock<Vec<ReplicationOperation>>>,
    primary_cluster_id: Arc<RwLock<Option<String>>>,
}

impl PerformanceReplication {
    /// Create new performance replication service
    pub fn new(config: BaseReplicationConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            replicas: Arc::new(RwLock::new(HashMap::new())),
            operations: Arc::new(RwLock::new(Vec::new())),
            primary_cluster_id: Arc::new(RwLock::new(None)),
        }
    }

    /// Configure performance replication
    pub async fn configure(&self, config: BaseReplicationConfig) -> Result<(), ReplicationError> {
        if config.mode != ReplicationMode::Performance {
            return Err(ReplicationError::InvalidConfiguration(
                "Performance replication service requires Performance mode".to_string(),
            ));
        }

        let mut current_config = self.config.write().await;
        *current_config = config;
        Ok(())
    }

    /// Add replica cluster
    pub async fn add_replica(&self, replica: ClusterNode) -> Result<(), ReplicationError> {
        let mut replicas = self.replicas.write().await;
        replicas.insert(replica.node_id.clone(), replica);
        Ok(())
    }

    /// Remove replica cluster
    pub async fn remove_replica(&self, node_id: &str) -> Result<(), ReplicationError> {
        let mut replicas = self.replicas.write().await;
        replicas
            .remove(node_id)
            .ok_or_else(|| ReplicationError::ClusterError("Replica not found".to_string()))?;
        Ok(())
    }

    /// Record operation for replication
    pub async fn record_operation(
        &self,
        operation_type: OperationType,
        path: String,
        data: Option<Vec<u8>>,
    ) -> Result<String, ReplicationError> {
        let operation_id = uuid::Uuid::new_v4().to_string();

        let operation = ReplicationOperation {
            operation_id: operation_id.clone(),
            operation_type,
            path,
            data,
            timestamp: Utc::now(),
            replicated_to: Vec::new(),
        };

        let mut operations = self.operations.write().await;
        operations.push(operation);

        Ok(operation_id)
    }

    /// Sync operations to all active replicas
    pub async fn sync_to_replicas(&self) -> Result<HashMap<String, usize>, ReplicationError> {
        let mut sync_counts = HashMap::new();
        let replicas = self.replicas.read().await;
        let mut operations = self.operations.write().await;

        for (node_id, replica) in replicas.iter() {
            // In performance mode, all replicas can serve requests
            // so we sync to all connected replicas
            if replica.replication_lag.is_some() && replica.replication_lag.unwrap() > 1000 {
                continue; // Skip if lag is too high
            }

            let mut synced_count = 0;

            // Find operations not yet replicated to this cluster
            for operation in operations.iter_mut() {
                if !operation.replicated_to.contains(node_id) {
                    // Mock replication - real implementation would send to replica
                    self.mock_replicate_operation(operation, &replica.address)
                        .await?;

                    operation.replicated_to.push(node_id.clone());
                    synced_count += 1;
                }
            }

            sync_counts.insert(node_id.clone(), synced_count);
        }

        // Update last heartbeat for replicas that received sync
        drop(operations);
        drop(replicas);

        let mut replicas = self.replicas.write().await;
        for (node_id, _) in sync_counts.iter() {
            if let Some(replica) = replicas.get_mut(node_id) {
                replica.last_heartbeat = Utc::now();
            }
        }

        Ok(sync_counts)
    }

    /// Get sync status for a specific replica
    pub async fn get_sync_status(&self, node_id: &str) -> Result<SyncStatus, ReplicationError> {
        let replicas = self.replicas.read().await;
        let replica = replicas
            .get(node_id)
            .ok_or_else(|| ReplicationError::ClusterError("Replica not found".to_string()))?;

        let operations = self.operations.read().await;
        let node_id_string = node_id.to_string();

        let operations_pending = operations
            .iter()
            .filter(|op| !op.replicated_to.contains(&node_id_string))
            .count() as u64;

        let operations_synced = operations
            .iter()
            .filter(|op| op.replicated_to.contains(&node_id_string))
            .count() as u64;

        Ok(SyncStatus {
            cluster_id: node_id.to_string(),
            operations_pending,
            operations_synced,
            last_sync_at: replica.last_heartbeat,
            estimated_lag_ms: replica.replication_lag.unwrap_or(0),
            sync_errors: 0,
        })
    }

    /// Get replica cluster information
    pub async fn get_replica_info(&self, node_id: &str) -> Result<ClusterNode, ReplicationError> {
        let replicas = self.replicas.read().await;
        replicas
            .get(node_id)
            .cloned()
            .ok_or_else(|| ReplicationError::ClusterError("Replica not found".to_string()))
    }

    /// Update replica status and lag
    pub async fn update_replica_status(
        &self,
        node_id: &str,
        lag_ms: Option<u64>,
    ) -> Result<(), ReplicationError> {
        let mut replicas = self.replicas.write().await;
        let replica = replicas
            .get_mut(node_id)
            .ok_or_else(|| ReplicationError::ClusterError("Replica not found".to_string()))?;

        replica.replication_lag = lag_ms;
        replica.last_heartbeat = Utc::now();

        Ok(())
    }

    /// Promote replica to primary (for failover scenarios)
    pub async fn promote_replica(&self, node_id: &str) -> Result<(), ReplicationError> {
        let replica_address = {
            let replicas = self.replicas.read().await;
            let replica = replicas
                .get(node_id)
                .ok_or_else(|| ReplicationError::ClusterError("Replica not found".to_string()))?;

            if replica.replication_lag.is_some() && replica.replication_lag.unwrap() > 1000 {
                return Err(ReplicationError::ClusterError(
                    "Cannot promote replica with high lag".to_string(),
                ));
            }

            replica.address.clone()
        };

        // Update config to point to new primary
        let mut config = self.config.write().await;
        config.primary_cluster_addr = Some(replica_address);

        let mut primary_cluster_id = self.primary_cluster_id.write().await;
        *primary_cluster_id = Some(node_id.to_string());

        Ok(())
    }

    /// List all replica clusters
    pub async fn list_replicas(&self) -> Vec<ClusterNode> {
        let replicas = self.replicas.read().await;
        replicas.values().cloned().collect()
    }

    /// Get total operation count
    pub async fn get_operation_count(&self) -> usize {
        let operations = self.operations.read().await;
        operations.len()
    }

    /// Calculate average replication lag across all replicas
    pub async fn calculate_average_lag(&self) -> u64 {
        let replicas = self.replicas.read().await;

        let active_replicas: Vec<_> = replicas
            .values()
            .filter(|r| r.replication_lag.is_some())
            .collect();

        if active_replicas.is_empty() {
            return 0;
        }

        let total_lag: u64 = active_replicas
            .iter()
            .map(|r| r.replication_lag.unwrap())
            .sum();
        total_lag / active_replicas.len() as u64
    }

    /// Get replication status summary
    pub async fn get_status(&self) -> ReplicationStatus {
        let config = self.config.read().await;
        let replicas = self.replicas.read().await;
        let _operations = self.operations.read().await;

        ReplicationStatus {
            state: ReplicationState::Active,
            cluster_id: config.cluster_id.clone(),
            is_primary: true, // Performance replication service is typically on primary
            last_sync: Some(Utc::now()),
            connected_secondaries: replicas.values().cloned().collect(),
        }
    }

    // Mock replication operation (would be replaced with actual network calls)
    async fn mock_replicate_operation(
        &self,
        _operation: &ReplicationOperation,
        _endpoint: &str,
    ) -> Result<(), ReplicationError> {
        // Simulate network delay
        tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;
        // Real implementation would POST operation to endpoint
        Ok(())
    }
}

impl Default for PerformanceReplication {
    fn default() -> Self {
        Self::new(BaseReplicationConfig {
            mode: ReplicationMode::Performance,
            cluster_id: "default".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> BaseReplicationConfig {
        BaseReplicationConfig {
            mode: ReplicationMode::Performance,
            cluster_id: "test-cluster".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        }
    }
    fn create_test_replica(name: &str) -> ClusterNode {
        ClusterNode {
            node_id: uuid::Uuid::new_v4().to_string(),
            address: format!("https://{}.vault.example.com", name),
            is_primary: false,
            last_heartbeat: Utc::now(),
            replication_lag: Some(0),
        }
    }

    #[tokio::test]
    async fn test_add_replica() {
        let replication = PerformanceReplication::new(create_test_config());
        let replica = create_test_replica("replica1");

        replication.add_replica(replica.clone()).await.unwrap();

        let replicas = replication.list_replicas().await;
        assert_eq!(replicas.len(), 1);
        assert_eq!(replicas[0].address, replica.address);
    }

    #[tokio::test]
    async fn test_record_and_sync_operations() {
        let replication = PerformanceReplication::new(create_test_config());
        let replica = create_test_replica("replica1");

        replication.add_replica(replica.clone()).await.unwrap();

        // Record operations
        replication
            .record_operation(
                OperationType::Write,
                "/secret/data/app1".to_string(),
                Some(vec![1, 2, 3]),
            )
            .await
            .unwrap();

        replication
            .record_operation(
                OperationType::Write,
                "/secret/data/app2".to_string(),
                Some(vec![4, 5, 6]),
            )
            .await
            .unwrap();

        let op_count = replication.get_operation_count().await;
        assert_eq!(op_count, 2);

        // Sync to replicas
        let sync_counts = replication.sync_to_replicas().await.unwrap();
        assert_eq!(sync_counts.get(&replica.node_id), Some(&2));
    }

    #[tokio::test]
    async fn test_get_sync_status() {
        let replication = PerformanceReplication::new(create_test_config());
        let replica = create_test_replica("replica1");

        replication.add_replica(replica.clone()).await.unwrap();

        replication
            .record_operation(OperationType::Write, "/secret/data/app1".to_string(), None)
            .await
            .unwrap();

        let status = replication.get_sync_status(&replica.node_id).await.unwrap();

        assert_eq!(status.operations_pending, 1);
        assert_eq!(status.operations_synced, 0);

        // Sync
        replication.sync_to_replicas().await.unwrap();

        let status = replication.get_sync_status(&replica.node_id).await.unwrap();

        assert_eq!(status.operations_pending, 0);
        assert_eq!(status.operations_synced, 1);
    }

    #[tokio::test]
    async fn test_promote_replica() {
        let replication = PerformanceReplication::new(create_test_config());
        let replica = create_test_replica("replica1");

        replication.add_replica(replica.clone()).await.unwrap();

        replication.promote_replica(&replica.node_id).await.unwrap();

        let config = replication.config.read().await;
        assert_eq!(config.primary_cluster_addr, Some(replica.address));
    }

    #[tokio::test]
    async fn test_replica_lag_monitoring() {
        let replication = PerformanceReplication::new(create_test_config());

        let mut replica1 = create_test_replica("replica1");
        replica1.replication_lag = Some(50);

        let mut replica2 = create_test_replica("replica2");
        replica2.replication_lag = Some(150);

        replication.add_replica(replica1).await.unwrap();
        replication.add_replica(replica2).await.unwrap();

        let avg_lag = replication.calculate_average_lag().await;
        assert_eq!(avg_lag, 100); // (50 + 150) / 2
    }

    #[tokio::test]
    async fn test_invalid_mode_configuration() {
        let replication = PerformanceReplication::new(create_test_config());

        let dr_config = BaseReplicationConfig {
            mode: ReplicationMode::DisasterRecovery,
            cluster_id: "test".to_string(),
            primary_cluster_addr: None,
            secondary_token: None,
            enabled: true,
        };

        let result = replication.configure(dr_config).await;
        assert!(matches!(
            result,
            Err(ReplicationError::InvalidConfiguration(_))
        ));
    }
}
