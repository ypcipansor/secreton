//! Common replication types and traits

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::ReplicationError;

/// Replication mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ReplicationMode {
    /// Disaster Recovery: all data replicated, secondary sealed
    DisasterRecovery,

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

/// Base replication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseReplicationConfig {
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

/// Replication status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationStatus {
    /// Current state
    pub state: ReplicationState,

    /// Cluster ID
    pub cluster_id: String,

    /// Is primary
    pub is_primary: bool,

    /// Last sync time
    pub last_sync: Option<DateTime<Utc>>,

    /// Connected secondaries
    pub connected_secondaries: Vec<ClusterNode>,
}

/// Common replication trait
#[async_trait::async_trait]
pub trait ReplicationServiceTrait {
    /// Configure replication
    async fn configure(&self, config: BaseReplicationConfig) -> Result<(), ReplicationError>;

    /// Start replication
    async fn start(&self) -> Result<(), ReplicationError>;

    /// Stop replication
    async fn stop(&self) -> Result<(), ReplicationError>;

    /// Get replication status
    async fn status(&self) -> ReplicationStatus;
}