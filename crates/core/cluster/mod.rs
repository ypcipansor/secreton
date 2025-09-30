//! Cluster module for Secreton
//!
//! Provides clustering, high availability, and distributed consensus
//! functionality using the Raft consensus algorithm.

pub mod discovery;
pub mod loadbalancer;
pub mod raft;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// Cluster-level errors
#[derive(Error, Debug)]
pub enum ClusterError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),

    #[error("Election timeout")]
    ElectionTimeout,

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Leader not available")]
    LeaderNotAvailable,

    #[error("Consensus error: {0}")]
    ConsensusError(String),
}

/// Main cluster manager that coordinates all clustering components
pub struct ClusterManager {
    node_id: String,
    raft_cluster: raft::RaftCluster,
    discovery: discovery::ClusterDiscovery,
    load_balancer: loadbalancer::LoadBalancer,
    is_running: bool,
}

/// Configuration for the entire cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfig {
    pub node_id: String,
    pub raft_config: raft::RaftConfig,
    pub discovery_config: discovery::DiscoveryConfig,
    pub load_balancer_config: loadbalancer::LoadBalancerConfig,
    pub initial_peers: Vec<String>,
}

impl ClusterManager {
    pub async fn new(config: ClusterConfig) -> Result<Self, ClusterError> {
        // Initialize Raft cluster
        let raft_cluster = raft::RaftCluster::new(
            config.node_id.clone(),
            config.initial_peers.clone(),
            config.raft_config.clone(),
        );

        // Initialize discovery service
        let discovery = discovery::ClusterDiscovery::new(
            config.node_id.clone(),
            config.discovery_config.clone(),
            config.initial_peers.clone(),
        ).await?;

        // Initialize load balancer
        let load_balancer = loadbalancer::LoadBalancer::new(config.load_balancer_config.clone());

        Ok(Self {
            node_id: config.node_id,
            raft_cluster,
            discovery,
            load_balancer,
            is_running: false,
        })
    }

    pub async fn start(&mut self) -> Result<(), ClusterError> {
        if self.is_running {
            return Err(ClusterError::InvalidConfiguration("Cluster already running".to_string()));
        }

        info!("Starting cluster manager for node: {}", self.node_id);

        // Bootstrap Raft cluster
        self.raft_cluster.bootstrap_cluster().await?;

        // Start discovery service
        self.discovery.start().await?;

        // Start load balancer
        self.load_balancer.start().await?;

        // Start Raft cluster
        self.raft_cluster.start().await?;

        self.is_running = true;
        info!("Cluster manager started successfully");

        Ok(())
    }

    pub async fn stop(&mut self) -> Result<(), ClusterError> {
        if !self.is_running {
            return Ok(());
        }

        info!("Stopping cluster manager for node: {}", self.node_id);

        // Stop discovery service
        self.discovery.stop().await?;

        // Stop load balancer
        self.load_balancer.stop().await?;

        self.is_running = false;
        info!("Cluster manager stopped successfully");

        Ok(())
    }

    pub async fn is_leader(&self) -> bool {
        self.raft_cluster.is_leader().await
    }

    pub fn get_node_id(&self) -> &str {
        &self.node_id
    }

    pub async fn get_cluster_state(&self) -> HashMap<String, serde_json::Value> {
        let mut state = HashMap::new();

        state.insert("node_id".to_string(), json!(self.node_id));
        state.insert("is_leader".to_string(), json!(self.is_leader().await));
        state.insert("raft_state".to_string(), json!(self.raft_cluster.get_state().await));
        state.insert("healthy_nodes".to_string(), json!(self.load_balancer.get_healthy_nodes().await.len()));

        state
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
            raft_config: raft::RaftConfig::default(),
            discovery_config: discovery::DiscoveryConfig::default(),
            load_balancer_config: loadbalancer::LoadBalancerConfig::default(),
            initial_peers: vec!["node-1".to_string(), "node-2".to_string(), "node-3".to_string()],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cluster_manager_creation() {
        let config = ClusterConfig::default();
        let manager = ClusterManager::new(config).await;

        assert!(manager.is_ok());
    }

    #[tokio::test]
    async fn test_cluster_config_default() {
        let config = ClusterConfig::default();

        assert_eq!(config.node_id, "node-1");
        assert_eq!(config.initial_peers.len(), 3);
    }
}
