use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::time::{interval, timeout};
use thiserror::Error;
use tracing::{debug, error, info, warn};

/// Errors that can occur in the Raft cluster
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
}

/// Raft cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    pub election_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub max_log_entries: usize,
    pub replication_factor: usize,
}

/// Represents the state of a Raft node
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RaftNodeState {
    Follower,
    Candidate,
    Leader,
}

/// Information about a cluster node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub address: String,
    pub port: u16,
    pub last_seen: Instant,
    pub state: RaftNodeState,
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub term: u64,
    pub index: u64,
    pub command: String,
    pub data: Vec<u8>,
}

/// Raft cluster state
#[derive(Debug)]
pub struct RaftCluster {
    node_id: String,
    peers: Vec<String>,
    config: RaftConfig,
    current_term: Arc<RwLock<u64>>,
    voted_for: Arc<RwLock<Option<String>>>,
    log: Arc<RwLock<Vec<LogEntry>>>,
    commit_index: Arc<RwLock<u64>>,
    last_applied: Arc<RwLock<u64>>,
    next_index: Arc<RwLock<HashMap<String, u64>>>,
    match_index: Arc<RwLock<HashMap<String, u64>>>,
    state: Arc<RwLock<RaftNodeState>>,
    leader_id: Arc<RwLock<Option<String>>>,
    election_timer: Arc<Mutex<Option<tokio::time::Interval>>>,
    heartbeat_timer: Arc<Mutex<Option<tokio::time::Interval>>>,
}

/// Trait for Raft log storage
#[async_trait]
pub trait RaftLogStore: Send + Sync {
    async fn append_entries(&self, entries: Vec<LogEntry>) -> Result<(), ClusterError>;
    async fn get_log_entries(&self, start_index: u64, end_index: u64) -> Result<Vec<LogEntry>, ClusterError>;
    async fn get_last_log_entry(&self) -> Result<Option<LogEntry>, ClusterError>;
    async fn truncate_log(&self, index: u64) -> Result<(), ClusterError>;
}

/// Trait for Raft state machine
#[async_trait]
pub trait RaftStateMachine: Send + Sync {
    async fn apply(&self, command: String, data: Vec<u8>) -> Result<(), ClusterError>;
    async fn snapshot(&self) -> Result<Vec<u8>, ClusterError>;
    async fn restore(&self, snapshot: Vec<u8>) -> Result<(), ClusterError>;
}

impl RaftCluster {
    pub fn new(node_id: String, peers: Vec<String>, config: RaftConfig) -> Self {
        Self {
            node_id,
            peers,
            config,
            current_term: Arc::new(RwLock::new(0)),
            voted_for: Arc::new(RwLock::new(None)),
            log: Arc::new(RwLock::new(Vec::new())),
            commit_index: Arc::new(RwLock::new(0)),
            last_applied: Arc::new(RwLock::new(0)),
            next_index: Arc::new(RwLock::new(HashMap::new())),
            match_index: Arc::new(RwLock::new(HashMap::new())),
            state: Arc::new(RwLock::new(RaftNodeState::Follower)),
            leader_id: Arc::new(RwLock::new(None)),
            election_timer: Arc::new(Mutex::new(None)),
            heartbeat_timer: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn bootstrap_cluster(&self) -> Result<(), ClusterError> {
        info!("Bootstrapping Raft cluster for node: {}", self.node_id);

        // Initialize Raft cluster with initial configuration
        *self.current_term.write().await = 0;
        *self.voted_for.write().await = None;
        *self.leader_id.write().await = None;

        // Initialize peer tracking
        let mut next_index = self.next_index.write().await;
        let mut match_index = self.match_index.write().await;

        for peer in &self.peers {
            next_index.insert(peer.clone(), 1);
            match_index.insert(peer.clone(), 0);
        }

        // Start as follower
        self.become_follower().await?;

        info!("Raft cluster bootstrapped successfully");
        Ok(())
    }

    pub async fn start(&self) -> Result<(), ClusterError> {
        info!("Starting Raft cluster node: {}", self.node_id);

        // Start election timer
        self.start_election_timer().await;

        // Start heartbeat timer if leader
        self.start_heartbeat_timer().await;

        // Start background tasks
        self.start_background_tasks().await?;

        Ok(())
    }

    async fn start_election_timer(&self) {
        let election_timeout = self.config.election_timeout;
        let node_id = self.node_id.clone();
        let election_timer = Arc::clone(&self.election_timer);

        tokio::spawn(async move {
            let mut timer = interval(election_timeout);
            timer.tick().await; // First tick immediately

            loop {
                timer.tick().await;

                // Check if we should start an election
                // This would be implemented based on the actual election logic
                debug!("Election timer ticked for node: {}", node_id);
            }
        });
    }

    async fn start_heartbeat_timer(&self) {
        let heartbeat_interval = self.config.heartbeat_interval;
        let node_id = self.node_id.clone();
        let heartbeat_timer = Arc::clone(&self.heartbeat_timer);

        tokio::spawn(async move {
            let mut timer = interval(heartbeat_interval);

            loop {
                timer.tick().await;

                // Send heartbeats to followers if we're the leader
                debug!("Heartbeat timer ticked for node: {}", node_id);
            }
        });
    }

    async fn start_background_tasks(&self) -> Result<(), ClusterError> {
        // Start log replication task
        self.start_log_replication().await?;

        // Start log compaction task
        self.start_log_compaction().await?;

        Ok(())
    }

    async fn start_log_replication(&self) -> Result<(), ClusterError> {
        // Implementation for log replication to followers
        Ok(())
    }

    async fn start_log_compaction(&self) -> Result<(), ClusterError> {
        // Implementation for log compaction and snapshotting
        Ok(())
    }

    async fn become_follower(&self) -> Result<(), ClusterError> {
        *self.state.write().await = RaftNodeState::Follower;
        *self.leader_id.write().await = None;

        info!("Node {} became follower", self.node_id);
        Ok(())
    }

    async fn become_candidate(&self) -> Result<(), ClusterError> {
        *self.state.write().await = RaftNodeState::Candidate;

        // Increment current term
        let mut term = self.current_term.write().await;
        *term += 1;
        let current_term = *term;

        // Vote for ourselves
        *self.voted_for.write().await = Some(self.node_id.clone());

        info!("Node {} became candidate for term {}", self.node_id, current_term);
        Ok(())
    }

    async fn become_leader(&self) -> Result<(), ClusterError> {
        *self.state.write().await = RaftNodeState::Leader;

        // Initialize leader state
        let mut next_index = self.next_index.write().await;
        let mut match_index = self.match_index.write().await;

        if let Some(last_log_entry) = self.get_last_log_entry().await? {
            let next_idx = last_log_entry.index + 1;
            for peer in &self.peers {
                next_index.insert(peer.clone(), next_idx);
                match_index.insert(peer.clone(), 0);
            }
        }

        info!("Node {} became leader", self.node_id);
        Ok(())
    }

    async fn get_last_log_entry(&self) -> Result<Option<LogEntry>, ClusterError> {
        let log = self.log.read().await;
        Ok(log.last().cloned())
    }

    pub async fn get_state(&self) -> RaftNodeState {
        self.state.read().await.clone()
    }

    pub async fn get_current_term(&self) -> u64 {
        *self.current_term.read().await
    }

    pub async fn is_leader(&self) -> bool {
        matches!(self.get_state().await, RaftNodeState::Leader)
    }

    pub fn get_node_id(&self) -> &str {
        &self.node_id
    }

    pub fn get_peers(&self) -> &[String] {
        &self.peers
    }
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            election_timeout: Duration::from_millis(1000),
            heartbeat_interval: Duration::from_millis(500),
            max_log_entries: 10000,
            replication_factor: 3,
        }
    }
}
