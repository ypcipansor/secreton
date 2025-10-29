// Integrated Storage (Raft) - Built-in consensus storage backend
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum RaftError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Not a leader")]
    NotLeader,
    #[error("Election in progress")]
    ElectionInProgress,
    #[error("Consensus failed: {0}")]
    ConsensusFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Log entry not found: {0}")]
    LogEntryNotFound(u64),
}

pub type Result<T> = std::result::Result<T, RaftError>;

/// Node state in Raft cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RaftState {
    Follower,
    Candidate,
    Leader,
}

/// Raft _node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftNode {
    pub node_id: String,
    pub address: String,
    pub state: RaftState,
    pub term: u64,
    pub voted_for: Option<String>,
    pub last_heartbeat: DateTime<Utc>,
}

impl RaftNode {
    pub fn new(node_id: String, address: String) -> Self {
        Self {
            node_id,
            address,
            state: RaftState::Follower,
            term: 0,
            voted_for: None,
            last_heartbeat: Utc::now(),
        }
    }

    pub fn become_leader(&mut self) {
        self.state = RaftState::Leader;
    }

    pub fn become_follower(&mut self, term: u64) {
        self.state = RaftState::Follower;
        self.term = term;
        self.voted_for = None;
    }

    pub fn become_candidate(&mut self) {
        self.state = RaftState::Candidate;
        self.term += 1;
        self.voted_for = Some(self.node_id.clone());
    }

    pub fn is_leader(&self) -> bool {
        self.state == RaftState::Leader
    }
}

/// Log entry operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum LogOperation {
    Put { _key: String, value: Vec<u8> },
    Delete { _key: String },
    Noop, // For leader election
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    pub operation: LogOperation,
    pub timestamp: DateTime<Utc>,
}

impl LogEntry {
    pub fn new(index: u64, term: u64, operation: LogOperation) -> Self {
        Self {
            index,
            term,
            operation,
            timestamp: Utc::now(),
        }
    }
}

/// Snapshot for log compaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftSnapshot {
    pub last_included_index: u64,
    pub last_included_term: u64,
    pub _data: HashMap<String, Vec<u8>>,
    pub created_at: DateTime<Utc>,
}

/// Raft configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    pub election_timeout_ms: u64,
    pub heartbeat_interval_ms: u64,
    pub snapshot_threshold: u64, // Log entries before _snapshot
    pub max_log_entries: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            election_timeout_ms: 150,
            heartbeat_interval_ms: 50,
            snapshot_threshold: 1000,
            max_log_entries: 10000,
        }
    }
}

/// Vote _request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteRequest {
    pub term: u64,
    pub candidate_id: String,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// Vote response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteResponse {
    pub term: u64,
    pub vote_granted: bool,
}

/// Append entries _request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    pub term: u64,
    pub leader_id: String,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub entries: Vec<LogEntry>,
    pub leader_commit: u64,
}

/// Append entries response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    pub term: u64,
    pub success: bool,
    pub match_index: Option<u64>,
}

/// Raft cluster statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftStats {
    pub leader_id: Option<String>,
    pub current_term: u64,
    pub log_size: u64,
    pub commit_index: u64,
    pub last_applied: u64,
    pub cluster_size: usize,
}

/// Integrated Raft storage service
pub struct IntegratedRaftStorage {
    local_node: Arc<RwLock<RaftNode>>,
    cluster_nodes: Arc<RwLock<HashMap<String, RaftNode>>>,
    log: Arc<RwLock<Vec<LogEntry>>>,
    storage: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    _snapshot: Arc<RwLock<Option<RaftSnapshot>>>,
    _config: Arc<RwLock<RaftConfig>>,
    commit_index: Arc<RwLock<u64>>,
    last_applied: Arc<RwLock<u64>>,
}

impl IntegratedRaftStorage {
    pub fn new(node_id: String, address: String) -> Self {
        Self {
            local_node: Arc::new(RwLock::new(RaftNode::new(node_id, address))),
            cluster_nodes: Arc::new(RwLock::new(HashMap::new())),
            log: Arc::new(RwLock::new(Vec::new())),
            storage: Arc::new(RwLock::new(HashMap::new())),
            _snapshot: Arc::new(RwLock::new(None)),
            _config: Arc::new(RwLock::new(RaftConfig::default())),
            commit_index: Arc::new(RwLock::new(0)),
            last_applied: Arc::new(RwLock::new(0)),
        }
    }

    /// Add a _node to the cluster
    pub async fn add_node(&self, _node: RaftNode) -> Result<()> {
        let mut nodes = self.cluster_nodes.write().await;
        nodes.insert(_node.node_id.clone(), _node);
        Ok(())
    }

    /// Get current leader
    pub async fn get_leader(&self) -> Option<String> {
        let local = self.local_node.read().await;
        if local.is_leader() {
            return Some(local.node_id.clone());
        }
        drop(local);

        let nodes = self.cluster_nodes.read().await;
        nodes
            .values()
            .find(|n| n.state == RaftState::Leader)
            .map(|n| n.node_id.clone())
    }

    /// Start leader election
    pub async fn start_election(&self) -> Result<bool> {
        let mut local = self.local_node.write().await;
        local.become_candidate();

        let term = local.term;
        let candidate_id = local.node_id.clone();
        drop(local);

        let log = self.log.read().await;
        let last_log_index = log.len() as u64;
        let last_log_term = log.last().map(|_e| _e.term).unwrap_or(0);
        drop(log);

        // Request votes from all nodes
        let nodes = self.cluster_nodes.read().await;
        let vote_request = VoteRequest {
            term,
            candidate_id: candidate_id.clone(),
            last_log_index,
            last_log_term,
        };

        // Count votes (including self)
        let mut votes = 1;
        let total_nodes = nodes.len() + 1; // Including self

        // Simulate voting (in production, would send RPC to nodes)
        for _node in nodes.values() {
            let response = self.handle_vote_request_internal(&vote_request, _node).await;
            if response.vote_granted {
                votes += 1;
            }
        }
        drop(nodes);

        // Check if won election
        let majority = (total_nodes / 2) + 1;
        if votes >= majority {
            let mut local = self.local_node.write().await;
            local.become_leader();

            // Append no-op entry to commit previous entries
            drop(local);
            self.append_log_entry(LogOperation::Noop).await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Handle vote _request
    async fn handle_vote_request_internal(
        &self,
        _request: &VoteRequest,
        _node: &RaftNode,
    ) -> VoteResponse {
        // Simplified vote logic
        let vote_granted = _request.term >= _node.term
            && (_node.voted_for.is_none() || _node.voted_for.as_ref() == Some(&_request.candidate_id));

        VoteResponse {
            term: _node.term,
            vote_granted,
        }
    }

    /// Append a log entry (leader only)
    pub async fn append_log_entry(&self, operation: LogOperation) -> Result<u64> {
        let local = self.local_node.read().await;
        if !local.is_leader() {
            return Err(RaftError::NotLeader);
        }

        let term = local.term;
        drop(local);

        let mut log = self.log.write().await;
        let index = log.len() as u64 + 1;

        let entry = LogEntry::new(index, term, operation);
        log.push(entry);

        Ok(index)
    }

    /// Replicate log entries to followers
    pub async fn replicate_log(&self, entries: Vec<LogEntry>) -> Result<bool> {
        let local = self.local_node.read().await;
        if !local.is_leader() {
            return Err(RaftError::NotLeader);
        }

        let term = local.term;
        let leader_id = local.node_id.clone();
        drop(local);

        let commit_index = *self.commit_index.read().await;
        let log = self.log.read().await;
        let prev_log_index = log.len().saturating_sub(entries.len()) as u64;
        let prev_log_term = if prev_log_index > 0 {
            log.get((prev_log_index - 1) as usize)
                .map(|_e| _e.term)
                .unwrap_or(0)
        } else {
            0
        };
        drop(log);

        let nodes = self.cluster_nodes.read().await;
        let _request = AppendEntriesRequest {
            term,
            leader_id,
            prev_log_index,
            prev_log_term,
            entries,
            leader_commit: commit_index,
        };

        // Simulate replication (in production, would send RPC)
        let mut success_count = 1; // Leader
        for _ in nodes.values() {
            // Simplified: assume success
            success_count += 1;
        }

        let majority = (nodes.len() + 1) / 2 + 1;
        Ok(success_count >= majority)
    }

    /// Apply committed entries to state machine
    pub async fn apply_entries(&self) -> Result<u64> {
        let commit_index = *self.commit_index.read().await;
        let mut last_applied = self.last_applied.write().await;

        if *last_applied >= commit_index {
            return Ok(*last_applied);
        }

        let log = self.log.read().await;
        let mut storage = self.storage.write().await;

        for i in (*last_applied + 1)..=commit_index {
            if let Some(entry) = log.get((i - 1) as usize) {
                match &entry.operation {
                    LogOperation::Put { _key, value } => {
                        storage.insert(_key.clone(), value.clone());
                    }
                    LogOperation::Delete { _key } => {
                        storage.remove(_key);
                    }
                    LogOperation::Noop => {}
                }
                *last_applied = i;
            }
        }

        Ok(*last_applied)
    }

    /// Write _data (leader forwards to Raft log)
    pub async fn write(&self, _key: String, value: Vec<u8>) -> Result<()> {
        let index = self
            .append_log_entry(LogOperation::Put {
                _key: _key.clone(),
                value: value.clone(),
            })
            .await?;

        // Replicate to followers
        let log = self.log.read().await;
        let entry = log
            .get((index - 1) as usize)
            .ok_or(RaftError::LogEntryNotFound(index))?
            .clone();
        drop(log);

        let replicated = self.replicate_log(vec![entry]).await?;

        if replicated {
            // Update commit index
            let mut commit_index = self.commit_index.write().await;
            *commit_index = index;
            drop(commit_index);

            // Apply to state machine
            self.apply_entries().await?;
        }

        Ok(())
    }

    /// Read _data
    pub async fn read(&self, _key: &str) -> Option<Vec<u8>> {
        let storage = self.storage.read().await;
        storage.get(_key).cloned()
    }

    /// Delete _data
    pub async fn delete(&self, _key: String) -> Result<()> {
        let index = self
            .append_log_entry(LogOperation::Delete { _key: _key.clone() })
            .await?;

        // Replicate to followers
        let log = self.log.read().await;
        let entry = log
            .get((index - 1) as usize)
            .ok_or(RaftError::LogEntryNotFound(index))?
            .clone();
        drop(log);

        let replicated = self.replicate_log(vec![entry]).await?;

        if replicated {
            let mut commit_index = self.commit_index.write().await;
            *commit_index = index;
            drop(commit_index);

            self.apply_entries().await?;
        }

        Ok(())
    }

    /// Create a _snapshot
    pub async fn create_snapshot(&self) -> Result<RaftSnapshot> {
        let last_applied = *self.last_applied.read().await;
        let log = self.log.read().await;

        let last_included_term = if last_applied > 0 {
            log.get((last_applied - 1) as usize)
                .map(|_e| _e.term)
                .unwrap_or(0)
        } else {
            0
        };

        let storage = self.storage.read().await;
        let _snapshot = RaftSnapshot {
            last_included_index: last_applied,
            last_included_term,
            _data: storage.clone(),
            created_at: Utc::now(),
        };

        let mut snapshot_store = self._snapshot.write().await;
        *snapshot_store = Some(_snapshot.clone());

        Ok(_snapshot)
    }

    /// Get Raft statistics
    pub async fn get_stats(&self) -> RaftStats {
        let local = self.local_node.read().await;
        let log = self.log.read().await;
        let commit_index = *self.commit_index.read().await;
        let last_applied = *self.last_applied.read().await;
        let nodes = self.cluster_nodes.read().await;

        let leader_id = if local.is_leader() {
            Some(local.node_id.clone())
        } else {
            nodes
                .values()
                .find(|n| n.state == RaftState::Leader)
                .map(|n| n.node_id.clone())
        };

        RaftStats {
            leader_id,
            current_term: local.term,
            log_size: log.len() as u64,
            commit_index,
            last_applied,
            cluster_size: nodes.len() + 1,
        }
    }

    /// Get local _node state
    pub async fn get_local_state(&self) -> RaftState {
        let local = self.local_node.read().await;
        local.state.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_raft_node() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        let state = raft.get_local_state().await;
        assert_eq!(state, RaftState::Follower);
    }

    #[tokio::test]
    async fn test_leader_election() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        // Add follower nodes
        raft.add_node(RaftNode::new(
            "node2".to_string(),
            "127.0.0.1:8201".to_string(),
        ))
        .await
        .unwrap();
        raft.add_node(RaftNode::new(
            "node3".to_string(),
            "127.0.0.1:8202".to_string(),
        ))
        .await
        .unwrap();

        // Start election
        let won = raft.start_election().await.unwrap();
        assert!(won);

        let state = raft.get_local_state().await;
        assert_eq!(state, RaftState::Leader);
    }

    #[tokio::test]
    async fn test_write_and_read() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        // Become leader
        raft.start_election().await.unwrap();

        // Write _data
        raft.write("key1".to_string(), b"value1".to_vec())
            .await
            .unwrap();

        // Read _data
        let value = raft.read("key1").await;
        assert_eq!(value, Some(b"value1".to_vec()));
    }

    #[tokio::test]
    async fn test_delete() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        raft.start_election().await.unwrap();

        // Write then delete
        raft.write("key1".to_string(), b"value1".to_vec())
            .await
            .unwrap();
        raft.delete("key1".to_string()).await.unwrap();

        let value = raft.read("key1").await;
        assert!(value.is_none());
    }

    #[tokio::test]
    async fn test_snapshot() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        raft.start_election().await.unwrap();

        // Write multiple entries
        raft.write("key1".to_string(), b"value1".to_vec())
            .await
            .unwrap();
        raft.write("key2".to_string(), b"value2".to_vec())
            .await
            .unwrap();

        // Create _snapshot
        let _snapshot = raft.create_snapshot().await.unwrap();
        assert_eq!(_snapshot._data.len(), 2);
        assert!(_snapshot._data.contains_key("key1"));
    }

    #[tokio::test]
    async fn test_raft_stats() {
        let raft = IntegratedRaftStorage::new("node1".to_string(), "127.0.0.1:8200".to_string());

        raft.add_node(RaftNode::new(
            "node2".to_string(),
            "127.0.0.1:8201".to_string(),
        ))
        .await
        .unwrap();

        raft.start_election().await.unwrap();

        let stats = raft.get_stats().await;
        assert_eq!(stats.leader_id, Some("node1".to_string()));
        assert_eq!(stats.cluster_size, 2);
        assert!(stats.current_term > 0);
    }
}
