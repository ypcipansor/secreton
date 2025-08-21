use openraft::{Raft, RaftNetwork, RaftStorage, Config, NodeId, AppData, AppDataResponse, LogId, StorageError, RaftTypeConfig};
use serde::{Serialize, Deserialize};
use async_trait::async_trait;
use axum::{extract::{State, Json}, response::IntoResponse};
use std::sync::{Arc, Mutex};
use openraft::Entry;
use crate::core::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: NodeId,
    pub address: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClusterState {
    pub nodes: Vec<ClusterNode>,
    pub leader_id: Option<NodeId>,
}

// Dummy data & response untuk raft
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum VaultRaftCmd {
    PutSecret { path: String, data: Vec<u8> },
    DeleteSecret { path: String },
    PutPolicy { name: String, data: Vec<u8> },
    DeletePolicy { name: String },
    // Tambah perintah lain sesuai kebutuhan
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultRaftData(pub VaultRaftCmd);
impl AppData for VaultRaftData {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VaultRaftResponse(pub Vec<u8>);
impl AppDataResponse for VaultRaftResponse {}

pub struct VaultRaftNetwork;
#[async_trait]
impl RaftNetwork<VaultRaftTypeConfig> for VaultRaftNetwork {
    async fn send_append_entries(&self, _rpc: openraft::raft::AppendEntriesRequest<VaultRaftTypeConfig>) -> Result<openraft::raft::AppendEntriesResponse<VaultRaftTypeConfig>, openraft::error::RPCError<VaultRaftTypeConfig>> {
        todo!()
    }
    async fn send_install_snapshot(&self, _rpc: openraft::raft::InstallSnapshotRequest<VaultRaftTypeConfig>) -> Result<openraft::raft::InstallSnapshotResponse<VaultRaftTypeConfig>, openraft::error::RPCError<VaultRaftTypeConfig>> {
        todo!()
    }
    async fn send_vote(&self, _rpc: openraft::raft::VoteRequest<VaultRaftTypeConfig>) -> Result<openraft::raft::VoteResponse<VaultRaftTypeConfig>, openraft::error::RPCError<VaultRaftTypeConfig>> {
        todo!()
    }
}

pub struct VaultRaftStorage {
    pub logs: Arc<Mutex<Vec<Entry<VaultRaftTypeConfig>>>>,
    pub app_state: Option<Arc<AppState>>, // Untuk akses storage utama
}

impl Default for VaultRaftStorage {
    fn default() -> Self {
        Self { logs: Arc::new(Mutex::new(vec![])), app_state: None }
    }
}

#[async_trait]
impl RaftStorage<VaultRaftTypeConfig> for VaultRaftStorage {
    type SnapshotData = Vec<u8>;
    async fn get_membership_config(&self) -> Result<openraft::storage::MembershipConfig, StorageError<VaultRaftTypeConfig>> { todo!() }
    async fn get_log_state(&self) -> Result<openraft::storage::LogState<VaultRaftTypeConfig>, StorageError<VaultRaftTypeConfig>> { todo!() }
    async fn save_hard_state(&self, _hs: &openraft::storage::HardState) -> Result<(), StorageError<VaultRaftTypeConfig>> { Ok(()) }
    async fn get_hard_state(&self) -> Result<Option<openraft::storage::HardState>, StorageError<VaultRaftTypeConfig>> { Ok(None) }
    async fn get_log_entries(&self, start: u64, stop: u64) -> Result<Vec<Entry<VaultRaftTypeConfig>>, StorageError<VaultRaftTypeConfig>> {
        let logs = self.logs.lock().unwrap();
        Ok(logs.iter().filter(|e| e.log_id.index >= start && e.log_id.index < stop).cloned().collect())
    }
    async fn append_entry_to_log(&self, entry: &Entry<VaultRaftTypeConfig>) -> Result<(), StorageError<VaultRaftTypeConfig>> {
        let mut logs = self.logs.lock().unwrap();
        logs.push(entry.clone());
        Ok(())
    }
    async fn replicate_to_log(&self, entries: &[Entry<VaultRaftTypeConfig>]) -> Result<(), StorageError<VaultRaftTypeConfig>> {
        let mut logs = self.logs.lock().unwrap();
        logs.extend_from_slice(entries);
        Ok(())
    }
    async fn apply_entry_to_state_machine(&self, _index: &LogId<VaultRaftTypeConfig>, data: &VaultRaftData) -> Result<VaultRaftResponse, StorageError<VaultRaftTypeConfig>> {
        match &data.0 {
            VaultRaftCmd::PutSecret { path, data } => {
                println!("[RAFT] Commit PutSecret: {} ({} bytes)", path, data.len());
                if let Some(app_state) = &self.app_state {
                    // Dummy: parse data dan commit ke storage utama
                    let payload: serde_json::Value = serde_json::from_slice(data).unwrap_or(serde_json::json!({}));
                    let ns = "default"; // TODO: namespace dari path
                    let _ = app_state.storage.create_secret(path, ns, &payload).await;
                }
            }
            VaultRaftCmd::DeleteSecret { path } => {
                println!("[RAFT] Commit DeleteSecret: {}", path);
                if let Some(app_state) = &self.app_state {
                    let ns = "default"; // TODO: namespace dari path
                    let _ = app_state.storage.delete_secret(path, ns).await;
                }
            }
            VaultRaftCmd::PutPolicy { name, data } => {
                println!("[RAFT] Commit PutPolicy: {} ({} bytes)", name, data.len());
            }
            VaultRaftCmd::DeletePolicy { name } => {
                println!("[RAFT] Commit DeletePolicy: {}", name);
            }
        }
        Ok(VaultRaftResponse(vec![]))
    }
    async fn do_log_compaction(&self) -> Result<openraft::storage::Snapshot<VaultRaftTypeConfig, Self::SnapshotData>, StorageError<VaultRaftTypeConfig>> { todo!() }
    async fn begin_receiving_snapshot(&self) -> Result<Box<Self::SnapshotData>, StorageError<VaultRaftTypeConfig>> { todo!() }
    async fn install_snapshot(&self, _meta: &openraft::storage::SnapshotMeta<VaultRaftTypeConfig>, _snapshot: Box<Self::SnapshotData>) -> Result<(), StorageError<VaultRaftTypeConfig>> { todo!() }
}

pub struct VaultRaftTypeConfig;
impl RaftTypeConfig for VaultRaftTypeConfig {
    type D = VaultRaftData;
    type R = VaultRaftResponse;
    type NodeId = NodeId;
    type Node = ClusterNode;
}

#[derive(Deserialize)]
pub struct JoinRequest {
    pub node_id: u64,
    pub address: String,
}

#[derive(Serialize)]
pub struct JoinResponse {
    pub status: String,
    pub message: String,
}

pub async fn cluster_join(State(state): State<Arc<AppState>>, Json(payload): Json<JoinRequest>) -> impl IntoResponse {
    // Dummy: tambahkan node ke cluster_state
    let mut cluster = state.cluster_status.lock().unwrap();
    let node = ClusterNode { id: payload.node_id, address: payload.address.clone() };
    if !cluster.peers.iter().any(|n| n == &payload.address) {
        cluster.peers.push(payload.address.clone());
    }
    JoinResponse {
        status: "success".to_string(),
        message: format!("Node {} joined", node.id),
    }
}

#[derive(Serialize)]
pub struct ClusterStatusResponse {
    pub leader_id: Option<u64>,
    pub peers: Vec<String>,
}

pub async fn cluster_status(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cluster = state.cluster_status.lock().unwrap();
    ClusterStatusResponse {
        leader_id: cluster.leader_id.as_ref().and_then(|id| id.parse().ok()),
        peers: cluster.peers.clone(),
    }
}

#[derive(Deserialize)]
pub struct PromoteRequest {
    pub leader_id: u64,
}

#[derive(Serialize)]
pub struct PromoteResponse {
    pub status: String,
    pub leader_id: u64,
}

pub async fn cluster_promote(State(state): State<Arc<AppState>>, Json(payload): Json<PromoteRequest>) -> impl IntoResponse {
    let mut cluster = state.cluster_status.lock().unwrap();
    cluster.leader_id = Some(payload.leader_id.to_string());
    PromoteResponse {
        status: "success".to_string(),
        leader_id: payload.leader_id,
    }
}

#[derive(Deserialize)]
pub struct HeartbeatRequest {
    pub node_id: u64,
}

#[derive(Serialize)]
pub struct HeartbeatResponse {
    pub status: String,
    pub node_id: u64,
}

pub async fn cluster_heartbeat(State(state): State<Arc<AppState>>, Json(payload): Json<HeartbeatRequest>) -> impl IntoResponse {
    let mut cluster = state.cluster_status.lock().unwrap();
    if !cluster.peers.iter().any(|n| n == &payload.node_id.to_string()) {
        cluster.peers.push(payload.node_id.to_string());
    }
    cluster.last_heartbeat = Some(chrono::Utc::now());
    HeartbeatResponse {
        status: "ok".to_string(),
        node_id: payload.node_id,
    }
} 