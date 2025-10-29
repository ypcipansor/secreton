//! Raft Integrated Storage Backend
//!
//! This module provides a Raft consensus-based storage backend for Secreton,
//! compatible with HashiCorp Vault's integrated storage approach.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use tokio::sync::Mutex;
use tracing::{debug, error, info};
use uuid::Uuid;

use crate::{
    HealthStatus, QueryParams, StorageBackend, StorageError, StorageResult, StorageStats,
    StorageTransaction, VaultEntry,
};

/// Raft node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Node ID
    pub node_id: String,

    /// Raft data directory
    pub data_dir: PathBuf,

    /// Bind address for Raft communication
    pub bind_addr: String,

    /// Advertised address for Raft communication
    pub advertise_addr: String,

    /// Cluster peers for initial bootstrap
    pub peers: Vec<String>,

    /// Enable automatic snapshots
    pub snapshot_enabled: bool,

    /// Snapshot interval
    pub snapshot_interval_secs: u64,

    /// Log retention count
    pub log_retention_count: u64,

    /// Performance tuning
    pub performance_multiplier: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            node_id: "node-1".to_string(),
            data_dir: PathBuf::from("./raft-data"),
            bind_addr: "127.0.0.1:8201".to_string(),
            advertise_addr: "127.0.0.1:8201".to_string(),
            peers: vec![],
            snapshot_enabled: true,
            snapshot_interval_secs: 120,
            log_retention_count: 10000,
            performance_multiplier: 1,
        }
    }
}

/// Raft command types for consensus operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftCommand {
    /// Store a vault entry
    Store { entry: VaultEntry },

    /// Update an existing entry
    Update { entry: VaultEntry },

    /// Delete an entry by path
    Delete { path: String },

    /// Batch operations
    Batch { operations: Vec<RaftCommand> },
}

/// Raft state machine response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftResponse {
    Success,
    Error { message: String },
    Entry { entry: Box<Option<VaultEntry>> },
    Entries { entries: Vec<VaultEntry> },
    Count { count: u64 },
    Boolean { value: bool },
}

/// Raft storage state machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftStateMachine {
    /// In-memory storage for fast access
    data: HashMap<String, VaultEntry>,

    /// Index by UUID for O(1) lookups
    id_index: HashMap<Uuid, String>,

    /// Last applied index
    last_applied_index: u64,

    /// Storage statistics
    stats: StorageStats,
}

impl Default for RaftStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl RaftStateMachine {
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            id_index: HashMap::new(),
            last_applied_index: 0,
            stats: StorageStats {
                total_entries: 0,
                total_size_bytes: 0,
                average_entry_size: 0.0,
                entries_by_security_level: HashMap::new(),
                entries_created_today: 0,
                entries_updated_today: 0,
                expired_entries: 0,
            },
        }
    }

    /// Apply a Raft command to the state machine
    pub fn apply_command(&mut self, command: RaftCommand) -> RaftResponse {
        match command {
            RaftCommand::Store { entry } => {
                let path = entry.path.clone();
                let id = entry.id;

                self.data.insert(path.clone(), entry);
                self.id_index.insert(id, path);
                self.update_stats();

                RaftResponse::Success
            }

            RaftCommand::Update { entry } => {
                let path = entry.path.clone();

                match self.data.entry(path) {
                    std::collections::hash_map::Entry::Occupied(mut e) => {
                        e.insert(entry);
                        self.update_stats();
                        RaftResponse::Success
                    }
                    std::collections::hash_map::Entry::Vacant(_) => RaftResponse::Error {
                        message: "Entry not found".to_string(),
                    },
                }
            }

            RaftCommand::Delete { path } => {
                if let Some(entry) = self.data.remove(&path) {
                    self.id_index.remove(&entry.id);
                    self.update_stats();
                    RaftResponse::Boolean { value: true }
                } else {
                    RaftResponse::Boolean { value: false }
                }
            }

            RaftCommand::Batch { operations } => {
                let mut _success_count = 0;
                let mut errors = Vec::new();

                for op in operations {
                    match self.apply_command(op) {
                        RaftResponse::Success => _success_count += 1,
                        RaftResponse::Error { message } => errors.push(message),
                        _ => {}
                    }
                }

                if errors.is_empty() {
                    RaftResponse::Success
                } else {
                    RaftResponse::Error {
                        message: format!(
                            "Batch operation had {} errors: {:?}",
                            errors.len(),
                            errors
                        ),
                    }
                }
            }
        }
    }

    /// Update storage statistics
    fn update_stats(&mut self) {
        self.stats.total_entries = self.data.len() as u64;
        self.stats.total_size_bytes = self
            .data
            .values()
            .map(|e| e.encrypted_data.len() as u64)
            .sum();

        if self.stats.total_entries > 0 {
            self.stats.average_entry_size =
                self.stats.total_size_bytes as f64 / self.stats.total_entries as f64;
        }

        // Update entries by security level
        let mut by_level = HashMap::new();
        for entry in self.data.values() {
            *by_level.entry(entry.security_level).or_insert(0) += 1;
        }
        self.stats.entries_by_security_level = by_level;
    }

    /// Get entry by path
    pub fn get_by_path(&self, path: &str) -> Option<VaultEntry> {
        self.data.get(path).cloned()
    }

    /// Get entry by ID
    pub fn get_by_id(&self, id: Uuid) -> Option<VaultEntry> {
        self.id_index
            .get(&id)
            .and_then(|path| self.data.get(path))
            .cloned()
    }

    /// List entries matching query parameters
    pub fn list(&self, params: &QueryParams) -> Vec<VaultEntry> {
        let mut results: Vec<VaultEntry> = self
            .data
            .values()
            .filter(|entry| self.matches_query(entry, params))
            .cloned()
            .collect();

        // Apply sorting
        if let Some(sort_by) = &params.sort_by {
            match sort_by.as_str() {
                "created_at" => results.sort_by(|a, b| a.created_at.cmp(&b.created_at)),
                "updated_at" => results.sort_by(|a, b| a.updated_at.cmp(&b.updated_at)),
                "path" => results.sort_by(|a, b| a.path.cmp(&b.path)),
                _ => {}
            }
        }

        // Apply reverse order if needed
        if params.sort_order.as_deref() == Some("desc") {
            results.reverse();
        }

        // Apply offset and limit
        let start = params.offset.unwrap_or(0) as usize;
        let end = params
            .limit
            .map(|limit| start + limit as usize)
            .unwrap_or(results.len());

        results
            .get(start..end.min(results.len()))
            .unwrap_or(&[])
            .to_vec()
    }

    /// Check if entry matches query parameters
    fn matches_query(&self, entry: &VaultEntry, params: &QueryParams) -> bool {
        // Check expiration
        if !params.include_expired && entry.is_expired() {
            return false;
        }

        // Check path prefix
        if let Some(prefix) = &params.path_prefix {
            if !entry.path.starts_with(prefix) {
                return false;
            }
        }

        // Check security level
        if let Some(min_level) = params.security_level {
            if entry.security_level < min_level {
                return false;
            }
        }

        // Check owner
        if let Some(owner_id) = params.owner_id {
            if entry.owner_id != owner_id {
                return false;
            }
        }

        // Check tags
        if !params.tags.is_empty() && !params.tags.iter().any(|tag| entry.tags.contains(tag)) {
            return false;
        }

        // Check metadata filters
        for (key, value) in &params.metadata_filters {
            if entry.metadata.get(key) != Some(value) {
                return false;
            }
        }

        true
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> StorageStats {
        self.stats.clone()
    }
}

/// Raft integrated storage backend
pub struct RaftStorageBackend {
    /// Raft configuration
    config: RaftConfig,

    /// Raft state machine
    state_machine: Arc<RwLock<RaftStateMachine>>,

    /// Leader status
    is_leader: Arc<RwLock<bool>>,

    /// Node health status
    health_status: Arc<RwLock<HealthStatus>>,

    /// Transaction mutex for serializing writes
    transaction_mutex: Arc<Mutex<()>>,
}

impl RaftStorageBackend {
    /// Create a new Raft storage backend
    pub async fn new(config: RaftConfig) -> StorageResult<Self> {
        // Create data directory if it doesn't exist
        if let Err(e) = tokio::fs::create_dir_all(&config.data_dir).await {
            return Err(StorageError::ConfigurationError {
                message: format!("Failed to create data directory: {}", e),
            });
        }

        let state_machine = Arc::new(RwLock::new(RaftStateMachine::new()));

        let health_status = Arc::new(RwLock::new(HealthStatus {
            is_healthy: true,
            response_time_ms: 0.0,
            connections_active: 1,
            connections_idle: 0,
            last_error: None,
            uptime_seconds: 0,
        }));

        info!(
            "Initializing Raft storage backend with config: {:?}",
            config
        );

        Ok(Self {
            config,
            state_machine,
            is_leader: Arc::new(RwLock::new(false)), // Start as follower
            health_status,
            transaction_mutex: Arc::new(Mutex::new(())),
        })
    }

    /// Initialize the Raft cluster
    pub async fn initialize_cluster(&self) -> StorageResult<()> {
        info!(
            "Initializing Raft cluster for node: {}",
            self.config.node_id
        );

        // In a real implementation, this would:
        // 1. Initialize Raft consensus engine
        // 2. Join existing cluster or bootstrap new one
        // 3. Start heartbeat and election processes
        // 4. Load existing state from disk

        // For now, simulate single-node cluster
        if let Ok(mut is_leader) = self.is_leader.write() {
            *is_leader = true;
        }

        info!("Raft cluster initialized successfully");
        Ok(())
    }

    /// Check if this node is the cluster leader
    pub fn is_leader(&self) -> bool {
        self.is_leader.read().map(|guard| *guard).unwrap_or(false)
    }

    /// Apply command through Raft consensus
    async fn apply_command(&self, command: RaftCommand) -> StorageResult<RaftResponse> {
        // Check if we're the leader
        if !self.is_leader() {
            return Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message: "Not the cluster leader".to_string(),
            });
        }

        // In a real implementation, this would:
        // 1. Submit command to Raft log
        // 2. Wait for consensus from majority of nodes
        // 3. Apply to state machine once committed
        // 4. Return result

        // For now, apply directly to state machine
        let response = {
            let mut state = self
                .state_machine
                .write()
                .map_err(|e| StorageError::BackendError {
                    backend: "raft".to_string(),
                    message: format!("State lock error: {}", e),
                })?;

            state.apply_command(command)
        };

        Ok(response)
    }
}

#[async_trait]
impl StorageBackend for RaftStorageBackend {
    async fn store(&self, entry: &VaultEntry) -> StorageResult<()> {
        debug!("Storing entry: {}", entry.path);

        let command = RaftCommand::Store {
            entry: entry.clone(),
        };

        match self.apply_command(command).await? {
            RaftResponse::Success => Ok(()),
            RaftResponse::Error { message } => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message,
            }),
            _ => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message: "Unexpected response type".to_string(),
            }),
        }
    }

    async fn get_by_id(&self, id: Uuid) -> StorageResult<Option<VaultEntry>> {
        debug!("Getting entry by ID: {}", id);

        let state = self
            .state_machine
            .read()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("State lock error: {}", e),
            })?;

        Ok(state.get_by_id(id))
    }

    async fn get_by_path(&self, path: &str) -> StorageResult<Option<VaultEntry>> {
        debug!("Getting entry by path: {}", path);

        let state = self
            .state_machine
            .read()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("State lock error: {}", e),
            })?;

        Ok(state.get_by_path(path))
    }

    async fn update(&self, entry: &VaultEntry) -> StorageResult<()> {
        debug!("Updating entry: {}", entry.path);

        let command = RaftCommand::Update {
            entry: entry.clone(),
        };

        match self.apply_command(command).await? {
            RaftResponse::Success => Ok(()),
            RaftResponse::Error { message } => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message,
            }),
            _ => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message: "Unexpected response type".to_string(),
            }),
        }
    }

    async fn delete_by_id(&self, id: Uuid) -> StorageResult<bool> {
        debug!("Deleting entry by ID: {}", id);

        // First find the path
        let path = {
            let state = self
                .state_machine
                .read()
                .map_err(|e| StorageError::BackendError {
                    backend: "raft".to_string(),
                    message: format!("State lock error: {}", e),
                })?;

            state.id_index.get(&id).cloned()
        };

        if let Some(path) = path {
            self.delete_by_path(&path).await
        } else {
            Ok(false)
        }
    }

    async fn delete_by_path(&self, path: &str) -> StorageResult<bool> {
        debug!("Deleting entry by path: {}", path);

        let command = RaftCommand::Delete {
            path: path.to_string(),
        };

        match self.apply_command(command).await? {
            RaftResponse::Boolean { value } => Ok(value),
            RaftResponse::Error { message } => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message,
            }),
            _ => Err(StorageError::BackendError {
                backend: "raft".to_string(),
                message: "Unexpected response type".to_string(),
            }),
        }
    }

    async fn list(&self, params: &QueryParams) -> StorageResult<Vec<VaultEntry>> {
        debug!("Listing entries with params: {:?}", params);

        let state = self
            .state_machine
            .read()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("State lock error: {}", e),
            })?;

        Ok(state.list(params))
    }

    async fn count(&self, params: &QueryParams) -> StorageResult<u64> {
        debug!("Counting entries with params: {:?}", params);

        let entries = self.list(params).await?;
        Ok(entries.len() as u64)
    }

    async fn exists(&self, path: &str) -> StorageResult<bool> {
        debug!("Checking existence of path: {}", path);

        let state = self
            .state_machine
            .read()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("State lock error: {}", e),
            })?;

        Ok(state.data.contains_key(path))
    }

    async fn begin_transaction(&self) -> StorageResult<Box<dyn StorageTransaction>> {
        debug!("Beginning Raft transaction");

        Ok(Box::new(RaftTransaction::new(
            Arc::clone(&self.state_machine),
            Arc::clone(&self.transaction_mutex),
        )))
    }

    async fn health_check(&self) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        // Perform basic health checks
        let is_healthy = self.is_leader() && self.state_machine.read().is_ok();

        let response_time = start.elapsed().as_millis() as f64;

        let mut health = self
            .health_status
            .write()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("Health status lock error: {}", e),
            })?;

        health.is_healthy = is_healthy;
        health.response_time_ms = response_time;
        health.connections_active = if is_healthy { 1 } else { 0 };

        if !is_healthy {
            health.last_error = Some("Not cluster leader or state machine unavailable".to_string());
        }

        Ok(health.clone())
    }

    async fn get_stats(&self) -> StorageResult<StorageStats> {
        debug!("Getting storage statistics");

        let state = self
            .state_machine
            .read()
            .map_err(|e| StorageError::BackendError {
                backend: "raft".to_string(),
                message: format!("State lock error: {}", e),
            })?;

        Ok(state.get_stats())
    }

    async fn migrate(&self) -> StorageResult<()> {
        info!("Running Raft storage migrations");

        // In a real implementation, this would handle:
        // 1. Schema migrations for persistence layer
        // 2. Data format migrations
        // 3. Cluster configuration updates

        Ok(())
    }
}

/// Raft transaction implementation
pub struct RaftTransaction {
    state_machine: Arc<RwLock<RaftStateMachine>>,
    transaction_mutex: Arc<Mutex<()>>,
    operations: Vec<RaftCommand>,
    _guard: Option<tokio::sync::MutexGuard<'static, ()>>,
}

impl RaftTransaction {
    pub fn new(
        state_machine: Arc<RwLock<RaftStateMachine>>,
        transaction_mutex: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            state_machine,
            transaction_mutex,
            operations: Vec::new(),
            _guard: None,
        }
    }
}

#[async_trait]
impl StorageTransaction for RaftTransaction {
    async fn store(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        self.operations.push(RaftCommand::Store {
            entry: entry.clone(),
        });
        Ok(())
    }

    async fn update(&mut self, entry: &VaultEntry) -> StorageResult<()> {
        self.operations.push(RaftCommand::Update {
            entry: entry.clone(),
        });
        Ok(())
    }

    async fn delete(&mut self, id: Uuid) -> StorageResult<bool> {
        // Find path by ID first
        let path = {
            let state = self
                .state_machine
                .read()
                .map_err(|e| StorageError::TransactionFailed {
                    message: format!("State lock error: {}", e),
                })?;

            state.id_index.get(&id).cloned()
        };

        if let Some(path) = path {
            self.operations.push(RaftCommand::Delete { path });
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn commit(mut self: Box<Self>) -> StorageResult<()> {
        debug!(
            "Committing Raft transaction with {} operations",
            self.operations.len()
        );

        if self.operations.is_empty() {
            return Ok(());
        }

        // Acquire transaction mutex
        let _guard = self.transaction_mutex.lock().await;

        // Apply batch operation
        let batch_command = RaftCommand::Batch {
            operations: std::mem::take(&mut self.operations),
        };

        let mut state =
            self.state_machine
                .write()
                .map_err(|e| StorageError::TransactionFailed {
                    message: format!("State lock error: {}", e),
                })?;

        match state.apply_command(batch_command) {
            RaftResponse::Success => {
                info!("Raft transaction committed successfully");
                Ok(())
            }
            RaftResponse::Error { message } => {
                error!("Raft transaction failed: {}", message);
                Err(StorageError::TransactionFailed { message })
            }
            _ => Err(StorageError::TransactionFailed {
                message: "Unexpected response from batch operation".to_string(),
            }),
        }
    }

    async fn rollback(self: Box<Self>) -> StorageResult<()> {
        debug!("Rolling back Raft transaction");
        // For in-memory state machine, rollback is just dropping operations
        Ok(())
    }
}
