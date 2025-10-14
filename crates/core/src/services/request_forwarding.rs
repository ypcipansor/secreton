// Request Forwarding - Automatic forwarding in HA cluster
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ForwardingError {
    #[error("Node not found: {0}")]
    NodeNotFound(String),
    #[error("Not in HA mode")]
    NotInHAMode,
    #[error("Leader not available")]
    LeaderNotAvailable,
    #[error("Forwarding failed: {0}")]
    ForwardingFailed(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Circuit breaker open for node: {0}")]
    CircuitBreakerOpen(String),
}

pub type Result<T> = std::result::Result<T, ForwardingError>;

/// Node role in HA cluster
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeRole {
    Leader,
    Follower,
    Standby,
}

/// Node information in cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub node_id: String,
    pub address: String,
    pub role: NodeRole,
    pub is_active: bool,
    pub last_heartbeat: DateTime<Utc>,
    pub api_address: String,
    pub cluster_address: String,
}

/// Request that needs forwarding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardRequest {
    pub id: String,
    pub method: String,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub source_node: String,
    pub target_node: Option<String>,
    pub created_at: DateTime<Utc>,
}

/// Response from forwarded request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardResponse {
    pub request_id: String,
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub forwarded_by: String,
    pub processed_at: DateTime<Utc>,
}

/// Forwarding statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardingStats {
    pub node_id: String,
    pub total_forwarded: u64,
    pub total_received: u64,
    pub successful_forwards: u64,
    pub failed_forwards: u64,
    pub average_latency_ms: u64,
    pub last_forward: Option<DateTime<Utc>>,
}

/// Circuit breaker state for fault tolerance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CircuitBreakerState {
    Closed,   // Normal operation
    Open,     // Too many failures, stop forwarding
    HalfOpen, // Testing if node recovered
}

/// Circuit breaker for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreaker {
    pub node_id: String,
    pub state: CircuitBreakerState,
    pub failure_count: u64,
    pub success_count: u64,
    pub last_failure: Option<DateTime<Utc>>,
    pub last_state_change: DateTime<Utc>,
    pub failure_threshold: u64,
    pub success_threshold: u64,
    pub timeout_seconds: u64,
}

impl CircuitBreaker {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            success_count: 0,
            last_failure: None,
            last_state_change: Utc::now(),
            failure_threshold: 5,
            success_threshold: 3,
            timeout_seconds: 60,
        }
    }

    pub fn record_success(&mut self) {
        match self.state {
            CircuitBreakerState::Closed => {
                self.failure_count = 0;
            }
            CircuitBreakerState::HalfOpen => {
                self.success_count += 1;
                if self.success_count >= self.success_threshold {
                    self.state = CircuitBreakerState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                    self.last_state_change = Utc::now();
                }
            }
            CircuitBreakerState::Open => {}
        }
    }

    pub fn record_failure(&mut self) {
        self.failure_count += 1;
        self.last_failure = Some(Utc::now());

        match self.state {
            CircuitBreakerState::Closed => {
                if self.failure_count >= self.failure_threshold {
                    self.state = CircuitBreakerState::Open;
                    self.last_state_change = Utc::now();
                }
            }
            CircuitBreakerState::HalfOpen => {
                self.state = CircuitBreakerState::Open;
                self.success_count = 0;
                self.last_state_change = Utc::now();
            }
            CircuitBreakerState::Open => {}
        }
    }

    pub fn can_attempt(&mut self) -> bool {
        match self.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::HalfOpen => true,
            CircuitBreakerState::Open => {
                // Check if timeout elapsed
                let elapsed = Utc::now() - self.last_state_change;
                if elapsed.num_seconds() >= self.timeout_seconds as i64 {
                    self.state = CircuitBreakerState::HalfOpen;
                    self.success_count = 0;
                    self.last_state_change = Utc::now();
                    true
                } else {
                    false
                }
            }
        }
    }
}

impl ClusterNode {
    pub fn new(node_id: String, address: String, role: NodeRole) -> Self {
        Self {
            node_id,
            api_address: address.clone(),
            address,
            role,
            is_active: true,
            last_heartbeat: Utc::now(),
            cluster_address: String::new(),
        }
    }

    pub fn is_healthy(&self) -> bool {
        if !self.is_active {
            return false;
        }

        let elapsed = Utc::now() - self.last_heartbeat;
        elapsed.num_seconds() < 30 // 30 second heartbeat timeout
    }

    pub fn update_heartbeat(&mut self) {
        self.last_heartbeat = Utc::now();
    }
}

impl ForwardingStats {
    pub fn new(node_id: String) -> Self {
        Self {
            node_id,
            total_forwarded: 0,
            total_received: 0,
            successful_forwards: 0,
            failed_forwards: 0,
            average_latency_ms: 0,
            last_forward: None,
        }
    }

    pub fn record_forward(&mut self, success: bool, latency_ms: u64) {
        self.total_forwarded += 1;
        self.last_forward = Some(Utc::now());

        if success {
            self.successful_forwards += 1;
        } else {
            self.failed_forwards += 1;
        }

        // Update average latency (simple moving average)
        let total_requests = self.total_forwarded;
        self.average_latency_ms =
            ((self.average_latency_ms * (total_requests - 1)) + latency_ms) / total_requests;
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_forwarded == 0 {
            return 1.0;
        }
        self.successful_forwards as f64 / self.total_forwarded as f64
    }
}

/// Request forwarding service
pub struct RequestForwardingService {
    local_node_id: Arc<RwLock<String>>,
    cluster_nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    circuit_breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    stats: Arc<RwLock<HashMap<String, ForwardingStats>>>,
    pending_requests: Arc<RwLock<HashMap<String, ForwardRequest>>>,
}

impl RequestForwardingService {
    pub fn new() -> Self {
        Self {
            local_node_id: Arc::new(RwLock::new(String::new())),
            cluster_nodes: Arc::new(RwLock::new(HashMap::new())),
            circuit_breakers: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(HashMap::new())),
            pending_requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Initialize the service with local node information
    pub async fn initialize(&self, node_id: String, address: String, role: NodeRole) -> Result<()> {
        let mut local_id = self.local_node_id.write().await;
        *local_id = node_id.clone();

        let mut nodes = self.cluster_nodes.write().await;
        nodes.insert(
            node_id.clone(),
            ClusterNode::new(node_id.clone(), address, role),
        );

        let mut stats = self.stats.write().await;
        stats.insert(node_id.clone(), ForwardingStats::new(node_id));

        Ok(())
    }

    /// Register a cluster node
    pub async fn register_node(&self, node: ClusterNode) -> Result<()> {
        let mut nodes = self.cluster_nodes.write().await;
        let node_id = node.node_id.clone();
        nodes.insert(node_id.clone(), node);

        // Initialize circuit breaker
        let mut breakers = self.circuit_breakers.write().await;
        breakers.insert(node_id.clone(), CircuitBreaker::new(node_id.clone()));

        // Initialize stats
        let mut stats = self.stats.write().await;
        stats.insert(node_id.clone(), ForwardingStats::new(node_id));

        Ok(())
    }

    /// Get the current leader node
    pub async fn get_leader(&self) -> Result<ClusterNode> {
        let nodes = self.cluster_nodes.read().await;

        nodes
            .values()
            .find(|n| n.role == NodeRole::Leader && n.is_healthy())
            .cloned()
            .ok_or(ForwardingError::LeaderNotAvailable)
    }

    /// Check if current node is leader
    pub async fn is_leader(&self) -> bool {
        let local_id = self.local_node_id.read().await;
        let nodes = self.cluster_nodes.read().await;

        if let Some(node) = nodes.get(&*local_id) {
            node.role == NodeRole::Leader
        } else {
            false
        }
    }

    /// Determine if a request should be forwarded
    pub async fn should_forward(&self, path: &str, method: &str) -> Result<bool> {
        // Check if we're in HA mode
        let nodes = self.cluster_nodes.read().await;
        if nodes.len() <= 1 {
            return Ok(false); // Single node, no forwarding needed
        }

        // Check if we're the leader
        let is_leader = self.is_leader().await;

        // Write operations must go to leader
        let is_write_operation = matches!(method, "POST" | "PUT" | "DELETE" | "PATCH");

        if is_write_operation && !is_leader {
            return Ok(true); // Forward to leader
        }

        Ok(false)
    }

    /// Forward a request to appropriate node (usually leader)
    pub async fn forward_request(
        &self,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: Option<Vec<u8>>,
    ) -> Result<ForwardResponse> {
        let leader = self.get_leader().await?;
        let local_id = self.local_node_id.read().await.clone();

        // Check circuit breaker
        let mut breakers = self.circuit_breakers.write().await;
        let breaker = breakers
            .entry(leader.node_id.clone())
            .or_insert_with(|| CircuitBreaker::new(leader.node_id.clone()));

        if !breaker.can_attempt() {
            return Err(ForwardingError::CircuitBreakerOpen(leader.node_id.clone()));
        }
        drop(breakers);

        // Create forward request
        let request = ForwardRequest {
            id: uuid::Uuid::new_v4().to_string(),
            method: method.clone(),
            path: path.clone(),
            headers,
            body,
            source_node: local_id.clone(),
            target_node: Some(leader.node_id.clone()),
            created_at: Utc::now(),
        };

        let request_id = request.id.clone();

        // Store pending request
        let mut pending = self.pending_requests.write().await;
        pending.insert(request_id.clone(), request);
        drop(pending);

        let start_time = Utc::now();

        // Simulate forwarding (in production, would make HTTP request)
        let success = self
            .simulate_forward(&leader.api_address, &method, &path)
            .await;

        let latency_ms = (Utc::now() - start_time).num_milliseconds() as u64;

        // Update circuit breaker
        let mut breakers = self.circuit_breakers.write().await;
        if let Some(breaker) = breakers.get_mut(&leader.node_id) {
            if success {
                breaker.record_success();
            } else {
                breaker.record_failure();
            }
        }
        drop(breakers);

        // Update stats
        let mut stats = self.stats.write().await;
        if let Some(stat) = stats.get_mut(&local_id) {
            stat.record_forward(success, latency_ms);
        }

        // Remove from pending
        let mut pending = self.pending_requests.write().await;
        pending.remove(&request_id);

        if success {
            Ok(ForwardResponse {
                request_id,
                status_code: 200,
                headers: HashMap::new(),
                body: Some(b"Success".to_vec()),
                forwarded_by: local_id,
                processed_at: Utc::now(),
            })
        } else {
            Err(ForwardingError::ForwardingFailed(
                "Simulated failure".to_string(),
            ))
        }
    }

    /// Update node heartbeat
    pub async fn update_heartbeat(&self, node_id: &str) -> Result<()> {
        let mut nodes = self.cluster_nodes.write().await;
        let node = nodes
            .get_mut(node_id)
            .ok_or_else(|| ForwardingError::NodeNotFound(node_id.to_string()))?;

        node.update_heartbeat();
        Ok(())
    }

    /// Get forwarding statistics
    pub async fn get_stats(&self, node_id: &str) -> Result<ForwardingStats> {
        let stats = self.stats.read().await;
        stats
            .get(node_id)
            .cloned()
            .ok_or_else(|| ForwardingError::NodeNotFound(node_id.to_string()))
    }

    /// Get all cluster nodes
    pub async fn list_nodes(&self) -> Vec<ClusterNode> {
        let nodes = self.cluster_nodes.read().await;
        nodes.values().cloned().collect()
    }

    /// Get circuit breaker status for a node
    pub async fn get_circuit_breaker(&self, node_id: &str) -> Result<CircuitBreaker> {
        let breakers = self.circuit_breakers.read().await;
        breakers
            .get(node_id)
            .cloned()
            .ok_or_else(|| ForwardingError::NodeNotFound(node_id.to_string()))
    }

    /// Simulate forwarding (placeholder for actual HTTP request)
    async fn simulate_forward(&self, _address: &str, _method: &str, _path: &str) -> bool {
        // In production, this would make an actual HTTP request
        // For now, simulate success
        true
    }

    /// Remove unhealthy nodes
    pub async fn cleanup_unhealthy_nodes(&self) -> Vec<String> {
        let mut nodes = self.cluster_nodes.write().await;
        let unhealthy: Vec<_> = nodes
            .iter()
            .filter(|(_, node)| !node.is_healthy())
            .map(|(id, _)| id.clone())
            .collect();

        for node_id in &unhealthy {
            nodes.remove(node_id);
        }

        unhealthy
    }
}

impl Default for RequestForwardingService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_initialize_service() {
        let service = RequestForwardingService::new();

        service
            .initialize(
                "node-1".to_string(),
                "127.0.0.1:8200".to_string(),
                NodeRole::Leader,
            )
            .await
            .unwrap();

        assert!(service.is_leader().await);
    }

    #[tokio::test]
    async fn test_register_nodes() {
        let service = RequestForwardingService::new();

        service
            .initialize(
                "node-1".to_string(),
                "127.0.0.1:8200".to_string(),
                NodeRole::Leader,
            )
            .await
            .unwrap();

        let follower = ClusterNode::new(
            "node-2".to_string(),
            "127.0.0.1:8201".to_string(),
            NodeRole::Follower,
        );

        service.register_node(follower).await.unwrap();

        let nodes = service.list_nodes().await;
        assert_eq!(nodes.len(), 2);
    }

    #[tokio::test]
    async fn test_should_forward() {
        let service = RequestForwardingService::new();

        // Initialize as follower
        service
            .initialize(
                "node-1".to_string(),
                "127.0.0.1:8200".to_string(),
                NodeRole::Follower,
            )
            .await
            .unwrap();

        // Register leader
        let leader = ClusterNode::new(
            "node-2".to_string(),
            "127.0.0.1:8201".to_string(),
            NodeRole::Leader,
        );
        service.register_node(leader).await.unwrap();

        // Write operations should be forwarded to leader
        let should_forward = service
            .should_forward("/secret/data", "POST")
            .await
            .unwrap();
        assert!(should_forward);
    }

    #[tokio::test]
    async fn test_circuit_breaker() {
        let mut breaker = CircuitBreaker::new("test-node".to_string());

        assert_eq!(breaker.state, CircuitBreakerState::Closed);
        assert!(breaker.can_attempt());

        // Record failures to open circuit
        for _ in 0..5 {
            breaker.record_failure();
        }

        assert_eq!(breaker.state, CircuitBreakerState::Open);
        assert!(!breaker.can_attempt());
    }

    #[tokio::test]
    async fn test_forwarding_stats() {
        let mut stats = ForwardingStats::new("node-1".to_string());

        stats.record_forward(true, 10);
        stats.record_forward(true, 20);
        stats.record_forward(false, 30);

        assert_eq!(stats.total_forwarded, 3);
        assert_eq!(stats.successful_forwards, 2);
        assert_eq!(stats.failed_forwards, 1);
        assert_eq!(stats.success_rate(), 2.0 / 3.0);
    }

    #[tokio::test]
    async fn test_node_health_check() {
        let mut node = ClusterNode::new(
            "test-node".to_string(),
            "127.0.0.1:8200".to_string(),
            NodeRole::Follower,
        );

        assert!(node.is_healthy());

        // Simulate old heartbeat
        node.last_heartbeat = Utc::now() - chrono::Duration::seconds(60);
        assert!(!node.is_healthy());

        // Update heartbeat
        node.update_heartbeat();
        assert!(node.is_healthy());
    }
}
