use super::raft::{ClusterError, NodeInfo, RaftNodeState};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

/// Configuration for cluster discovery
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub bind_address: String,
    pub bind_port: u16,
    pub advertise_address: Option<String>,
    pub discovery_port: u16,
    pub gossip_interval: Duration,
    pub probe_timeout: Duration,
    pub max_packet_size: usize,
}

/// Gossip protocol message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Node joining the cluster
    Join {
        node_id: String,
        address: String,
        port: u16,
        state: RaftNodeState,
    },
    /// Node leaving the cluster
    Leave {
        node_id: String,
    },
    /// Ping message for liveness checking
    Ping {
        node_id: String,
        timestamp: u64,
    },
    /// Pong response to ping
    Pong {
        node_id: String,
        timestamp: u64,
    },
    /// Node state update
    StateUpdate {
        node_id: String,
        state: RaftNodeState,
        term: u64,
        leader_id: Option<String>,
    },
}

/// Cluster discovery service using gossip protocol
pub struct ClusterDiscovery {
    node_id: String,
    config: DiscoveryConfig,
    membership_list: Arc<RwLock<HashMap<String, NodeInfo>>>,
    gossip_socket: Arc<tokio::net::UdpSocket>,
    is_running: Arc<RwLock<bool>>,
}

/// Gossip protocol implementation
pub struct GossipProtocol {
    config: DiscoveryConfig,
    socket: Arc<tokio::net::UdpSocket>,
    membership_list: Arc<RwLock<HashMap<String, NodeInfo>>>,
}

impl ClusterDiscovery {
    pub async fn new(
        node_id: String,
        config: DiscoveryConfig,
        initial_peers: Vec<String>,
    ) -> Result<Self, ClusterError> {
        // Create UDP socket for gossip communication
        let bind_addr = format!("{}:{}", config.bind_address, config.discovery_port);
        let socket = Arc::new(tokio::net::UdpSocket::bind(&bind_addr).await
            .map_err(|e| ClusterError::NetworkError(e.to_string()))?);

        info!("Cluster discovery socket bound to: {}", bind_addr);

        // Initialize membership list with known peers
        let membership_list = Arc::new(RwLock::new(HashMap::new()));

        // Add initial peers to membership list
        for peer in initial_peers {
            let node_info = NodeInfo {
                id: peer.clone(),
                address: "127.0.0.1".to_string(), // This should be resolved from peer string
                port: config.discovery_port,
                last_seen: Instant::now(),
                state: RaftNodeState::Follower,
            };
            membership_list.write().await.insert(peer, node_info);
        }

        Ok(Self {
            node_id,
            config,
            membership_list,
            gossip_socket: socket,
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> Result<(), ClusterError> {
        info!("Starting cluster discovery for node: {}", self.node_id);

        *self.is_running.write().await = true;

        // Start gossip protocol
        self.start_gossip_protocol().await?;

        // Start periodic cleanup
        self.start_membership_cleanup().await?;

        // Announce ourselves to the cluster
        self.announce_join().await?;

        Ok(())
    }

    pub async fn stop(&self) -> Result<(), ClusterError> {
        info!("Stopping cluster discovery for node: {}", self.node_id);

        *self.is_running.write().await = false;

        // Announce that we're leaving
        self.announce_leave().await?;

        Ok(())
    }

    async fn start_gossip_protocol(&self) -> Result<(), ClusterError> {
        let socket = Arc::clone(&self.gossip_socket);
        let membership_list = Arc::clone(&self.membership_list);
        let node_id = self.node_id.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; config.max_packet_size];

            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((size, src)) => {
                        if let Ok(message) = serde_json::from_slice::<GossipMessage>(&buf[..size]) {
                            if let Err(e) = Self::handle_gossip_message(
                                &membership_list,
                                &node_id,
                                message,
                                src
                            ).await {
                                warn!("Failed to handle gossip message: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to receive gossip message: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(())
    }

    async fn start_membership_cleanup(&self) -> Result<(), ClusterError> {
        let membership_list = Arc::clone(&self.membership_list);
        let cleanup_interval = Duration::from_secs(30);

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);

            loop {
                interval.tick().await;

                let mut members = membership_list.write().await;
                let now = Instant::now();

                // Remove nodes that haven't been seen for too long
                members.retain(|node_id, node_info| {
                    let age = now.duration_since(node_info.last_seen);
                    if age > Duration::from_secs(300) { // 5 minutes timeout
                        debug!("Removing stale node: {}", node_id);
                        false
                    } else {
                        true
                    }
                });
            }
        });

        Ok(())
    }

    async fn announce_join(&self) -> Result<(), ClusterError> {
        let message = GossipMessage::Join {
            node_id: self.node_id.clone(),
            address: self.get_advertise_address(),
            port: self.config.discovery_port,
            state: RaftNodeState::Follower,
        };

        self.broadcast_message(message).await
    }

    async fn announce_leave(&self) -> Result<(), ClusterError> {
        let message = GossipMessage::Leave {
            node_id: self.node_id.clone(),
        };

        self.broadcast_message(message).await
    }

    async fn broadcast_message(&self, message: GossipMessage) -> Result<(), ClusterError> {
        let serialized = serde_json::to_vec(&message)
            .map_err(|e| ClusterError::NetworkError(e.to_string()))?;

        let members = self.membership_list.read().await;

        for (node_id, node_info) in members.iter() {
            if node_id != &self.node_id {
                let target_addr = SocketAddr::new(
                    node_info.address.parse::<IpAddr>()
                        .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
                    node_info.port,
                );

                if let Err(e) = self.gossip_socket.send_to(&serialized, target_addr).await {
                    warn!("Failed to send gossip message to {}: {}", node_id, e);
                }
            }
        }

        Ok(())
    }

    async fn handle_gossip_message(
        membership_list: &Arc<RwLock<HashMap<String, NodeInfo>>>,
        local_node_id: &str,
        message: GossipMessage,
        src: SocketAddr,
    ) -> Result<(), ClusterError> {
        match message {
            GossipMessage::Join { node_id, address, port, state } => {
                let mut members = membership_list.write().await;
                let node_info = NodeInfo {
                    id: node_id.clone(),
                    address,
                    port,
                    last_seen: Instant::now(),
                    state,
                };

                members.insert(node_id, node_info);
                info!("Node {} joined the cluster", node_id);
            }

            GossipMessage::Leave { node_id } => {
                let mut members = membership_list.write().await;
                if members.remove(&node_id).is_some() {
                    info!("Node {} left the cluster", node_id);
                }
            }

            GossipMessage::Ping { node_id, timestamp } => {
                let mut members = membership_list.write().await;
                if let Some(node_info) = members.get_mut(&node_id) {
                    node_info.last_seen = Instant::now();

                    // Send pong response
                    let pong = GossipMessage::Pong { node_id: local_node_id.to_string(), timestamp };
                    // Send pong back to sender (implementation needed)
                }
            }

            GossipMessage::StateUpdate { node_id, state, term, leader_id } => {
                let mut members = membership_list.write().await;
                if let Some(node_info) = members.get_mut(&node_id) {
                    node_info.state = state;
                    node_info.last_seen = Instant::now();
                    debug!("Updated state for node {}: term={}, leader={:?}", node_id, term, leader_id);
                }
            }

            GossipMessage::Pong { .. } => {
                // Update last seen time for the responding node
                // Implementation needed
            }
        }

        Ok(())
    }

    pub async fn discover_peers(&self) -> Result<Vec<NodeInfo>, ClusterError> {
        let members = self.membership_list.read().await;
        Ok(members.values().cloned().collect())
    }

    pub async fn get_node_info(&self, node_id: &str) -> Result<Option<NodeInfo>, ClusterError> {
        let members = self.membership_list.read().await;
        Ok(members.get(node_id).cloned())
    }

    pub async fn update_node_state(&self, state: RaftNodeState, term: u64, leader_id: Option<String>) -> Result<(), ClusterError> {
        // Update our own state in membership list
        let mut members = self.membership_list.write().await;
        if let Some(node_info) = members.get_mut(&self.node_id) {
            node_info.state = state;
            node_info.last_seen = Instant::now();
        }

        // Broadcast state update
        let message = GossipMessage::StateUpdate {
            node_id: self.node_id.clone(),
            state,
            term,
            leader_id,
        };

        self.broadcast_message(message).await
    }

    fn get_advertise_address(&self) -> String {
        self.config.advertise_address.clone()
            .unwrap_or_else(|| self.config.bind_address.clone())
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
}

impl GossipProtocol {
    pub fn new(config: DiscoveryConfig, membership_list: Arc<RwLock<HashMap<String, NodeInfo>>>) -> Result<Self, ClusterError> {
        // Implementation for gossip protocol
        Ok(Self {
            config,
            socket: Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await
                .map_err(|e| ClusterError::NetworkError(e.to_string()))?),
            membership_list,
        })
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bind_address: "0.0.0.0".to_string(),
            bind_port: 0,
            advertise_address: None,
            discovery_port: 7946, // Default Serf port
            gossip_interval: Duration::from_secs(1),
            probe_timeout: Duration::from_secs(5),
            max_packet_size: 4096,
        }
    }
}
