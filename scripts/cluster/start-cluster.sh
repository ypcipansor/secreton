#!/bin/bash

# Secreton Vault - Multi-Node Raft Cluster Setup
# This script sets up a 3-node Raft cluster for high availability

set -e

echo "🏛️  Setting up Secreton Vault 3-Node Raft Cluster"
echo "=============================================="

# Configuration
CLUSTER_NAME="${CLUSTER_NAME:-secreton-cluster}"
BASE_DATA_DIR="${BASE_DATA_DIR:-./data/cluster}"
BASE_API_PORT="${BASE_API_PORT:-8200}"
BASE_RAFT_PORT="${BASE_RAFT_PORT:-8201}"

# Node configurations
NODES=(
    "node-1:127.0.0.1:$BASE_API_PORT:127.0.0.1:$BASE_RAFT_PORT"
    "node-2:127.0.0.1:$((BASE_API_PORT + 10)):127.0.0.1:$((BASE_RAFT_PORT + 10))"
    "node-3:127.0.0.1:$((BASE_API_PORT + 20)):127.0.0.1:$((BASE_RAFT_PORT + 20))"
)

# Create data directories
for node_config in "${NODES[@]}"; do
    IFS=':' read -r node_id api_host api_port raft_host raft_port <<< "$node_config"
    mkdir -p "$BASE_DATA_DIR/$node_id"
    mkdir -p "./logs/$node_id"
done

# Build the application
echo "🔨 Building Secreton vault..."
cargo build -p secreton-api --bin api_server

echo ""
echo "Starting cluster nodes..."
echo ""

# Start nodes
for i in "${!NODES[@]}"; do
    node_config="${NODES[$i]}"
    IFS=':' read -r node_id api_host api_port raft_host raft_port <<< "$node_config"
    
    # Create peer list (exclude self)
    peers=""
    for peer_config in "${NODES[@]}"; do
        IFS=':' read -r peer_id peer_api_host peer_api_port peer_raft_host peer_raft_port <<< "$peer_config"
        if [[ "$peer_id" != "$node_id" ]]; then
            if [[ -n "$peers" ]]; then
                peers="$peers,$peer_raft_host:$peer_raft_port"
            else
                peers="$peer_raft_host:$peer_raft_port"
            fi
        fi
    done
    
    echo "🚀 Starting $node_id..."
    echo "   API: http://$api_host:$api_port"
    echo "   Raft: $raft_host:$raft_port"
    echo "   Peers: $peers"
    
    # Set environment variables for this node
    export SECRETON_STORAGE_BACKEND="raft"
    export SECRETON_NODE_ID="$node_id"
    export SECRETON_RAFT_DATA_DIR="$BASE_DATA_DIR/$node_id"
    export SECRETON_RAFT_BIND_ADDR="$raft_host:$raft_port"
    export SECRETON_RAFT_ADVERTISE_ADDR="$raft_host:$raft_port"
    export SECRETON_RAFT_PEERS="$peers"
    export SECRETON_HOST="$api_host"
    export SECRETON_PORT="$api_port"
    export SECRETON_LOG_LEVEL="info"
    
    # Start node in background
    cargo run -p secreton-api --bin api_server > "./logs/$node_id/server.log" 2>&1 &
    
    # Store PID
    echo $! > "./logs/$node_id/server.pid"
    
    echo "   PID: $(cat "./logs/$node_id/server.pid")"
    echo "   Log: ./logs/$node_id/server.log"
    
    # Wait a bit before starting next node
    sleep 2
    echo ""
done

echo "✅ All nodes started!"
echo ""
echo "Cluster endpoints:"
for node_config in "${NODES[@]}"; do
    IFS=':' read -r node_id api_host api_port raft_host raft_port <<< "$node_config"
    echo "  $node_id: http://$api_host:$api_port"
done

echo ""
echo "To check cluster status:"
echo "  curl http://127.0.0.1:$BASE_API_PORT/health"
echo "  curl http://127.0.0.1:$BASE_API_PORT/v1/sys/leader"
echo ""
echo "To stop the cluster:"
echo "  ./stop-cluster.sh"
echo ""
echo "Logs are available in ./logs/[node-id]/server.log"
