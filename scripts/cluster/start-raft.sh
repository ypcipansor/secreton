#!/bin/bash

# Secreton Vault - Raft Integrated Storage Startup Script
# This script demonstrates how to start Secreton vault with Raft integrated storage

set -e

echo "🔐 Starting Secreton Vault with Raft Integrated Storage"
echo "================================================"

# Configuration
export SECRETON_STORAGE_BACKEND="raft"
export SECRETON_NODE_ID="${SECRETON_NODE_ID:-secreton-node-1}"
export SECRETON_RAFT_DATA_DIR="${SECRETON_RAFT_DATA_DIR:-./data/raft}"
export SECRETON_RAFT_BIND_ADDR="${SECRETON_RAFT_BIND_ADDR:-127.0.0.1:8201}"
export SECRETON_RAFT_ADVERTISE_ADDR="${SECRETON_RAFT_ADVERTISE_ADDR:-127.0.0.1:8201}"

# Cluster configuration (empty for single node)
export SECRETON_RAFT_PEERS="${SECRETON_RAFT_PEERS:-}"

# Performance tuning
export SECRETON_RAFT_SNAPSHOT_ENABLED="${SECRETON_RAFT_SNAPSHOT_ENABLED:-true}"
export SECRETON_RAFT_SNAPSHOT_INTERVAL="${SECRETON_RAFT_SNAPSHOT_INTERVAL:-120}"
export SECRETON_RAFT_LOG_RETENTION="${SECRETON_RAFT_LOG_RETENTION:-10000}"

# Server configuration
export SECRETON_HOST="${SECRETON_HOST:-127.0.0.1}"
export SECRETON_PORT="${SECRETON_PORT:-8200}"
export SECRETON_LOG_LEVEL="${SECRETON_LOG_LEVEL:-info}"

# Create data directory if it doesn't exist
mkdir -p "$SECRETON_RAFT_DATA_DIR"
mkdir -p "./logs"

echo "Configuration:"
echo "  Storage Backend: $SECRETON_STORAGE_BACKEND"
echo "  Node ID: $SECRETON_NODE_ID"
echo "  Data Directory: $SECRETON_RAFT_DATA_DIR"
echo "  Bind Address: $SECRETON_RAFT_BIND_ADDR"
echo "  Advertise Address: $SECRETON_RAFT_ADVERTISE_ADDR"
echo "  Server Address: $SECRETON_HOST:$SECRETON_PORT"

if [[ -n "$SECRETON_RAFT_PEERS" ]]; then
    echo "  Cluster Peers: $SECRETON_RAFT_PEERS"
else
    echo "  Single-node mode (no peers)"
fi

echo ""

# Check if cargo is available
if ! command -v cargo &> /dev/null; then
    echo "❌ Error: Cargo not found. Please install Rust."
    exit 1
fi

# Build if needed
echo "🔨 Building Secreton vault..."
cargo build -p secreton-api --bin api_server

# Start the server
echo "🚀 Starting Secreton Vault server..."
echo "   API endpoint: http://$SECRETON_HOST:$SECRETON_PORT"
echo "   Raft endpoint: $SECRETON_RAFT_BIND_ADDR"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

exec cargo run -p secreton-api --bin api_server
