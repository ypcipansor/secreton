#!/bin/bash

# Brankas Vault - Raft Integrated Storage Startup Script
# This script demonstrates how to start Brankas vault with Raft integrated storage

set -e

echo "🔐 Starting Brankas Vault with Raft Integrated Storage"
echo "================================================"

# Configuration
export BRANKAS_STORAGE_BACKEND="raft"
export BRANKAS_NODE_ID="${BRANKAS_NODE_ID:-brankas-node-1}"
export BRANKAS_RAFT_DATA_DIR="${BRANKAS_RAFT_DATA_DIR:-./data/raft}"
export BRANKAS_RAFT_BIND_ADDR="${BRANKAS_RAFT_BIND_ADDR:-127.0.0.1:8201}"
export BRANKAS_RAFT_ADVERTISE_ADDR="${BRANKAS_RAFT_ADVERTISE_ADDR:-127.0.0.1:8201}"

# Cluster configuration (empty for single node)
export BRANKAS_RAFT_PEERS="${BRANKAS_RAFT_PEERS:-}"

# Performance tuning
export BRANKAS_RAFT_SNAPSHOT_ENABLED="${BRANKAS_RAFT_SNAPSHOT_ENABLED:-true}"
export BRANKAS_RAFT_SNAPSHOT_INTERVAL="${BRANKAS_RAFT_SNAPSHOT_INTERVAL:-120}"
export BRANKAS_RAFT_LOG_RETENTION="${BRANKAS_RAFT_LOG_RETENTION:-10000}"

# Server configuration
export BRANKAS_HOST="${BRANKAS_HOST:-127.0.0.1}"
export BRANKAS_PORT="${BRANKAS_PORT:-8200}"
export BRANKAS_LOG_LEVEL="${BRANKAS_LOG_LEVEL:-info}"

# Create data directory if it doesn't exist
mkdir -p "$BRANKAS_RAFT_DATA_DIR"
mkdir -p "./logs"

echo "Configuration:"
echo "  Storage Backend: $BRANKAS_STORAGE_BACKEND"
echo "  Node ID: $BRANKAS_NODE_ID"
echo "  Data Directory: $BRANKAS_RAFT_DATA_DIR"
echo "  Bind Address: $BRANKAS_RAFT_BIND_ADDR"
echo "  Advertise Address: $BRANKAS_RAFT_ADVERTISE_ADDR"
echo "  Server Address: $BRANKAS_HOST:$BRANKAS_PORT"

if [[ -n "$BRANKAS_RAFT_PEERS" ]]; then
    echo "  Cluster Peers: $BRANKAS_RAFT_PEERS"
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
echo "🔨 Building Brankas vault..."
cargo build -p brankas-api --bin api_server

# Start the server
echo "🚀 Starting Brankas Vault server..."
echo "   API endpoint: http://$BRANKAS_HOST:$BRANKAS_PORT"
echo "   Raft endpoint: $BRANKAS_RAFT_BIND_ADDR"
echo ""
echo "Press Ctrl+C to stop the server"
echo ""

exec cargo run -p brankas-api --bin api_server
