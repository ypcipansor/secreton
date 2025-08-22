#!/bin/bash

# Secreton Vault - Stop Raft Cluster
# This script stops all nodes in the Raft cluster

set -e

echo "🛑 Stopping Secreton Vault Raft Cluster"
echo "====================================="

# Find and stop all server processes
if ls ./logs/*/server.pid >/dev/null 2>&1; then
    for pid_file in ./logs/*/server.pid; do
        if [[ -f "$pid_file" ]]; then
            pid=$(cat "$pid_file")
            node_dir=$(dirname "$pid_file")
            node_name=$(basename "$node_dir")
            
            if kill -0 "$pid" 2>/dev/null; then
                echo "Stopping $node_name (PID: $pid)..."
                kill "$pid"
                
                # Wait for process to stop
                for i in {1..10}; do
                    if ! kill -0 "$pid" 2>/dev/null; then
                        break
                    fi
                    sleep 1
                done
                
                # Force kill if still running
                if kill -0 "$pid" 2>/dev/null; then
                    echo "Force stopping $node_name..."
                    kill -9 "$pid" 2>/dev/null || true
                fi
            else
                echo "$node_name was not running"
            fi
            
            # Remove PID file
            rm -f "$pid_file"
        fi
    done
else
    echo "No PID files found - cluster may not be running"
fi

# Also kill any remaining api_server processes
echo "Cleaning up any remaining processes..."
pkill -f "api_server" || true

echo ""
echo "✅ Cluster stopped successfully"
echo ""
echo "To clean up data and logs:"
echo "  rm -rf ./data/cluster ./logs"
