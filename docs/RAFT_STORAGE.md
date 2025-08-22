# Secreton Vault - Raft Integrated Storage

Secreton Vault implements HashiCorp Vault-compatible integrated storage using the Raft consensus algorithm. This provides a self-contained, highly available storage solution without external dependencies.

## 📋 Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)  
- [Configuration](#configuration)
- [Deployment Modes](#deployment-modes)
- [Getting Started](#getting-started)
- [Multi-Node Cluster](#multi-node-cluster)
- [Operations](#operations)
- [Performance](#performance)
- [Security](#security)
- [Troubleshooting](#troubleshooting)

## 🔍 Overview

Raft Integrated Storage is inspired by HashiCorp Vault's integrated storage backend, providing:

- **Self-Contained**: No external database dependencies
- **High Availability**: Built-in consensus and leader election
- **Strong Consistency**: ACID transactions with linearizability
- **Automatic Failover**: Leader election in case of node failures
- **Data Replication**: Automatic data replication across cluster nodes
- **Snapshotting**: Periodic snapshots for faster recovery
- **Compatible API**: Drop-in replacement for other storage backends

## 🏗️ Architecture

### Raft Consensus

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Leader Node   │    │  Follower Node  │    │  Follower Node  │
│                 │    │                 │    │                 │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │    API    │  │◄───┤  │    API    │  │◄───┤  │    API    │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │   Raft    │  │────┤  │   Raft    │  │────┤  │   Raft    │  │
│  │  Engine   │  │    │  │  Engine   │  │    │  │  Engine   │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
│  ┌───────────┐  │    │  ┌───────────┐  │    │  ┌───────────┐  │
│  │  Storage  │  │    │  │  Storage  │  │    │  │  Storage  │  │
│  └───────────┘  │    │  └───────────┘  │    │  └───────────┘  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                    Raft Consensus Network
```

### Storage Stack

```
┌─────────────────────────────────────────┐
│           Secreton API Layer             │
├─────────────────────────────────────────┤
│          Transit Engine                 │
│            KV Engine                    │
├─────────────────────────────────────────┤
│        Storage Abstraction              │
├─────────────────────────────────────────┤
│        Raft State Machine               │
├─────────────────────────────────────────┤
│          Raft Consensus                 │
├─────────────────────────────────────────┤
│      Persistent Log Storage             │
└─────────────────────────────────────────┘
```

## ⚙️ Configuration

### Environment Variables

```bash
# Storage Backend Selection
export SECRETON_STORAGE_BACKEND="raft"

# Node Configuration
export SECRETON_NODE_ID="secreton-node-1"
export SECRETON_RAFT_DATA_DIR="./data/raft"

# Network Configuration
export SECRETON_RAFT_BIND_ADDR="127.0.0.1:8201"
export SECRETON_RAFT_ADVERTISE_ADDR="127.0.0.1:8201"

# Cluster Configuration
export SECRETON_RAFT_PEERS="node2:8201,node3:8201"

# Performance Tuning
export SECRETON_RAFT_SNAPSHOT_ENABLED="true"
export SECRETON_RAFT_SNAPSHOT_INTERVAL="120"
export SECRETON_RAFT_LOG_RETENTION="10000"
export SECRETON_RAFT_PERFORMANCE_MULTIPLIER="1"
```

### Configuration File (config/raft.toml)

```toml
[server]
host = "127.0.0.1"
port = 8200

[storage]
backend_type = "raft"
node_id = "secreton-node-1"
data_dir = "./data/raft"
bind_addr = "127.0.0.1:8201"
advertise_addr = "127.0.0.1:8201"
peers = []

[raft]
snapshot_enabled = true
snapshot_interval_secs = 120
log_retention_count = 10000
performance_multiplier = 1
```

## 🚀 Deployment Modes

### 1. Single Node (Development)

Perfect for development and testing:

```bash
# Start single node
export SECRETON_STORAGE_BACKEND="raft"
export SECRETON_NODE_ID="dev-node"
export SECRETON_RAFT_DATA_DIR="./data/dev-raft"

cargo run -p secreton-api --bin api_server
```

### 2. Three-Node Cluster (Production)

Recommended for production high availability:

```bash
# Use provided cluster scripts
./start-cluster.sh
```

### 3. Five-Node Cluster (High Availability)

For maximum fault tolerance (tolerates 2 node failures):

```bash
# Modify start-cluster.sh for 5 nodes
# Can tolerate up to 2 simultaneous node failures
```

## 🎯 Getting Started

### Quick Start

1. **Single Node Setup**:
   ```bash
   ./start-raft.sh
   ```

2. **Test the System**:
   ```bash
   ./demo-raft.sh
   ```

3. **Multi-Node Cluster**:
   ```bash
   ./start-cluster.sh
   ```

### Manual Setup

1. **Install Dependencies**:
   ```bash
   cargo build --workspace
   ```

2. **Configure Node**:
   ```bash
   export SECRETON_STORAGE_BACKEND="raft"
   export SECRETON_NODE_ID="node-1"
   export SECRETON_RAFT_DATA_DIR="./data/raft/node-1"
   ```

3. **Start Server**:
   ```bash
   cargo run -p secreton-api --bin api_server
   ```

## 🏛️ Multi-Node Cluster

### Cluster Formation

1. **Bootstrap First Node**:
   ```bash
   export SECRETON_STORAGE_BACKEND="raft"
   export SECRETON_NODE_ID="node-1"
   export SECRETON_RAFT_BIND_ADDR="10.0.1.1:8201"
   export SECRETON_RAFT_PEERS=""
   
   cargo run -p secreton-api --bin api_server
   ```

2. **Join Additional Nodes**:
   ```bash
   export SECRETON_STORAGE_BACKEND="raft"
   export SECRETON_NODE_ID="node-2"
   export SECRETON_RAFT_BIND_ADDR="10.0.1.2:8201"
   export SECRETON_RAFT_PEERS="10.0.1.1:8201,10.0.1.3:8201"
   
   cargo run -p secreton-api --bin api_server
   ```

3. **Verify Cluster**:
   ```bash
   curl http://10.0.1.1:8200/v1/sys/leader
   curl http://10.0.1.2:8200/health
   curl http://10.0.1.3:8200/health
   ```

### Node Roles

- **Leader**: Handles all writes, replicates to followers
- **Follower**: Receives updates from leader, can serve reads
- **Candidate**: Temporary state during leader election

## 🔧 Operations

### Monitoring

```bash
# Check cluster health
curl http://localhost:8200/health

# Get leader information
curl http://localhost:8200/v1/sys/leader

# Storage statistics
curl http://localhost:8200/v1/sys/storage/raft/stats

# Node status
curl http://localhost:8200/v1/sys/storage/raft/configuration
```

### Backup and Recovery

```bash
# Create snapshot (automatic)
# Snapshots are created automatically every 120 seconds

# Manual backup
cp -r ./data/raft ./backup/raft-$(date +%Y%m%d-%H%M%S)

# Recovery
# 1. Stop all nodes
# 2. Restore data directory from backup
# 3. Start nodes
```

### Scaling

```bash
# Add new node to existing cluster
export SECRETON_NODE_ID="node-4"
export SECRETON_RAFT_PEERS="existing-nodes..."

# Remove node (graceful)
# 1. Stop the node
# 2. Update SECRETON_RAFT_PEERS on remaining nodes
# 3. Clean up data directory
```

## 📊 Performance

### Benchmarks

**Single Node Performance**:
- Writes: ~500-1000 ops/sec
- Reads: ~5000-10000 ops/sec
- Latency: <10ms p99

**Cluster Performance**:
- Writes: ~300-600 ops/sec (consensus overhead)
- Reads: ~4000-8000 ops/sec per node
- Latency: <20ms p99

### Tuning

```bash
# Increase performance multiplier for faster elections
export SECRETON_RAFT_PERFORMANCE_MULTIPLIER="2"

# Adjust snapshot frequency
export SECRETON_RAFT_SNAPSHOT_INTERVAL="60"

# Increase log retention for better recovery
export SECRETON_RAFT_LOG_RETENTION="50000"
```

## 🔐 Security

### Network Security

- Use TLS for Raft communication in production
- Implement network segmentation
- Use mutual authentication between nodes

### Data Security

- All data encrypted at rest using AES-256-GCM
- Transit encryption for network communication
- Audit logging for all operations

### Access Control

- API authentication required for all operations
- Role-based access control (RBAC)
- Policy-based authorization

## 🔍 Troubleshooting

### Common Issues

**Issue: Node can't join cluster**
```bash
# Check network connectivity
telnet <leader-ip> 8201

# Verify configuration
echo $SECRETON_RAFT_PEERS
```

**Issue: Split-brain scenario**
```bash
# Check leader status on all nodes
for node in node1 node2 node3; do
  curl http://$node:8200/v1/sys/leader
done

# Restart minority partition
```

**Issue: Performance degradation**
```bash
# Check disk I/O
iostat -x 1

# Check network latency between nodes
ping <peer-node>

# Review Raft log size
du -sh ./data/raft/
```

### Debugging

```bash
# Enable debug logging
export SECRETON_LOG_LEVEL="debug"
export RUST_LOG="secreton=debug"

# Check server logs
tail -f server.log

# Examine Raft state
ls -la ./data/raft/
```

### Recovery Procedures

**Leader Election Stuck**:
1. Restart all nodes simultaneously
2. Check network connectivity
3. Verify node IDs are unique

**Data Corruption**:
1. Stop all nodes
2. Restore from latest backup
3. Restart cluster

**Node Failure**:
1. Verify cluster has majority (n/2 + 1)
2. Remove failed node from configuration
3. Add replacement node if needed

## 🔗 API Compatibility

The Raft storage backend is fully compatible with all Secreton Vault APIs:

- **Transit Engine**: Encryption/decryption operations
- **KV Secrets Engine**: Secret storage and retrieval
- **System APIs**: Health, status, and administrative operations

All operations are replicated across the cluster using Raft consensus, ensuring strong consistency and durability.

## 📈 Production Recommendations

1. **Use odd number of nodes** (3, 5, 7) for proper quorum
2. **Deploy across different availability zones** for fault tolerance
3. **Monitor disk usage** and implement log rotation
4. **Regular backups** of Raft data directories
5. **Network security** with TLS and firewall rules
6. **Resource allocation** with sufficient CPU and disk I/O
7. **Health monitoring** with alerting on leader changes

---

For more information, see the main [README.md](../README.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
