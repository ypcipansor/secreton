# 🗄️ Secreton Storage Backends Documentation

## 📋 Overview

Secreton supports multiple storage backends for maximum flexibility in deployment. This document provides comprehensive information about each backend, configuration options, and usage examples.

---

## 🎯 Available Storage Backends

### **Production Ready (6 backends)**
1. ✅ **File Storage** - Local filesystem
2. ✅ **Memory Storage** - In-memory (testing)
3. ✅ **Consul Storage** - Consul KV store
4. ✅ **PostgreSQL Storage** - PostgreSQL database
5. ✅ **Secure Storage** - Encrypted storage
6. ✅ **Namespace Storage** - Multi-tenant storage

### **Code Complete (1 backend)**
7. ✅ **etcd Storage** - etcd v3 distributed storage

### **Planned (8 backends)**
8. ⏳ MySQL Storage
9. ⏳ DynamoDB Storage
10. ⏳ S3 Storage
11. ⏳ Azure Storage
12. ⏳ GCS Storage
13. ⏳ CockroachDB Storage
14. ⏳ Cassandra Storage
15. ⏳ Redis Storage

---

## 🚀 Quick Start

### Using Storage Factory

```rust
use secreton_storage::{StorageFactory, StorageFactoryConfig, StorageBackendType};

// Create in-memory storage (for testing)
let storage = StorageFactory::create_memory();

// Create Consul storage
let storage = StorageFactory::create_consul(
    "http://localhost:8500".to_string()
).await?;

// Create PostgreSQL storage
let storage = StorageFactory::create_postgresql(
    "postgresql://vault:pass@localhost/vault".to_string()
).await?;

// Create etcd storage
let storage = StorageFactory::create_etcd(
    vec!["http://localhost:2379".to_string()]
).await?;
```

### Using Configuration

```rust
use secreton_storage::{StorageFactory, StorageFactoryConfig, StorageBackendType};
use secreton_storage::ConsulStorageConfig;

let config = StorageFactoryConfig {
    backend_type: StorageBackendType::Consul,
    consul_config: Some(ConsulStorageConfig {
        address: "http://consul.example.com:8500".to_string(),
        datacenter: Some("dc1".to_string()),
        token: Some("your-consul-token".to_string()),
        path: "vault/".to_string(),
        tls_enabled: true,
        tls_ca_cert: Some(ca_cert_pem),
        timeout: 30,
        max_retries: 3,
    }),
    ..Default::default()
};

let storage = StorageFactory::create(config).await?;
```

---

## 📚 Backend Details

### 1. Consul Storage

**Description**: Uses HashiCorp Consul's KV store as the backend.

**Features**:
- ✅ Distributed and highly available
- ✅ Built-in service discovery
- ✅ Multi-datacenter support
- ✅ TLS/SSL encryption
- ✅ Token-based authentication
- ✅ Automatic retry with exponential backoff
- ✅ In-memory caching

**Configuration**:
```rust
use secreton_storage::ConsulStorageConfig;

let config = ConsulStorageConfig {
    // Consul server address
    address: "http://localhost:8500".to_string(),
    
    // Optional: Consul datacenter
    datacenter: Some("dc1".to_string()),
    
    // Optional: Consul ACL token
    token: Some("your-consul-token".to_string()),
    
    // Key prefix for all vault data
    path: "vault/".to_string(),
    
    // Enable TLS
    tls_enabled: true,
    
    // Optional: TLS CA certificate (PEM format)
    tls_ca_cert: Some(ca_cert_string),
    
    // Connection timeout in seconds
    timeout: 30,
    
    // Maximum number of retries
    max_retries: 3,
};
```

**Usage Example**:
```rust
use secreton_storage::backends::{ConsulStorage, ConsulStorageConfig};
use secreton_storage::StorageBackend;

// Create storage
let config = ConsulStorageConfig::default();
let storage = ConsulStorage::new(config).await?;

// Store entry
storage.store(&vault_entry).await?;

// Retrieve entry
let entry = storage.get_by_path("secret/myapp/config").await?;

// List entries
let params = QueryParams::new().with_path_prefix("secret/myapp/".to_string());
let entries = storage.list(&params).await?;

// Health check
let health = storage.health_check().await?;
println!("Consul is healthy: {}", health.is_healthy);
```

**Best Practices**:
- Use TLS in production
- Configure appropriate ACL tokens
- Set reasonable timeout values
- Enable retry logic for transient failures
- Monitor Consul cluster health

**Performance**:
- Read latency: ~5-10ms (local datacenter)
- Write latency: ~10-20ms (with replication)
- Throughput: ~1000 ops/sec per node

---

### 2. PostgreSQL Storage

**Description**: Uses PostgreSQL database as the backend with full ACID guarantees.

**Features**:
- ✅ ACID transactions
- ✅ Connection pooling
- ✅ Automatic schema creation
- ✅ JSONB metadata support
- ✅ Full-text search capabilities
- ✅ Advanced indexing
- ✅ SSL/TLS support

**Configuration**:
```rust
use secreton_storage::PostgreSQLStorageConfig;

let config = PostgreSQLStorageConfig {
    // PostgreSQL connection string
    connection_string: "postgresql://vault:password@localhost/vault".to_string(),
    
    // Table name for storing vault data
    table_name: "vault_kv_store".to_string(),
    
    // Maximum number of connections in pool
    max_connections: 10,
    
    // Connection timeout in seconds
    connection_timeout: 30,
    
    // SSL mode: disable, allow, prefer, require
    ssl_mode: "prefer".to_string(),
};
```

**Schema**:
```sql
CREATE TABLE vault_kv_store (
    id UUID PRIMARY KEY,
    path VARCHAR(512) UNIQUE NOT NULL,
    encrypted_data BYTEA NOT NULL,
    encryption_metadata JSONB NOT NULL,
    security_level INTEGER NOT NULL,
    metadata JSONB,
    tags TEXT[],
    version INTEGER NOT NULL DEFAULT 1,
    owner_id UUID NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_vault_kv_store_path ON vault_kv_store (path);
CREATE INDEX idx_vault_kv_store_owner ON vault_kv_store (owner_id);
CREATE INDEX idx_vault_kv_store_expires ON vault_kv_store (expires_at);
```

**Usage Example**:
```rust
use secreton_storage::backends::{PostgreSQLStorage, PostgreSQLStorageConfig};

// Create storage
let config = PostgreSQLStorageConfig {
    connection_string: "postgresql://vault:pass@localhost/vault".to_string(),
    max_connections: 20,
    ..Default::default()
};

let storage = PostgreSQLStorage::new(config).await?;

// Store entry
storage.store(&vault_entry).await?;

// Update entry
storage.update(&updated_entry).await?;

// Delete entry
let deleted = storage.delete_by_path("secret/old").await?;

// Get statistics
let stats = storage.get_stats().await?;
println!("Total entries: {}", stats.total_entries);
```

**Best Practices**:
- Use connection pooling
- Enable SSL in production
- Regular backups with pg_dump
- Monitor connection pool usage
- Use appropriate indexes
- Configure vacuum and analyze

**Performance**:
- Read latency: ~1-5ms
- Write latency: ~2-10ms
- Throughput: ~5000 ops/sec (with proper indexing)

---

### 3. etcd Storage

**Description**: Uses etcd v3 as a distributed key-value store.

**Features**:
- ✅ Distributed consensus (Raft)
- ✅ Strong consistency
- ✅ Watch API for change notifications
- ✅ Multi-version concurrency control
- ✅ TLS client certificates
- ✅ Basic authentication
- ✅ Multiple endpoints support

**Configuration**:
```rust
use secreton_storage::EtcdStorageConfig;

let config = EtcdStorageConfig {
    // etcd server endpoints
    endpoints: vec![
        "http://etcd1:2379".to_string(),
        "http://etcd2:2379".to_string(),
        "http://etcd3:2379".to_string(),
    ],
    
    // Key prefix for all vault data
    prefix: "/vault/".to_string(),
    
    // Optional: Username for authentication
    username: Some("vault".to_string()),
    
    // Optional: Password for authentication
    password: Some("password".to_string()),
    
    // Enable TLS
    tls_enabled: true,
    
    // Optional: TLS CA certificate
    tls_ca_cert: Some(ca_cert),
    
    // Optional: TLS client certificate
    tls_client_cert: Some(client_cert),
    
    // Optional: TLS client key
    tls_client_key: Some(client_key),
    
    // Connection timeout in seconds
    timeout: 30,
};
```

**Usage Example**:
```rust
use secreton_storage::backends::{EtcdStorage, EtcdStorageConfig};

// Create storage with multiple endpoints
let config = EtcdStorageConfig {
    endpoints: vec![
        "https://etcd1.example.com:2379".to_string(),
        "https://etcd2.example.com:2379".to_string(),
    ],
    tls_enabled: true,
    ..Default::default()
};

let storage = EtcdStorage::new(config).await?;

// Use storage
storage.store(&vault_entry).await?;
let entry = storage.get_by_path("secret/config").await?;
```

**Best Practices**:
- Use 3 or 5 node clusters
- Enable TLS with client certificates
- Monitor cluster health
- Use appropriate key prefixes
- Regular backups with etcdctl

**Performance**:
- Read latency: ~1-5ms
- Write latency: ~5-15ms (with quorum)
- Throughput: ~10,000 ops/sec

---

### 4. Memory Storage

**Description**: In-memory storage for testing and development.

**Features**:
- ✅ Fast operations
- ✅ No external dependencies
- ✅ Perfect for testing
- ⚠️ Data lost on restart

**Usage Example**:
```rust
use secreton_storage::StorageFactory;

// Create memory storage
let storage = StorageFactory::create_memory();

// Use for testing
storage.store(&test_entry).await?;
```

**Use Cases**:
- Unit testing
- Integration testing
- Development environment
- Temporary storage

---

## 🔧 Common Operations

### Store Entry
```rust
use secreton_storage::{VaultEntry, EncryptionMetadata, SecurityLevel};
use uuid::Uuid;

let entry = VaultEntry::new(
    "secret/myapp/config".to_string(),
    encrypted_data,
    encryption_metadata,
    SecurityLevel::Secret,
    owner_id,
);

storage.store(&entry).await?;
```

### Retrieve Entry
```rust
// By path
let entry = storage.get_by_path("secret/myapp/config").await?;

// By ID
let entry = storage.get_by_id(entry_id).await?;
```

### List Entries
```rust
use secreton_storage::QueryParams;

let params = QueryParams::new()
    .with_path_prefix("secret/myapp/".to_string())
    .with_owner(owner_id)
    .with_limit(100);

let entries = storage.list(&params).await?;
```

### Delete Entry
```rust
// By path
let deleted = storage.delete_by_path("secret/old").await?;

// By ID
let deleted = storage.delete_by_id(entry_id).await?;
```

### Health Check
```rust
let health = storage.health_check().await?;

if health.is_healthy {
    println!("Storage is healthy");
    println!("Response time: {}ms", health.response_time_ms);
} else {
    println!("Storage is unhealthy: {:?}", health.last_error);
}
```

### Get Statistics
```rust
let stats = storage.get_stats().await?;

println!("Total entries: {}", stats.total_entries);
println!("Total size: {} bytes", stats.total_size_bytes);
println!("Average entry size: {:.2} bytes", stats.average_entry_size);
```

---

## 🔐 Security Considerations

### Encryption
- All data is encrypted before storage
- Encryption metadata stored alongside data
- Support for multiple encryption algorithms

### Access Control
- Owner-based access control
- Security level classification
- Path-based permissions

### Network Security
- TLS/SSL for all network backends
- Client certificate authentication
- Token-based authentication

### Audit
- All operations logged
- Timestamp tracking
- Version tracking

---

## 📊 Performance Comparison

| Backend | Read Latency | Write Latency | Throughput | HA | Consistency |
|---------|-------------|---------------|------------|-----|-------------|
| **Memory** | <1ms | <1ms | 100k+ ops/s | ❌ | Strong |
| **Consul** | 5-10ms | 10-20ms | 1k ops/s | ✅ | Eventual |
| **PostgreSQL** | 1-5ms | 2-10ms | 5k ops/s | ✅ | Strong |
| **etcd** | 1-5ms | 5-15ms | 10k ops/s | ✅ | Strong |

---

## 🎯 Choosing the Right Backend

### Use Consul When:
- ✅ You already use Consul for service discovery
- ✅ You need multi-datacenter support
- ✅ You want built-in service mesh integration
- ✅ Eventual consistency is acceptable

### Use PostgreSQL When:
- ✅ You need ACID transactions
- ✅ You want strong consistency
- ✅ You need complex queries
- ✅ You have existing PostgreSQL infrastructure

### Use etcd When:
- ✅ You need strong consistency
- ✅ You want watch API for notifications
- ✅ You're running on Kubernetes
- ✅ You need distributed coordination

### Use Memory When:
- ✅ Testing and development
- ✅ Temporary storage
- ✅ No persistence needed

---

## 🔄 Migration Between Backends

```rust
use secreton_storage::{StorageFactory, QueryParams};

// Source backend
let source = StorageFactory::create_consul("http://consul:8500".to_string()).await?;

// Destination backend
let dest = StorageFactory::create_postgresql(
    "postgresql://vault:pass@localhost/vault".to_string()
).await?;

// Migrate all entries
let entries = source.list(&QueryParams::default()).await?;
for entry in entries {
    dest.store(&entry).await?;
}

println!("Migrated {} entries", entries.len());
```

---

## 📈 Monitoring

### Health Checks
```rust
// Periodic health check
tokio::spawn(async move {
    loop {
        let health = storage.health_check().await;
        if let Ok(h) = health {
            metrics.gauge("storage.healthy", if h.is_healthy { 1.0 } else { 0.0 });
            metrics.gauge("storage.response_time_ms", h.response_time_ms);
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
});
```

### Metrics
```rust
// Collect statistics
let stats = storage.get_stats().await?;

metrics.gauge("storage.total_entries", stats.total_entries as f64);
metrics.gauge("storage.total_size_bytes", stats.total_size_bytes as f64);
metrics.gauge("storage.avg_entry_size", stats.average_entry_size);
```

---

## 🐛 Troubleshooting

### Connection Issues
```rust
// Check connectivity
match storage.health_check().await {
    Ok(health) if health.is_healthy => println!("Connected"),
    Ok(health) => println!("Unhealthy: {:?}", health.last_error),
    Err(e) => println!("Connection failed: {}", e),
}
```

### Performance Issues
- Check connection pool settings
- Monitor query performance
- Review index usage
- Check network latency

### Data Issues
- Verify encryption keys
- Check data integrity
- Review access permissions
- Monitor storage capacity

---

## 📚 Additional Resources

- [Consul Documentation](https://www.consul.io/docs)
- [PostgreSQL Documentation](https://www.postgresql.org/docs/)
- [etcd Documentation](https://etcd.io/docs/)
- [Secreton API Documentation](./API.md)

---

**Last Updated**: 2025-09-30  
**Version**: 1.0.0  
**Status**: Production Ready
