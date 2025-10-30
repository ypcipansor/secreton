# Secreton Configuration Guide

This guide covers configuration options for Secreton deployment and operation.

## Configuration Sources

Secreton supports multiple configuration sources with the following precedence (highest to lowest):

1. Command-line flags
2. Environment variables
3. Configuration files
4. Default values

## Basic Configuration

### Server Configuration

```toml
[server]
# Server listening address
address = "0.0.0.0:8200"

# TLS configuration
tls_cert_file = "/etc/secreton/cert.pem"
tls_key_file = "/etc/secreton/key.pem"
tls_ca_file = "/etc/secreton/ca.pem"

# Server timeouts
read_timeout = 30
write_timeout = 30

# Maximum request size (bytes)
max_request_size = 33554432  # 32MB

# CORS configuration
[cors]
enabled = true
allowed_origins = ["https://admin.example.com"]
allowed_headers = ["X-Vault-Token", "Content-Type"]
allow_credentials = true
```

### Storage Configuration

#### PostgreSQL Storage
```toml
[storage]
type = "postgresql"

[storage.postgresql]
connection_url = "postgres://user:password@localhost:5432/secreton"
max_connections = 10
min_connections = 2
connection_timeout = 30
idle_timeout = 300
max_lifetime = 3600

# SSL configuration
ssl_mode = "require"
ssl_cert = "/etc/secreton/db-cert.pem"
ssl_key = "/etc/secreton/db-key.pem"
ssl_root_cert = "/etc/secreton/db-ca.pem"
```

#### MySQL Storage
```toml
[storage]
type = "mysql"

[storage.mysql]
connection_url = "mysql://user:password@localhost:3306/secreton"
max_connections = 10
min_connections = 2

# Connection pool settings
connection_timeout = 30
idle_timeout = 300
max_lifetime = 3600
```

#### Redis Storage
```toml
[storage]
type = "redis"

[storage.redis]
url = "redis://localhost:6379"
connection_pool_size = 5
read_timeout = 30
write_timeout = 30

# Sentinel configuration (optional)
[sentinel]
masters = ["redis-master"]
endpoints = ["redis-sentinel-1:26379", "redis-sentinel-2:26379"]
```

#### etcd Storage
```toml
[storage]
type = "etcd"

[storage.etcd]
endpoints = ["http://localhost:2379"]
username = "secreton"
password = "secret"
connection_timeout = 30
request_timeout = 30

# TLS configuration
tls_cert_file = "/etc/secreton/etcd-cert.pem"
tls_key_file = "/etc/secreton/etcd-key.pem"
tls_ca_file = "/etc/secreton/etcd-ca.pem"
```

#### Consul Storage
```toml
[storage]
type = "consul"

[storage.consul]
address = "127.0.0.1:8500"
scheme = "https"
token = "consul-token"
datacenter = "dc1"

# TLS configuration
tls_cert_file = "/etc/secreton/consul-cert.pem"
tls_key_file = "/etc/secreton/consul-key.pem"
tls_ca_file = "/etc/secreton/consul-ca.pem"
```

#### S3 Storage
```toml
[storage]
type = "s3"

[storage.s3]
bucket = "secreton-storage"
region = "us-east-1"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
endpoint = "https://s3.us-east-1.amazonaws.com"

# Additional options
force_path_style = false
disable_ssl = false
max_retries = 3
```

#### DynamoDB Storage
```toml
[storage]
type = "dynamodb"

[storage.dynamodb]
region = "us-east-1"
table_name = "secreton-storage"
access_key = "AKIAIOSFODNN7EXAMPLE"
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
endpoint = "https://dynamodb.us-east-1.amazonaws.com"

# Performance settings
read_capacity = 5
write_capacity = 5
```

#### Azure Blob Storage
```toml
[storage]
type = "azure_blob"

[storage.azure_blob]
account_name = "secretonstorage"
account_key = "account-key"
container_name = "vault-data"
endpoint = "https://secretonstorage.blob.core.windows.net"

# Performance settings
max_retries = 3
retry_delay = 1
```

### Authentication Configuration

```toml
[auth]
# Default lease TTL for tokens (seconds)
default_lease_ttl = 3600

# Maximum lease TTL for tokens (seconds)
max_lease_ttl = 86400

# Token type (service or batch)
token_type = "service"

# Enable identity system
identity_enabled = true

# MFA configuration
[mfa]
enabled = true
default_method = "totp"
issuer = "Secreton"
```

### Secret Engine Configuration

#### PKI Engine
```toml
[secrets.pki]
# Default certificate TTL
default_lease_ttl = 21600  # 6 hours

# Maximum certificate TTL
max_lease_ttl = 31536000  # 1 year

# Root CA certificate
root_ca_cert = "/etc/secreton/ca.pem"
root_ca_key = "/etc/secreton/ca-key.pem"

# CRL configuration
crl_disable = false
crl_distribution_points = ["http://crl.example.com/pki/crl"]

# OCSP configuration
ocsp_disable = false
ocsp_servers = ["http://ocsp.example.com"]
```

#### Transit Engine
```toml
[secrets.transit]
# Default key type for new keys
default_key_type = "aes256-gcm96"

# Cache configuration
[secrets.transit.cache]
size = 1000
ttl = 300

# Key derivation settings
[secrets.transit.derived]
enabled = true
bits = 256
```

### Audit Configuration

```toml
[audit]
# Enable audit logging
enabled = true

# Audit log format
format = "json"

# Audit log path
path = "/var/log/secreton/audit.log"

# Log raw requests/responses (security risk)
log_raw = false

# Filter sensitive headers
filter_headers = ["X-Vault-Token", "Authorization"]
```

### Telemetry Configuration

```toml
[telemetry]
# Enable Prometheus metrics
prometheus_enabled = true
metrics_path = "/metrics"

# Enable statsd metrics
statsd_enabled = false
statsd_address = "localhost:8125"

# Enable dogstatsd tags
dogstatsd_tags = ["env:production", "service:secreton"]

# Performance monitoring
[telemetry.performance]
enabled = true
gauges = ["vault.core.handle_request"]
counters = ["vault.barrier.get", "vault.barrier.put"]
```

### Replication Configuration

```toml
[replication]
# Enable replication
enabled = false

# Replication mode (primary or secondary)
mode = "primary"

# Primary cluster address
primary_address = "https://primary.secreton.com:8200"

# Replication token
token = "replication-token"

# Performance settings
[replication.performance]
max_parallel_operations = 10
batch_size = 100
```

## Environment Variables

Secreton supports configuration via environment variables:

```bash
# Server configuration
export SECRETON_SERVER_ADDRESS="0.0.0.0:8200"
export SECRETON_TLS_CERT_FILE="/etc/secreton/cert.pem"
export SECRETON_TLS_KEY_FILE="/etc/secreton/key.pem"

# Storage configuration
export SECRETON_STORAGE_TYPE="postgresql"
export SECRETON_STORAGE_POSTGRESQL_CONNECTION_URL="postgres://..."

# Authentication
export SECRETON_AUTH_DEFAULT_LEASE_TTL="3600"

# Logging
export RUST_LOG="secreton=info"
```

## Command Line Flags

```bash
secreton server \
  --config=config/default.toml \
  --address=0.0.0.0:8200 \
  --tls-cert-file=/etc/secreton/cert.pem \
  --tls-key-file=/etc/secreton/key.pem \
  --storage-type=postgresql \
  --storage-postgresql-connection-url="postgres://..." \
  --log-level=info
```

## Advanced Configuration

### High Availability

```toml
[ha]
# Enable high availability
enabled = true

# Cluster configuration
[ha.cluster]
name = "secreton-cluster"
node_id = "node-01"
api_addr = "https://node-01.secreton.com:8200"

# Raft configuration (for integrated storage)
[ha.raft]
enabled = true
data_dir = "/var/lib/secreton/raft"
snapshot_threshold = 8192
trailing_logs = 10240

# Peer addresses
peers = [
  "https://node-01.secreton.com:8200",
  "https://node-02.secreton.com:8200",
  "https://node-03.secreton.com:8200"
]
```

### Security Hardening

```toml
[security]
# Disable mlock (may require root)
disable_mlock = false

# Entropy augmentation
[security.entropy]
augmentation = "linux-getrandom"

# FIPS compliance
fips_enabled = false

# TLS cipher suites
[security.tls]
cipher_suites = [
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
]

# Certificate validation
strict_client_cert_verification = true
```

### Performance Tuning

```toml
[performance]
# Worker threads
worker_threads = 4

# Connection limits
max_concurrent_requests = 1000

# Cache configuration
[performance.cache]
enabled = true
size = 10000
ttl = 300

# Database connection pooling
[performance.database]
max_connections = 20
min_connections = 5
connection_timeout = 30
idle_timeout = 300
```

## Configuration Validation

Secreton validates configuration on startup:

```bash
# Validate configuration file
secreton server --config=config/default.toml --validate

# Check for deprecated options
secreton server --config=config/default.toml --check-deprecated
```

## Configuration Reloading

Some configuration options can be reloaded without restart:

```bash
# Reload authentication configuration
secreton reload auth

# Reload audit configuration
secreton reload audit

# Reload all configurations
secreton reload
```

## Troubleshooting

### Common Configuration Issues

1. **Storage Connection Failed**
   - Check connection URLs
   - Verify credentials
   - Check network connectivity
   - Review firewall rules

2. **TLS Certificate Errors**
   - Verify certificate paths
   - Check certificate validity
   - Ensure proper permissions
   - Validate certificate chain

3. **Performance Issues**
   - Monitor connection pools
   - Check cache hit rates
   - Review worker thread utilization
   - Analyze audit log volume

### Debug Configuration

```toml
[debug]
# Enable debug logging
enabled = true

# Debug endpoints
[debug.endpoints]
pprof_enabled = true
metrics_enabled = true

# Memory profiling
[debug.memory]
enabled = true
sample_rate = 1000

# CPU profiling
[debug.cpu]
enabled = true
profile_duration = 30
```

### Logging Configuration

```toml
[logging]
# Log level
level = "info"

# Log format (json or text)
format = "json"

# Log file
file = "/var/log/secreton/secreton.log"

# Log rotation
[logging.rotation]
enabled = true
max_size = 100  # MB
max_files = 10

# Structured logging fields
[logging.fields]
include_timestamp = true
include_level = true
include_module = true
include_file = true
include_line = true
```

## Production Checklist

- [ ] TLS certificates configured and valid
- [ ] Storage backend properly configured and tested
- [ ] Authentication methods configured
- [ ] Audit logging enabled
- [ ] Telemetry/monitoring configured
- [ ] Backup strategy implemented
- [ ] Security hardening applied
- [ ] Performance tuning completed
- [ ] High availability configured (if needed)
- [ ] Disaster recovery plan documented