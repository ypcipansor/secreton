# 🔐 Secreton

[![CI](https://github.com/analisaperlengkapan/secreton/workflows/CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.90+-orange.svg)](https://www.rust-lang.org)
[![Security Rating](https://img.shields.io/badge/security-A%2B-brightgreen)](https://github.com/analisaperlengkapan/secreton)

**Secreton** is an enterprise-grade vault system providing advanced security with quantum-safe cryptography, zero-trust architecture, and comprehensive secret management capabilities. Built in Rust for memory safety and performance, Secreton offers a modern alternative to traditional vault systems.

## ✨ Key Features

### 🔒 Security-First Design
- **Quantum-Safe Cryptography**: Post-quantum algorithms ready for the future
- **Zero-Trust Architecture**: Security by default with comprehensive RBAC
- **Memory Safety**: Built in Rust with zero C dependencies
- **Audited Crypto Stack**: Uses RustCrypto suite (audited, memory-safe)
- **HSM Integration**: Hardware security module support

### 🔐 Authentication Methods
- **Token-based**: Built-in token authentication
- **User/Password**: Traditional credentials
- **LDAP/Active Directory**: Enterprise directory integration
- **OIDC/OAuth2**: Modern identity providers (Google, GitHub, Microsoft, Okta)
- **Kubernetes**: Service account authentication
- **AWS IAM**: Cloud provider authentication
- **Certificate**: X.509 certificate authentication
- **RADIUS**: Network authentication
- **SAML**: Enterprise SSO

### 🗄️ Secret Engines
- **KV v2**: Versioned key-value storage with rollback
- **Transit**: Encryption-as-a-service with key management
- **Database**: Dynamic database credentials
- **PKI**: Certificate authority and management
- **SSH**: SSH key signing and management
- **TOTP**: Time-based one-time passwords
- **Cloud Integrations**: AWS, Azure, GCP secret management

### 🚀 Enterprise Features
- **High Availability**: Raft-based clustering
- **Disaster Recovery**: Automated backup and replication
- **Audit Logging**: Comprehensive security audit trails
- **Compliance**: NIST, SOX, GDPR compliance frameworks
- **Monitoring**: Prometheus metrics and OpenTelemetry
- **Multi-Region**: Geographic distribution support

## 🚀 Quick Start

### Prerequisites

- **Rust** 1.90 or higher
- **PostgreSQL** 12+ (recommended) or SQLite for development
- **Linux/macOS/Windows** support

### Installation

#### Option 1: Build from Source

```bash
# Clone the repository
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

# Build all components
cargo build --workspace --release

# Install CLI tool
cargo install --path crates/cli

# Install API server
cargo install --path crates/api

# Install agent
cargo install --path crates/agent
```

#### Option 2: Download Pre-built Binaries

```bash
# Download for your platform
wget https://github.com/analisaperlengkapan/secreton/releases/latest/download/secreton-linux-x64.tar.gz
tar -xzf secreton-linux-x64.tar.gz
sudo cp secreton-* /usr/local/bin/
```

### Basic Setup

1. **Initialize Configuration**
   ```bash
   # Copy default configuration
   cp config/default.toml config/local.toml
   
   # Edit configuration
   nano config/local.toml
   ```

2. **Setup Database**
   ```bash
   # PostgreSQL (recommended)
   createdb secreton_db
   createuser secreton_user
   psql -c "ALTER USER secreton_user PASSWORD 'secure_password';"
   psql -c "GRANT ALL PRIVILEGES ON DATABASE secreton_db TO secreton_user;"
   ```

3. **Start the Server**
   ```bash
   # Start API server
   secreton-api --config config/local.toml
   
   # Or use Docker
   docker run -d --name secreton \
     -v $(pwd)/config:/app/config \
     -v $(pwd)/data:/app/data \
     -p 8200:8200 \
     secreton:latest
   ```

4. **Verify Installation**
   ```bash
   # Check health
   curl http://localhost:8200/health
   
   # Expected response
   {
     "success": true,
     "data": {
       "status": "healthy",
       "version": "0.1.0",
       "service": "secreton-api"
     }
   }
   ```

## 📖 Comprehensive Usage Guide

### 1. Server Configuration

#### Basic Configuration (`config/local.toml`)

```toml
[server]
host = "127.0.0.1"
port = 8200
log_level = "info"
storage_path = "./data"

[database]
url = "postgresql://secreton_user:secure_password@localhost:5432/secreton_db"
max_connections = 20
min_connections = 5

[auth]
token_ttl = 3600  # 1 hour
refresh_token_ttl = 2592000  # 30 days
jwt_secret = "your-secure-random-secret-here"

[security]
default_auth_method = "token"
auth_methods = ["token", "userpass", "ldap"]
audit_enabled = true
```

#### High Availability Configuration

```toml
[storage]
backend_type = "raft"
node_id = "secreton-node-1"
data_dir = "./data/raft"
bind_addr = "127.0.0.1:8201"
advertise_addr = "127.0.0.1:8201"
peers = ["node2:8201", "node3:8201"]

[storage.raft]
snapshot_enabled = true
snapshot_interval_secs = 120
log_retention_count = 10000
```

### 2. Authentication Setup

#### Token Authentication

```bash
# Create initial root token
curl -X POST http://localhost:8200/auth/token/create \
  -H "X-Vault-Token: your-root-token" \
  -d '{
    "policies": ["root"],
    "ttl": "24h",
    "renewable": true
  }'
```

#### User/Password Authentication

```bash
# Enable userpass auth
curl -X POST http://localhost:8200/auth/userpass enable \
  -H "X-Vault-Token: your-root-token"

# Create user
curl -X POST http://localhost:8200/auth/userpass/users/john \
  -H "X-Vault-Token: your-root-token" \
  -d '{
    "password": "secure-password",
    "policies": ["default", "developer"]
  }'

# Login
curl -X POST http://localhost:8200/auth/userpass/login/john \
  -d '{
    "password": "secure-password"
  }'
```

#### LDAP Authentication

```bash
# Configure LDAP
curl -X POST http://localhost:8200/auth/ldap/config \
  -H "X-Vault-Token: your-root-token" \
  -d '{
    "url": "ldap://ldap.example.com",
    "bind_dn": "cn=vault,ou=users,dc=example,dc=com",
    "bind_pass": "ldap-password",
    "user_dn": "ou=users,dc=example,dc=com",
    "user_filter": "(cn={{.Username}})",
    "group_dn": "ou=groups,dc=example,dc=com",
    "group_filter": "(member:1.2.840.113556.1.4.1941:={{.UserDN}})"
  }'
```

### 3. Secret Management

#### KV v2 Store

```bash
# Store a secret
curl -X POST http://localhost:8200/v1/secret/data/myapp/config \
  -H "X-Vault-Token: your-token" \
  -d '{
    "data": {
      "database_url": "postgresql://user:pass@db:5432/app",
      "api_key": "sk-1234567890abcdef",
      "debug": "true"
    }
  }'

# Retrieve a secret
curl -X GET http://localhost:8200/v1/secret/data/myapp/config \
  -H "X-Vault-Token: your-token"

# List secrets
curl -X LIST http://localhost:8200/v1/secret/metadata \
  -H "X-Vault-Token: your-token"

# Delete a secret
curl -X DELETE http://localhost:8200/v1/secret/data/myapp/config \
  -H "X-Vault-Token: your-token"
```

#### Versioning and Rollback

```bash
# Get secret versions
curl -X GET http://localhost:8200/v1/secret/metadata/myapp/config \
  -H "X-Vault-Token: your-token"

# Restore previous version
curl -X POST http://localhost:8200/v1/secret/restore/myapp/config \
  -H "X-Vault-Token: your-token" \
  -d '{
    "versions": [2]
  }'
```

### 4. Transit Encryption Engine

#### Key Management

```bash
# Create encryption key
curl -X POST http://localhost:8200/v1/transit/keys/myapp-key \
  -H "X-Vault-Token: your-token" \
  -d '{
    "type": "aes256-gcm",
    "exportable": false
  }'

# List keys
curl -X GET http://localhost:8200/v1/transit/keys \
  -H "X-Vault-Token: your-token"

# Rotate key
curl -X POST http://localhost:8200/v1/transit/keys/myapp-key/rotate \
  -H "X-Vault-Token: your-token"
```

#### Encryption/Decryption

```bash
# Encrypt data
curl -X POST http://localhost:8200/v1/transit/encrypt/myapp-key \
  -H "X-Vault-Token: your-token" \
  -d '{
    "plaintext": "dGhpcyBpcyBhIHNlY3JldA==",
    "context": "c29tZS1jb250ZXh0"
  }'

# Decrypt data
curl -X POST http://localhost:8200/v1/transit/decrypt/myapp-key \
  -H "X-Vault-Token: your-token" \
  -d '{
    "ciphertext": "vault:v1:abc123...",
    "context": "c29tZS1jb250ZXh0"
  }'

# Sign data
curl -X POST http://localhost:8200/v1/transit/sign/myapp-key \
  -H "X-Vault-Token: your-token" \
  -d '{
    "input": "dGhpcyBpcyBzaWduZWQ=",
    "signature_algorithm": "sha2-256"
  }'
```

### 5. Database Secret Engine

#### Configuration

```bash
# Enable database engine
curl -X POST http://localhost:8200/v1/database/config/postgresql \
  -H "X-Vault-Token: your-token" \
  -d '{
    "plugin_name": "postgresql-database-plugin",
    "connection_url": "postgresql://{{username}}:{{password}}@db:5432/vault",
    "allowed_roles": ["readonly", "readwrite"],
    "username": "vault_user",
    "password": "vault_password"
  }'

# Create role
curl -X POST http://localhost:8200/v1/database/roles/readonly \
  -H "X-Vault-Token: your-token" \
  -d '{
    "db_name": "postgresql",
    "creation_statements": ["CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"],
    "default_ttl": "1h",
    "max_ttl": "24h"
  }'
```

#### Usage

```bash
# Generate credentials
curl -X GET http://localhost:8200/v1/database/creds/readonly \
  -H "X-Vault-Token: your-token"

# Renew credentials
curl -X POST http://localhost:8200/v1/database/lease/renew \
  -H "X-Vault-Token: your-token" \
  -d '{
    "lease_id": "database/creds/readonly/...",
    "increment": "12h"
  }'
```

### 6. PKI Certificate Authority

#### Setup CA

```bash
# Enable PKI engine
curl -X POST http://localhost:8200/v1/pki/root/generate/internal \
  -H "X-Vault-Token: your-token" \
  -d '{
    "common_name": "My Company CA",
    "ttl": "87600h",
    "key_type": "rsa",
    "key_bits": 4096
  }'

# Configure URLs
curl -X POST http://localhost:8200/v1/pki/config/urls \
  -H "X-Vault-Token: your-token" \
  -d '{
    "issuing_certificates": ["http://localhost:8200/v1/pki/ca"],
    "crl_distribution_points": ["http://localhost:8200/v1/pki/crl"]
  }'
```

#### Issue Certificates

```bash
# Create role
curl -X POST http://localhost:8200/v1/pki/roles/myapp \
  -H "X-Vault-Token: your-token" \
  -d '{
    "allowed_domains": ["myapp.example.com"],
    "allow_subdomains": true,
    "max_ttl": "72h",
    "key_bits": 2048
  }'

# Issue certificate
curl -X POST http://localhost:8200/v1/pki/issue/myapp \
  -H "X-Vault-Token: your-token" \
  -d '{
    "common_name": "web.myapp.example.com",
    "ttl": "24h"
  }'
```

## 🛠️ CLI Usage

The Secreton CLI provides a convenient command-line interface for common operations.

### Installation

```bash
cargo install --path crates/cli
```

### Basic Commands

```bash
# Check server status
secreton-cli status --server http://localhost:8200

# Transit operations
secreton-cli transit create-key myapp-key
secreton-cli transit list-keys
secreton-cli transit encrypt myapp-key --data "secret message"
secreton-cli transit decrypt myapp-key --data "vault:v1:..."

# Secret operations
secreton-cli secret put myapp/config data="value" api_key="secret"
secreton-cli secret get myapp/config
secreton-cli secret list
secreton-cli secret delete myapp/config
```

### Configuration

Create `~/.secreton/config.toml`:

```toml
server_url = "http://localhost:8200"
token = "your-vault-token"
timeout = 30
```

## 🤖 Agent Usage

The Secreton Agent provides auto-authentication, template rendering, and secret injection capabilities.

### Configuration (`agent.yaml`)

```yaml
server_url: "https://vault1:8200"
server_urls:
  - "https://vault1:8200"
  - "https://vault2:8200"

auth_method: userpass
auth_config:
  username: "myuser"
  password: "mypassword"

templates:
  - source: "secret/data/myapp/config"
    dest: "/etc/myapp/config.json"
    mode: "interval"
    
interval: 60
sink: "file,env,child"

log_file: "logs/agent.log"
log_format: "json"
audit_file: "logs/audit.log"

run:
  - "bash"
  - "start_myapp.sh"
  
notify:
  webhook: "https://hooks.slack.com/services/xxx"
  
restart_child: true
restart_delay: 5
```

### Running the Agent

```bash
# Build and run
cargo build --release -p secreton-agent
./target/release/secreton-agent --config agent.yaml

# Or with Docker
docker run -d --name secreton-agent \
  -v $(pwd)/agent.yaml:/app/agent.yaml \
  -v $(pwd)/templates:/app/templates \
  secreton-agent:latest
```

### Health Check

```bash
curl http://localhost:9900/healthz

# Response
{
  "status": "ok",
  "token_valid": true,
  "child_running": true,
  "last_error": null
}
```

## 🔧 Advanced Configuration

### Performance Tuning

```toml
[server]
max_request_size = "32MB"
request_timeout = "30s"
graceful_shutdown_timeout = "30s"

[database]
max_connections = 100
connection_timeout = 10
idle_timeout = 300
max_lifetime = 1800

[performance]
worker_threads = 4
max_blocking_threads = 512
```

### Security Hardening

```toml
[security]
mfa_required = true
password_policy = "strong"
session_timeout = 3600
max_login_attempts = 5
lockout_duration = 900

[tls]
enabled = true
cert_file = "/path/to/cert.pem"
key_file = "/path/to/key.pem"
ca_file = "/path/to/ca.pem"
verify_incoming = true
```

### Monitoring and Metrics

```toml
[monitoring]
prometheus_enabled = true
prometheus_address = "0.0.0.0:9090"
jaeger_enabled = true
jaeger_endpoint = "http://jaeger:14268/api/traces"

[logging]
level = "info"
format = "json"
file = "/var/log/secreton.log"
audit_file = "/var/log/secreton-audit.log"
```

## 📊 Monitoring and Observability

### Prometheus Metrics

Available at `http://localhost:9090/metrics`:

- `secreton_requests_total` - Total API requests
- `secreton_request_duration_seconds` - Request latency
- `secreton_active_tokens` - Active authentication tokens
- `secreton_secret_operations_total` - Secret operations
- `secreton_crypto_operations_total` - Cryptographic operations

### Health Endpoints

```bash
# Basic health
curl http://localhost:8200/health

# Detailed status
curl http://localhost:8200/security/status

# Security metrics
curl http://localhost:8200/security/metrics
```

### Audit Logs

Audit logs are written in JSONL format:

```json
{"timestamp":"2024-01-01T12:00:00Z","action":"authenticate","actor":"user1","status":"success","ip":"192.168.1.100"}
{"timestamp":"2024-01-01T12:01:00Z","action":"secret_read","actor":"user1","resource":"secret/data/app/config","status":"success"}
```

## 🐳 Docker Deployment

### Single Node

```yaml
# docker-compose.yml
version: '3.8'
services:
  secreton:
    image: secreton:latest
    ports:
      - "8200:8200"
    environment:
      - SECRETON_SERVER__HOST=0.0.0.0
      - SECRETON_SERVER__PORT=8200
      - SECRETON_DATABASE__URL=postgresql://postgres:password@db:5432/secreton
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    depends_on:
      - db
      
  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=secreton
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=password
    volumes:
      - postgres_data:/var/lib/postgresql/data

volumes:
  postgres_data:
```

### High Availability Cluster

```yaml
# docker-compose-ha.yml
version: '3.8'
services:
  secreton-1:
    image: secreton:latest
    ports: ["8200:8200", "8201:8201"]
    environment:
      - SECRETON_SERVER__HOST=0.0.0.0
      - SECRETON_STORAGE__BACKEND_TYPE=raft
      - SECRETON_STORAGE__NODE_ID=secreton-1
      - SECRETON_STORAGE__PEERS=secreton-2:8201,secreton-3:8201
    volumes: ["secreton-1-data:/app/data"]
    
  secreton-2:
    image: secreton:latest
    ports: ["8202:8200", "8203:8201"]
    environment:
      - SECRETON_STORAGE__NODE_ID=secreton-2
      - SECRETON_STORAGE__PEERS=secreton-1:8201,secreton-3:8201
    volumes: ["secreton-2-data:/app/data"]
    
  secreton-3:
    image: secreton:latest
    ports: ["8204:8200", "8205:8201"]
    environment:
      - SECRETON_STORAGE__NODE_ID=secreton-3
      - SECRETON_STORAGE__PEERS=secreton-1:8201,secreton-2:8201
    volumes: ["secreton-3-data:/app/data"]

volumes:
  secreton-1-data:
  secreton-2-data:
  secreton-3-data:
```

## ☸️ Kubernetes Deployment

### Basic Deployment

```yaml
# secreton-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secreton
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secreton
  template:
    metadata:
      labels:
        app: secreton
    spec:
      containers:
      - name: secreton
        image: secreton:latest
        ports:
        - containerPort: 8200
        - containerPort: 8201
        env:
        - name: SECRETON_SERVER__HOST
          value: "0.0.0.0"
        - name: SECRETON_DATABASE__URL
          valueFrom:
            secretKeyRef:
              name: secreton-db
              key: url
        volumeMounts:
        - name: data
          mountPath: /app/data
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: secreton-data
---
apiVersion: v1
kind: Service
metadata:
  name: secreton
spec:
  selector:
    app: secreton
  ports:
  - name: api
    port: 8200
    targetPort: 8200
  - name: raft
    port: 8201
    targetPort: 8201
  type: ClusterIP
```

### Agent as Sidecar

```yaml
# app-with-agent.yaml
apiVersion: v1
kind: Pod
metadata:
  name: myapp
spec:
  containers:
  - name: myapp
    image: myapp:latest
    env:
    - name: DATABASE_URL
      valueFrom:
        secretKeyRef:
          name: app-config
          key: database_url
    - name: API_KEY
      valueFrom:
        secretKeyRef:
          name: app-config
          key: api_key
    volumeMounts:
    - name: config
      mountPath: /etc/myapp
      
  - name: secreton-agent
    image: secreton-agent:latest
    env:
    - name: VAULT_ADDR
      value: "http://secreton:8200"
    - name: VAULT_ROLE
      value: "myapp-role"
    volumeMounts:
    - name: config
      mountPath: /etc/myapp
    - name: agent-config
      mountPath: /etc/secreton-agent
    command: ["/app/secreton-agent"]
    args: ["-config", "/etc/secreton-agent/config.yaml"]
    
  volumes:
  - name: config
    emptyDir: {}
  - name: agent-config
    configMap:
      name: secreton-agent-config
```

## 🔒 Security Best Practices

### Production Deployment

1. **Network Security**
   - Use TLS/mTLS for all communications
   - Deploy in private networks
   - Implement proper firewall rules

2. **Access Control**
   - Enable MFA for all users
   - Use principle of least privilege
   - Regular token rotation

3. **Data Protection**
   - Enable audit logging
   - Use HSM for key protection
   - Regular backup and recovery testing

4. **Monitoring**
   - Set up alerts for security events
   - Monitor failed authentication attempts
   - Track unusual access patterns

### Compliance

Secreton supports compliance with:
- **NIST Cybersecurity Framework**
- **SOC 2 Type II**
- **GDPR**
- **HIPAA**
- **PCI DSS**

## 🛠️ Development

### Building from Source

```bash
# Clone repository
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

# Install Rust
rustup update stable
rustup component add rustfmt clippy

# Build
cargo build --workspace --release

# Run tests
cargo test --workspace --all-features
```

### Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Architecture

Secreton follows a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   API Server    │    │   CLI Tool      │    │   Agent         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────────────────────────────────────────────────────┐
│                    Core Business Logic                          │
├─────────────────┬─────────────────┬─────────────────┬───────────┤
│   Auth          │   Secrets       │   Crypto        │   Storage  │
└─────────────────┴─────────────────┴─────────────────┴───────────┘
```

## 📚 Documentation

- [API Reference](https://docs.secreton.com/api)
- [Configuration Guide](https://docs.secreton.com/config)
- [Security Guide](https://docs.secreton.com/security)
- [Deployment Guide](https://docs.secreton.com/deployment)

## 🤝 Community

- **Discord**: [Join our community](https://discord.gg/secreton)
- **GitHub**: [Report issues](https://github.com/analisaperlengkapan/secreton/issues)
- **Discussions**: [Join discussions](https://github.com/analisaperlengkapan/secreton/discussions)
- **Twitter**: [@SecretonVault](https://twitter.com/SecretonVault)

## 📄 License

Secreton is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full license text.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for memory safety
- Cryptography by [RustCrypto](https://github.com/RustCrypto)
- Inspired by [HashiCorp Vault](https://www.vaultproject.io/)
- Icons by [Feather Icons](https://feathericons.com/)

---

**Secreton** - Enterprise-grade security, built for the future. 🚀

If you find Secreton useful, please give us a ⭐ on GitHub!
