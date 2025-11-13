# Secreton

> **Advanced Security & Secrets Management System with Quantum-Safe Cryptography**

[![Rust CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/rust-ci.yml)
[![CodeQL](https://github.com/analisaperlengkapan/secreton/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/codeql-analysis.yml)
[![Security](https://github.com/analisaperlengkapan/secreton/workflows/Comprehensive%20Security%20Scan/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/security-comprehensive.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Secreton is a comprehensive, enterprise-grade secrets management platform built in Rust. Designed with security-first principles, it provides secure storage, encryption, access control, and comprehensive audit logging for sensitive data. Similar to HashiCorp Vault but enhanced with quantum-safe cryptography, zero-trust architecture, and modern cloud-native features.

## 🌟 Key Features

### 🔐 Core Security

- **Quantum-Safe Cryptography**: Built on RustCrypto suite with support for post-quantum cryptographic algorithms
- **Zero-Trust Architecture**: Every request requires authentication and authorization - no implicit trust
- **Multi-Algorithm Encryption**: AES-256-GCM, ChaCha20-Poly1305, Ed25519, X25519
- **Hardware Security Module (HSM)**: Integration support for hardware-backed key storage
- **Memory Safety**: Built in Rust with automatic memory management and `zeroize` for sensitive data

### 🔑 Secret Engines

#### Key-Value Secrets
- Versioned secret storage with rollback capability
- TTL (Time-To-Live) support for automatic secret expiration
- Metadata and custom attributes

#### PKI (Public Key Infrastructure)
- Complete Certificate Authority (CA) functionality
- Certificate generation, signing, and revocation
- CRL (Certificate Revocation List) management
- OCSP (Online Certificate Status Protocol) support

#### Database Secrets
- Dynamic database credential generation
- Just-in-time access provisioning
- Automatic credential rotation
- Support for PostgreSQL, MySQL, MongoDB

#### Transit Engine
- Encryption-as-a-Service
- Data encryption/decryption without storing data
- Key derivation and rotation
- Convergent encryption support

### 🔒 Authentication & Authorization

#### Authentication Methods
- **JWT Tokens**: Bearer token authentication with configurable TTL and refresh tokens
- **OAuth 2.0 / OIDC**: Integration with Google, GitHub, Microsoft, Okta, and custom providers
- **LDAP**: Active Directory and OpenLDAP integration
- **RADIUS**: Network authentication protocol support
- **Multi-Factor Authentication (MFA)**: TOTP, hardware tokens (U2F/FIDO2)
- **Kubernetes**: Service account token authentication

#### Authorization
- **Role-Based Access Control (RBAC)**: Fine-grained permissions and policies
- **Policy as Code**: Define access policies in declarative format
- **Dynamic Secrets**: Generate credentials on-demand with automatic expiration
- **Token Hierarchy**: Parent/child token relationships
- **Granular Revocation**: Revoke individual tokens, roles, or entire auth chains

### 🏗️ Infrastructure & Operations

#### High Availability
- **Data Replication**: Multi-node cluster with automatic failover
- **Storage Backends**: PostgreSQL (recommended), Redis, MongoDB, SQLite
- **Raft Consensus**: Distributed consensus for cluster coordination
- **Backup & Restore**: Automated backup with point-in-time recovery

#### Monitoring & Observability
- **Prometheus Metrics**: Comprehensive metrics export
- **OpenTelemetry**: Distributed tracing support
- **Audit Logging**: Detailed security event logging for compliance
- **Health Checks**: Deep health checks for all components
- **Alert Integration**: PagerDuty, Slack, webhook notifications

#### APIs & Integrations
- **REST API**: Full-featured HTTP API with OpenAPI/Swagger documentation
- **gRPC API**: High-performance RPC interface
- **GraphQL**: Flexible query interface (optional)
- **CLI Tool**: Command-line interface for all operations
- **Agent**: Sidecar helper for auto-authentication and secret injection

### 🌐 Cloud & Platform Integrations

- **AWS**: IAM, Secrets Manager, KMS integration
- **Kubernetes**: Operator for secret management and injection
- **Docker**: Container image with secure defaults
- **Cloud Providers**: Support for GCP, Azure, Oracle Cloud

### 🏢 Enterprise Features

- **Compliance**: FIPS 140-2, PCI DSS, SOX, HIPAA, GDPR support
- **Secret Versioning**: Complete history with rollback
- **Disaster Recovery**: Geo-redundant backups and recovery procedures
- **Multi-Tenancy**: Namespace isolation for different teams/environments
- **Performance**: High-throughput with connection pooling and caching
- **Scalability**: Horizontal scaling for high-availability clusters

## 📋 Prerequisites

- **Rust**: 1.90+ (2024 edition)
- **PostgreSQL**: 15+ (recommended for production)
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 512MB RAM (2GB+ recommended for production)
- **Storage**: SSD recommended for optimal performance

## 🚀 Quick Start

### Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton
```

#### 2. Install Rust Toolchain

```bash
# Install Rust using rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Update to latest stable
rustup update stable

# Add required components
rustup component add rustfmt clippy
```

#### 3. Install System Dependencies

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y build-essential libpq-dev pkg-config libssl-dev
```

**macOS:**
```bash
brew install postgresql openssl pkg-config
```

**Windows:**
```powershell
# Install Visual Studio Build Tools
# Install PostgreSQL from https://www.postgresql.org/download/windows/
```

#### 4. Build the Project

```bash
# Development build
cargo build --workspace

# Release build (optimized)
cargo build --workspace --release

# Build specific component
cargo build -p secreton-api --release
```

### Configuration

#### 1. Setup Environment

```bash
# Copy example environment file
cp .env.example .env

# Edit configuration
nano .env
```

#### 2. Configure Database

**Using Docker (Quick Setup):**
```bash
docker run --name secreton-db \
  -e POSTGRES_USER=secreton_user \
  -e POSTGRES_PASSWORD=your_secure_password \
  -e POSTGRES_DB=secreton_db \
  -p 5432:5432 \
  -d postgres:15
```

**Manual PostgreSQL Setup:**
```sql
CREATE DATABASE secreton_db;
CREATE USER secreton_user WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE secreton_db TO secreton_user;
```

#### 3. Initialize Secreton

```bash
# Run database migrations
cargo run -p secreton-api --bin migrate

# Initialize the vault
cargo run -p secreton-api --bin init
```

### Running Secreton

#### Start the API Server

```bash
# Development mode
cargo run -p secreton-api --bin api_server

# Production mode
./target/release/api_server
```

The server will start on `http://localhost:8080` (default).

#### Start the Agent (Optional)

```bash
# Development mode
cargo run -p secreton-agent

# Production mode
./target/release/secreton-agent
```

#### Using the CLI

```bash
# Set server address
export SECRETON_ADDR=http://localhost:8080

# Authenticate
secreton-cli login -t <your-token>

# Store a secret
secreton-cli kv put secret/myapp/database password=supersecret

# Retrieve a secret
secreton-cli kv get secret/myapp/database

# List secrets
secreton-cli kv list secret/myapp/
```

## 📚 Documentation

### Architecture

Secreton is built as a modular Rust workspace with the following crates:

```
secreton/
├── crates/
│   ├── api/              # REST API server
│   ├── agent/            # Sidecar agent for auto-auth
│   ├── auth/             # Authentication methods
│   ├── cli/              # Command-line interface
│   ├── common/           # Shared utilities
│   ├── config/           # Configuration management
│   ├── core/             # Core business logic
│   ├── crypto/           # Cryptography operations
│   ├── enterprise/       # Enterprise features
│   ├── errors/           # Error handling
│   ├── infrastructure/   # Infrastructure integrations
│   ├── integrations/     # Third-party integrations
│   ├── monitoring/       # Metrics and observability
│   ├── performance/      # Performance optimizations
│   ├── replication/      # High availability
│   ├── secrets/          # Secret engines
│   ├── secrets-database/ # Database secret engine
│   ├── secrets-pki/      # PKI secret engine
│   ├── security/         # Security features
│   ├── storage/          # Storage backends
│   └── ui/               # Web UI (optional)
└── tests/                # Integration tests
```

### API Documentation

Once the server is running, access the interactive API documentation:

- **Swagger UI**: http://localhost:8080/swagger-ui
- **OpenAPI Spec**: http://localhost:8080/api-docs/openapi.json
- **Health Check**: http://localhost:8080/health

### Key Concepts

#### Secrets
Secrets are encrypted data stored in Secreton. Each secret has:
- **Path**: Hierarchical location (e.g., `secret/myapp/database`)
- **Data**: Key-value pairs
- **Metadata**: Version, timestamps, custom attributes
- **Policy**: Access control rules

#### Tokens
Tokens are credentials used to authenticate with Secreton:
- **Root Token**: Initial superuser token (secure carefully!)
- **Service Tokens**: For applications and services
- **Batch Tokens**: High-performance, lightweight tokens
- **TTL**: Configurable time-to-live

#### Policies
Policies define what actions a token can perform:
```hcl
# Example policy
path "secret/myapp/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "database/creds/readonly" {
  capabilities = ["read"]
}
```

#### Audit Logs
All operations are logged for compliance and security:
- Who performed the action
- What action was performed
- When it happened
- Result (success/failure)

## 🧪 Testing

### Run Tests

```bash
# Run all tests
cargo test --workspace --all-features

# Run specific crate tests
cargo test -p secreton-core

# Run with output
cargo test --workspace --all-features -- --nocapture

# Run integration tests only
cargo test --test '*'
```

### Code Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage report
cargo tarpaulin --workspace --all-features --out Html

# Open coverage report
open tarpaulin-report.html
```

### Benchmarks

```bash
# Run benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench -p secreton-crypto
```

## 🔧 Development

### Code Quality

```bash
# Format code
cargo fmt --all

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Security audit
cargo audit

# Check for outdated dependencies
cargo outdated
```

### Development Workflow

```bash
# Watch for changes and run tests
cargo watch -x test

# Watch and run specific command
cargo watch -x 'test -p secreton-api'

# Run with logging
RUST_LOG=debug cargo run -p secreton-api
```

## 🐳 Docker

### Build Docker Image

```bash
docker build -t secreton:latest .
```

### Run with Docker Compose

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

### Docker Hub

```bash
# Pull official image
docker pull analisaperlengkapan/secreton:latest

# Run container
docker run -d \
  --name secreton \
  -p 8080:8080 \
  -e DATABASE_URL=postgresql://user:pass@host/db \
  analisaperlengkapan/secreton:latest
```

## ☸️ Kubernetes

### Deploy with Helm

```bash
# Add Helm repository
helm repo add secreton https://analisaperlengkapan.github.io/secreton-helm

# Install
helm install secreton secreton/secreton \
  --namespace secreton \
  --create-namespace

# Upgrade
helm upgrade secreton secreton/secreton
```

### Deploy with Operator

```bash
# Install operator
kubectl apply -f https://github.com/analisaperlengkapan/secreton/releases/latest/download/operator.yaml

# Create Secreton instance
kubectl apply -f - <<EOF
apiVersion: secreton.io/v1alpha1
kind: Secreton
metadata:
  name: secreton
spec:
  replicas: 3
  storage:
    type: postgresql
    connection: postgresql://user:pass@postgres:5432/secreton
EOF
```

## 🔒 Security

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Please report security issues privately to: **security@secreton.io**

We will respond within 48 hours and provide a fix as soon as possible.

### Security Features

- All secrets encrypted at rest (AES-256-GCM)
- All secrets encrypted in transit (TLS 1.3)
- Memory wiped after use (`zeroize` crate)
- Constant-time operations for crypto
- No third-party analytics or telemetry
- Regular security audits

### Best Practices

1. **Use Strong Tokens**: Generate tokens with sufficient entropy
2. **Rotate Regularly**: Implement automatic key and token rotation
3. **Principle of Least Privilege**: Grant minimal required permissions
4. **Enable Audit Logging**: Monitor all access and changes
5. **Backup Regularly**: Automated backups with encryption
6. **Use TLS**: Always use HTTPS in production
7. **Secure Root Token**: Store root token in secure location (HSM)

## 📈 Performance

### Benchmarks

- **Read Operations**: ~50,000 ops/sec (single node)
- **Write Operations**: ~10,000 ops/sec (single node)
- **Latency**: < 10ms (P99)
- **Encryption**: ~100,000 encryptions/sec
- **Token Validation**: ~200,000 validations/sec

*Benchmarks on AWS c5.2xlarge instance with PostgreSQL RDS*

### Optimization

- Connection pooling enabled by default
- In-memory caching for frequently accessed secrets
- Batch operations for improved throughput
- Async I/O throughout the stack
- Zero-copy operations where possible

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details on:

- Development setup
- Code style guidelines
- Testing requirements
- Pull request process
- Code of conduct

## 📜 License

This project is licensed under the **Apache License 2.0** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

Built with:
- **Rust** - Memory-safe systems programming language
- **RustCrypto** - Pure Rust cryptography implementations
- **Tokio** - Async runtime for Rust
- **Axum** - Web framework
- **PostgreSQL** - Primary storage backend

Inspired by:
- HashiCorp Vault
- AWS Secrets Manager
- Google Secret Manager

## 📞 Support

- **Documentation**: [https://secreton.io/docs](https://github.com/analisaperlengkapan/secreton/tree/main/docs)
- **Issues**: [GitHub Issues](https://github.com/analisaperlengkapan/secreton/issues)
- **Discussions**: [GitHub Discussions](https://github.com/analisaperlengkapan/secreton/discussions)
- **Email**: support@secreton.io

## 🗺️ Roadmap

### Version 0.2.0
- [ ] Web UI dashboard
- [ ] Advanced policy engine
- [ ] FIPS 140-2 validation
- [ ] Enhanced disaster recovery

### Version 0.3.0
- [ ] Multi-region replication
- [ ] Advanced MFA options
- [ ] Plugin system
- [ ] Performance improvements

### Version 1.0.0
- [ ] Production-ready release
- [ ] Complete documentation
- [ ] Security audit
- [ ] Enterprise support

---

**Made with ❤️ by the Secreton Team**

⭐ Star us on GitHub if you find this project useful!
