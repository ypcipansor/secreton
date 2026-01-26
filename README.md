# Secreton

> **Security & Secrets Management System built in Rust**

[![Rust CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/rust-ci.yml)
[![CodeQL](https://github.com/analisaperlengkapan/secreton/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/codeql-analysis.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

## ⚠️ Project Status: Alpha / Early Development

**Not Production Ready.** This is an actively developed, pre-1.0 project. The API, storage backends, and feature set are subject to breaking changes. Use only in development and testing environments.

**Current State:**
- Core architecture and module structure in place
- REST API with authentication/authorization working
- Multiple storage backends available (PostgreSQL, Redis, Raft, File)
- CLI tool functional
- Many enterprise/advanced features are scaffolded with partial implementations
- Test coverage exists but needs expansion

Secreton is a Rust-based secrets management platform designed with security-first principles. It aims to provide secure storage, encryption, access control, and audit logging for sensitive data.

## What's Implemented ✅

### Core Infrastructure
- **REST API** (Axum): Full-featured HTTP server with handlers for auth, secrets, admin functions
- **CLI Tool**: Command-line interface for managing secrets and configuration
- **Sidecar Agent**: Auto-authentication and secret injection capabilities
- **Modular Architecture**: 23 independent crates organized by domain (auth, storage, crypto, etc.)

### Authentication Methods
- **JWT/Token-based**: Bearer token authentication with TTL and refresh tokens
- **OAuth 2.0 / OIDC**: Integrations scaffolded (Google, GitHub, Microsoft, Okta)
- **LDAP/RADIUS**: Basic framework in place
- **Multi-Factor Authentication (MFA)**: Structure for TOTP, push notifications, SMS (partial)
- **Kubernetes Service Accounts**: Framework available
- **Certificate-based**: X.509 support (partial)

### Storage & Persistence
- **PostgreSQL**: Fully supported (recommended)
- **Redis**: Working backend with caching
- **In-Memory/File**: For development and testing
- **Raft Consensus**: Distributed consensus backend implemented
- **Planned**: MongoDB, MySQL, SQLite, S3, DynamoDB, Consul, FoundationDB (scaffolded but not implemented)

### Security Features
- **Data Encryption**: AES-256-GCM, ChaCha20-Poly1305 (via RustCrypto)
- **Key Management**: Ed25519, X25519 support
- **RBAC**: Role-based access control with policy engine
- **Audit Logging**: Security event tracking framework
- **Secret Versioning**: Rollback capability (enterprise crate)
- **Token Revocation**: Granular token/role revocation
- **Memory Safety**: Rust + zeroize for sensitive data

### Secret Engines
- **KV Secrets**: Versioned key-value storage with TTL
- **PKI**: Certificate Authority framework (scaffolded, partial implementation)
- **Database Secrets**: Dynamic credential generation (framework in place)
- **Transit**: Encryption-as-a-Service (framework in place)

### Observability
- **Prometheus Metrics**: Metrics collection framework
- **Tracing/Logging**: `tracing` crate integration
- **Health Checks**: Endpoint available
- **OpenTelemetry**: Support scaffolded

## What Needs Work / Is Partial ⚠️

- **PKI Engine**: CA functionality exists but not fully operationalized
- **Database Secrets**: Framework exists, backend implementations incomplete
- **Transit Engine**: Basic structure, not fully tested
- **Plugin System**: Architecture in place, not production-ready
- **Performance Standby/Replication**: Framework exists, needs testing at scale
- **Advanced MFA**: Push notifications, SMS scaffolded but limited
- **Cloud Integrations**: AWS, Azure, GCP - frameworks only, no real implementations
- **GraphQL API**: Basic structure, limited endpoint coverage
- **gRPC API**: Defined but minimal implementations
- **Web UI**: Leptos framework integrated but feature coverage limited
- **Kubernetes Operator**: No CRD or published operator

## Architecture Overview

Secreton is organized as a Rust workspace with domain-driven modules:

```
crates/
├── api/           - REST API server (Axum)
├── agent/         - Sidecar for auto-auth and templating
├── auth/          - Authentication methods & identity
├── cli/           - Command-line interface
├── common/        - Shared models and utilities
├── config/        - Configuration management
├── core/          - Core business logic
├── crypto/        - Cryptographic operations (RustCrypto)
├── enterprise/    - Enterprise features (versioning, replication)
├── errors/        - Error types and handling
├── infrastructure/- Infrastructure components (plugins, API gateway, performance standby)
├── integrations/  - Third-party integrations
├── monitoring/    - Metrics and observability
├── performance/   - Performance optimizations
├── replication/   - High availability and replication
├── secrets/       - Secret engine interfaces
├── secrets-database/ - Database secret engine
├── secrets-pki/   - PKI secret engine
├── security/      - Security policies and audit
├── storage/       - Storage backend abstraction
├── ui/            - Web UI (Leptos)
├── graphql/       - GraphQL API layer
└── grpc/          - gRPC service definitions
```

**Total**: 417 Rust files across 23 crates, ~8,600 lines of code in lib.rs alone

## Prerequisites

- **Rust**: 1.90+ (2024 edition)
- **PostgreSQL**: 15+ (recommended), or SQLite for development
- **Operating System**: Linux (primary), macOS, or Windows (WSL2)
- **Memory**: 512MB minimum, 2GB+ recommended
- **Cargo**: Latest stable version

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton
cargo build --workspace --release
```

### 2. Start Database

**Using Docker (recommended for dev):**
```bash
docker run -d --name secreton-db \
  -e POSTGRES_USER=secreton_user \
  -e POSTGRES_PASSWORD=secreton_pass \
  -e POSTGRES_DB=secreton_db \
  -p 5432:5432 \
  postgres:15
```

**Or use SQLite (simpler):**
```bash
export DATABASE_URL=sqlite:///./secreton.db
```

### 3. Run the API Server

```bash
cargo run -p secreton-api --release --bin api_server
```

The API starts at `http://localhost:8080`.

### 4. Basic Commands

```bash
# Health check
curl http://localhost:8080/health

# List endpoints (via OpenAPI)
curl http://localhost:8080/api/openapi.json

# Get config
curl http://localhost:8080/admin/config
```

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace --all-features

# Run specific crate tests
cargo test -p secreton-api
cargo test -p secreton-crypto
cargo test -p secreton-storage

# Run with output
cargo test --workspace -- --nocapture
```

### Code Quality

```bash
# Format
cargo fmt --all

# Lint
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Check compilation
cargo check --workspace --all-features
```

## Core Concepts

### Secrets
Encrypted data stored in Secreton with:
- **Path**: Hierarchical namespace (e.g., `secret/db/password`)
- **Data**: Key-value pairs (encrypted)
- **Metadata**: Version, timestamps, owner, tags
- **TTL**: Optional expiration time

### Tokens
Credentials for authentication:
- **Bearer Tokens**: JWT-based authentication
- **Refresh Tokens**: Extend session without re-authentication
- **Root Token**: Initial setup only (treat as root password)
- **Scope**: Permissions defined by associated policies

### Policies
Access control rules (similar to RBAC):
```
path "secret/app/*" {
  capabilities = ["read", "list"]
}
path "secret/app/admin" {
  capabilities = ["read", "write", "delete"]
}
```

### Audit Trail
All operations logged with:
- User/token that performed action
- Operation type and path
- Timestamp and result
- Source IP and user agent

## Known Limitations & Caveats

### Features Not Yet Implemented
- **PKI Engine**: Structure exists, Certificate generation/revocation incomplete
- **Database Secrets**: Framework only, credential generation not fully wired
- **Plugin System**: Sandboxing is mock implementation
- **GraphQL API**: Limited endpoint coverage
- **gRPC API**: Minimal implementation
- **Web UI**: Basic Leptos integration, missing many features
- **Cloud Backends**: S3, DynamoDB, Consul are declared but not implemented
- **Kubernetes Operator**: No CRDs or published operator
- **Formal Performance Tuning**: Not optimized for scale yet
- **Post-Quantum Crypto**: Research phase only, not production-ready

### Testing
- Unit tests present in most crates
- Integration tests exist but coverage is spotty
- No formal security audit has been completed
- No performance benchmarks established

### Documentation
- Architecture documentation exists but may be outdated
- API documentation is auto-generated via OpenAPI
- Many features lack inline documentation
- Examples and tutorials are minimal

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- Development setup
- Code standards (rustfmt, clippy)
- Testing requirements
- PR process
- Security reporting

### Development Setup

```bash
# Clone repo
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

# Setup pre-commit checks (optional)
cp scripts/pre-commit.sh .git/hooks/pre-commit

# Build and test
cargo build --workspace --all-features
cargo test --workspace --all-features
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

### Build Targets

```bash
# All crates
cargo build --workspace --release

# Individual binaries
cargo build -p secreton-api --release      # API server
cargo build -p secreton-cli --release      # CLI tool  
cargo build -p secreton-agent --release    # Sidecar agent
```

### Running in Docker

```bash
# Build release binary
cargo build -p secreton-api --release

# Create simple Dockerfile (example)
docker build -t secreton-api:latest \
  -f - \
  --build-arg BINARY=target/release/api_server \
  .

# Run container
docker run -d \
  -p 8080:8080 \
  -e DATABASE_URL=postgresql://user:pass@db:5432/secreton \
  secreton-api:latest
```

## Security Policy

### Reporting Vulnerabilities

**DO NOT** open public GitHub issues for security issues.

Please report privately:
1. GitHub Security Advisory tab ("Report a vulnerability")
2. Or email: security contact in Cargo.toml

### Security Considerations

- Secrets encrypted with AES-256-GCM at rest
- TLS 1.3 for transit encryption
- Sensitive data wiped from memory (`zeroize`)
- Constant-time crypto operations
- No telemetry or external calls
- Audit logging enabled by default

### Best Practices

1. Secure root token with HSM or physical vault
2. Rotate tokens and keys regularly
3. Use least-privilege policies
4. Monitor audit logs
5. Use PostgreSQL with TLS in production
6. Enable authentication on all endpoints
7. Run API server behind reverse proxy with rate limiting

## License

Apache License 2.0 - See [LICENSE](LICENSE)

## Acknowledgments

Built with:
- **Rust** - Safety + performance
- **RustCrypto** - Audited crypto primitives
- **Tokio** - Async runtime
- **Axum** - Web framework
- **PostgreSQL** - Reliable storage

Inspired by HashiCorp Vault, AWS Secrets Manager, Google Secret Manager

## Support & Contact

- **Issues**: [GitHub Issues](https://github.com/analisaperlengkapan/secreton/issues)
- **Discussions**: [GitHub Discussions](https://github.com/analisaperlengkapan/secreton/discussions)
- **Documentation**: See [`docs/`](docs/) directory
- **Contact**: Use GitHub Issues/Discussions or security contact in Cargo.toml

---

**Status**: 🔧 Active Development | 🚀 Not Production Ready | 📝 Alpha Release

Made with care in Rust 🦀
