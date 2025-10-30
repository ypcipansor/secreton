# Secreton

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Rust](https://img.shields.io/badge/rust-1.90%2B-orange.svg)](https://www.rust-lang.org/)
[![Security Audit](https://img.shields.io/badge/security-audited-green.svg)](https://github.com/RustCrypto)
[![Build Status](https://img.shields.io/github/actions/workflow/status/analisaperlengkapan/secreton/ci.yml)](https://github.com/analisaperlengkapan/secreton/actions)

**Advanced Security Vault System with Quantum-Safe Cryptography for SIMPelv2**

Secreton is a comprehensive, enterprise-grade secrets management system built in pure Rust. Designed for the SIMPelv2 platform, it provides secure storage, access control, and cryptographic operations for sensitive data management in zero-trust environments.

## 🚀 Key Features

### 🔐 Security & Cryptography
- **Pure Rust Implementation**: Memory-safe with zero C dependencies
- **Audited Cryptography**: Uses only RustCrypto libraries (independently audited)
- **Quantum-Safe Algorithms**: ML-DSA, ML-KEM, and Falcon signatures
- **Zero-Trust Architecture**: Comprehensive access controls and audit logging
- **Hardware Security**: HSM integration support

### 🗄️ Storage Backends
- **15+ Backends Supported**: PostgreSQL, MySQL, MongoDB, Redis, Cassandra, etcd, Consul, S3, DynamoDB, Azure Blob, CockroachDB, and more
- **Production-Ready Transactions**: ACID compliance across all backends
- **High Availability**: Replication and failover support
- **Multi-Region**: Global data distribution capabilities

### 🔑 Secret Engines
- **PKI**: X.509 certificate generation and management
- **KV**: Key-value secret storage with versioning
- **Transit**: Encryption/decryption as a service
- **AWS**: Dynamic AWS credential generation
- **OCI**: Oracle Cloud Infrastructure credentials
- **Database**: Dynamic database credentials
- **SSH**: SSH key signing and management
- **TOTP**: Time-based one-time passwords
- **RabbitMQ**: Message queue credentials

### 👤 Authentication Methods
- **Token**: Bearer token authentication
- **UserPass**: Username/password authentication
- **LDAP**: Directory service integration
- **OIDC**: OpenID Connect providers
- **SAML**: Enterprise SSO integration
- **AWS IAM**: AWS identity integration
- **Kubernetes**: Service account authentication
- **GitHub**: OAuth with GitHub
- **Okta**: Enterprise identity provider
- **RADIUS**: Network authentication

### 🏗️ Architecture
- **Modular Design**: 18+ crates for different components
- **Async First**: Built on Tokio for high performance
- **RESTful API**: OpenAPI/Swagger documentation
- **CLI Tool**: Command-line interface for operations
- **Policy Engine**: Attribute-based access control
- **Audit Logging**: Comprehensive security event logging

## 📊 Current Status

### ✅ Production Ready
- Storage backends with real transaction support
- Cryptographic operations (encryption, signing, key derivation)
- PKI certificate generation
- Transit encryption engine
- Basic secret engines (KV, TOTP, SSH)
- Authentication methods framework
- Security audit logging
- Comprehensive test suite

### 🚧 In Development
- Authentication API endpoints (currently TODO placeholders)
- Cloud secret backends (OCI, AWS use mock implementations)
- Web UI (minimal implementation)
- Enterprise features (separate licensing)
- Performance optimizations for high-throughput scenarios

### 🧪 Quality Assurance
- **40+ Fuzz Targets**: Extensive security fuzzing
- **Comprehensive Tests**: Unit, integration, and performance tests
- **Security Audits**: Regular audits of cryptography implementations
- **Code Coverage**: High test coverage across critical paths

## 🛠️ Installation

### Prerequisites
- Rust 1.90 or later
- Linux/macOS/Windows support

### From Source
```bash
# Clone the repository
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

# Build the project
cargo build --release

# Run tests
cargo test

# Install CLI tool
cargo install --path crates/cli
```

### Docker
```bash
# Build container
docker build -t secreton .

# Run with default configuration
docker run -p 8200:8200 secreton
```

## 🚀 Quick Start

### 1. Initialize Vault
```bash
# Start the server
secreton server -config=config/default.toml

# Initialize and unseal
secreton operator init
secreton operator unseal
```

### 2. Enable Secret Engines
```bash
# Enable KV secrets
secreton secrets enable -path=secret kv

# Enable PKI engine
secreton secrets enable -path=pki pki

# Enable Transit engine
secreton secrets enable -path=transit transit
```

### 3. Store and Retrieve Secrets
```bash
# Store a secret
secreton kv put secret/myapp api_key=12345 db_pass=secret

# Retrieve a secret
secreton kv get secret/myapp

# Generate a certificate
secreton write pki/issue/example-dot-com common_name=example.com
```

### 4. Authentication
```bash
# Login with token
secreton login <token>

# Enable userpass auth
secreton auth enable userpass

# Create user
secreton write auth/userpass/users/testuser password=testpass policies=default
```

## 📚 API Usage

### REST API
```bash
# Store secret via API
curl -H "X-Vault-Token: $VAULT_TOKEN" \
     -X POST \
     -d '{"data":{"key":"value"}}' \
     http://localhost:8200/v1/secret/data/mysecret

# Retrieve secret
curl -H "X-Vault-Token: $VAULT_TOKEN" \
     http://localhost:8200/v1/secret/data/mysecret
```

### Programmatic Access
```rust
use secreton_core::{Config, VaultClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let client = VaultClient::new(config).await?;

    // Store a secret
    client.kv_put("secret/myapp", serde_json::json!({
        "api_key": "secret123",
        "db_url": "postgres://..."
    })).await?;

    // Retrieve a secret
    let secret = client.kv_get("secret/myapp").await?;
    println!("{:?}", secret);

    Ok(())
}
```

## ⚙️ Configuration

### Basic Configuration
```toml
[server]
address = "0.0.0.0:8200"
tls_cert_file = "/path/to/cert.pem"
tls_key_file = "/path/to/key.pem"

[storage]
type = "postgresql"
connection_url = "postgres://user:pass@localhost/secreton"

[auth]
default_lease_ttl = 3600
max_lease_ttl = 86400

[telemetry]
prometheus_enabled = true
metrics_path = "/metrics"
```

### Storage Backend Configuration
```toml
[storage.postgresql]
connection_url = "postgres://user:pass@localhost/secreton"
max_connections = 10

[storage.redis]
url = "redis://localhost:6379"
connection_pool_size = 5

[storage.s3]
bucket = "secreton-storage"
region = "us-east-1"
access_key = "AKIA..."
secret_key = "..."
```

## 🔒 Security Considerations

### Cryptographic Security
- All cryptographic operations use audited Rust libraries
- Keys are properly zeroized from memory
- TLS 1.3 with perfect forward secrecy
- Support for hardware security modules

### Operational Security
- Comprehensive audit logging
- Policy-based access control
- Secret versioning and rotation
- Automated backup and recovery

### Compliance
- SOC 2 Type II ready
- GDPR compliant data handling
- FIPS 140-2 compatible cryptography
- Comprehensive audit trails

## 🧪 Testing & Quality

### Running Tests
```bash
# Run all tests
cargo test

# Run specific test suite
cargo test --package secreton-core
cargo test --package secreton-storage

# Run fuzzing
cargo fuzz run api_endpoints
cargo fuzz run crypto_operations
```

### Security Testing
```bash
# Run security-focused tests
cargo test security

# Run fuzzing campaigns
./scripts/fuzz.sh

# Memory safety checks
cargo +nightly miri test
```

## 📖 Documentation

- [API Reference](docs/api.md) - Complete API documentation
- [Configuration Guide](docs/config.md) - Detailed configuration options
- [Deployment Guide](docs/deployment.md) - Production deployment instructions
- [Security Guide](docs/security.md) - Security best practices
- [Contributing Guide](CONTRIBUTING.md) - Development and contribution guidelines

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup
```bash
# Clone and setup
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton

# Install development dependencies
cargo install cargo-audit cargo-fuzz cargo-miri

# Run development checks
cargo check
cargo test
cargo clippy
cargo audit
```

### Code Standards
- Follow Rust API guidelines
- Comprehensive test coverage required
- Security review for cryptographic changes
- Documentation for all public APIs

## 📄 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- Built with [RustCrypto](https://github.com/RustCrypto) libraries
- Inspired by industry-leading secret management systems
- Developed for the SIMPelv2 platform by the Kejaksaan security team

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/analisaperlengkapan/secreton/issues)
- **Discussions**: [GitHub Discussions](https://github.com/analisaperlengkapan/secreton/discussions)
- **Documentation**: [docs/](docs/) directory

---

**Secreton** - Secure, Fast, and Reliable Secrets Management for Modern Applications.