# Secreton

Advanced Security System with Quantum-Safe Cryptography

Secreton is a comprehensive, enterprise-grade secrets management platform built in Rust. It provides secure storage, encryption, access control, and audit logging for sensitive data, similar to HashiCorp Vault but with enhanced quantum-safe cryptography and zero-trust architecture.

## Features

### Core Security Capabilities
- **Quantum-Safe Cryptography**: Uses RustCrypto suite with support for post-quantum algorithms
- **Zero-Trust Architecture**: Every request requires authentication and authorization
- **Multi-Algorithm Encryption**: AES-GCM, ChaCha20Poly1305, RSA, ECC support
- **Key Management**: Automatic key rotation, versioning, and lifecycle policies
- **Audit Logging**: Comprehensive compliance and security event logging

### Secrets Engines
- **KV Secrets**: Key-value secret storage with versioning
- **PKI Secrets**: Certificate authority and certificate management
- **Database Secrets**: Dynamic database credential generation
- **Transit Engine**: Encryption as a service for data encryption/decryption

### Authentication Methods
- **JWT Tokens**: Bearer token authentication with configurable TTL
- **OAuth2**: Integration with Google, GitHub, Microsoft, and Okta
- **Multi-Factor Authentication**: TOTP and hardware token support
- **Role-Based Access Control**: Granular permissions and policies

### Infrastructure
- **Multi-Database Support**: PostgreSQL (recommended), SQLite, Redis
- **Replication**: High availability with data replication
- **Monitoring**: Prometheus metrics and health checks
- **API Gateway**: RESTful HTTP API with OpenAPI documentation
- **Agent**: Sidecar helper for auto-authentication and secret injection

### Enterprise Features
- **Compliance**: PCI DSS, SOX, FIPS 140-2, Common Criteria support
- **Granular Revocation**: Fine-grained token and permission revocation
- **Secret Versioning**: Historical secret versions with rollback
- **Integrations**: AWS, Kubernetes, cloud provider integrations

## Prerequisites

- **Rust**: 1.90 or later (latest stable recommended)
- **PostgreSQL**: 15+ (recommended for production)
- **Git**: For version control
- **Docker**: Optional, for containerized development

Important

This project is currently in a very early development/experimental stage. There are a lot of unimplemented/broken features at the moment. Contributions are welcome to help out with the progress!

## Installation

### Clone the Repository

```bash
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton
```

### Install Rust Toolchain

```bash
rustup update stable
rustup component add rustfmt clippy
```

### Install Development Tools (Optional)

```bash
cargo install cargo-watch cargo-tarpaulin cargo-audit
```

### Build the Project

```bash
# Build all workspace crates
cargo build --workspace

# Build with all features enabled
cargo build --workspace --all-features

# Build release version
cargo build --workspace --release
```

## Configuration

### Environment Setup

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit `.env` with your configuration:
```dotenv
# Server configuration
BRANKAS_SERVER__HOST=127.0.0.1
BRANKAS_SERVER__PORT=8080
BRANKAS_SERVER__LOG_LEVEL=info
BRANKAS_SERVER__STORAGE_PATH=./data

# Database configuration (PostgreSQL recommended)
BRANKAS_DATABASE__URL=postgresql://secreton_user:secure_password@localhost:5432/secreton_db
BRANKAS_DATABASE__MAX_CONNECTIONS=20

# Authentication configuration
BRANKAS_AUTH__TOKEN_TTL=3600
BRANKAS_AUTH__REFRESH_TOKEN_TTL=2592000
BRANKAS_AUTH__JWT_SECRET=your-secure-random-jwt-secret-here
```

### Database Setup

For development with PostgreSQL:

```bash
# Using Docker
docker run --name secreton-dev-db \
  -e POSTGRES_PASSWORD=secure_password \
  -e POSTGRES_USER=secreton_user \
  -e POSTGRES_DB=secreton_db \
  -p 5432:5432 \
  -d postgres:15
```

For production, configure PostgreSQL with proper security settings and connection pooling.

### OAuth Configuration (Optional)

Configure OAuth providers in your configuration file:

```toml
[oauth.google]
client_id = "your-google-client-id"
client_secret = "your-google-client-secret"
redirect_uri = "https://api.secreton.com/auth/oauth/google/callback"

[oauth.github]
client_id = "your-github-client-id"
client_secret = "your-github-client-secret"
redirect_uri = "https://api.secreton.com/auth/oauth/github/callback"
```

## Running the Application

### Start the API Server

```bash
# Run the API server
cargo run -p secreton-api --bin api_server

# Or with custom port
PORT=9090 cargo run -p secreton-api --bin api_server
```

The API server will start on `http://127.0.0.1:8080` (or your configured port).

### Start the Agent (Optional)

```bash
# Run the agent for auto-authentication
cargo run -p secreton-agent
```

### Health Check

Verify the server is running:

```bash
curl http://127.0.0.1:8080/health
```

Expected response:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "uptime": "0s"
}
```

## Usage

### Authentication

#### Login with Username/Password

```bash
curl -X POST http://127.0.0.1:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin",
    "password": "secure_password"
  }'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refresh_token": "refresh_token_here",
  "expires_in": 3600
}
```

#### OAuth Login

Redirect users to OAuth endpoints:
- Google: `GET /auth/oauth/google`
- GitHub: `GET /auth/oauth/github`
- Microsoft: `GET /auth/oauth/microsoft`
- Okta: `GET /auth/oauth/okta`

### Secret Operations

All secret operations require authentication. Include the JWT token in the Authorization header:

```bash
AUTH_TOKEN="your_jwt_token_here"
```

#### Create a Secret

```bash
curl -X POST http://127.0.0.1:8080/secret/secrets/myapp/database \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "db_user",
      "password": "db_password",
      "host": "localhost",
      "port": 5432
    }
  }'
```

#### Retrieve a Secret

```bash
curl -X GET http://127.0.0.1:8080/secret/secrets/myapp/database \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

Response:
```json
{
  "data": {
    "username": "db_user",
    "password": "db_password",
    "host": "localhost",
    "port": 5432
  },
  "metadata": {
    "version": 1,
    "created_time": "2025-01-13T10:00:00Z",
    "deletion_time": "",
    "destroyed": false
  }
}
```

#### Update a Secret

```bash
curl -X PUT http://127.0.0.1:8080/secret/secrets/myapp/database \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "data": {
      "username": "db_user",
      "password": "new_db_password",
      "host": "localhost",
      "port": 5432
    }
  }'
```

#### Delete a Secret

```bash
curl -X DELETE http://127.0.0.1:8080/secret/secrets/myapp/database \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

#### List Secrets

```bash
curl -X GET "http://127.0.0.1:8080/secret/secrets?path=myapp" \
  -H "Authorization: Bearer $AUTH_TOKEN"
```

### Key Management

#### Create an Encryption Key

```bash
curl -X POST http://127.0.0.1:8080/secret/keys \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "my-encryption-key",
    "type": "aes256-gcm96",
    "usage": "encrypt/decrypt"
  }'
```

#### Encrypt Data

```bash
curl -X POST http://127.0.0.1:8080/secret/encrypt \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "my-encryption-key",
    "plaintext": "SGVsbG8gV29ybGQ="  // base64 encoded
  }'
```

#### Decrypt Data

```bash
curl -X POST http://127.0.0.1:8080/secret/decrypt \
  -H "Authorization: Bearer $AUTH_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "key_name": "my-encryption-key",
    "ciphertext": "encrypted_data_here"
  }'
```

### User Management (Admin Only)

#### Create a User

```bash
curl -X POST http://127.0.0.1:8080/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newuser",
    "password": "secure_password",
    "email": "user@example.com",
    "roles": ["user"]
  }'
```

#### List Users

```bash
curl -X GET http://127.0.0.1:8080/admin/users \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

### System Monitoring

#### Get System Metrics

```bash
curl -X GET http://127.0.0.1:8080/admin/metrics \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

#### Get Prometheus Metrics

```bash
curl -X GET http://127.0.0.1:8080/metrics
```

## API Reference

### Base URL
```
http://127.0.0.1:8080
```

### Authentication Endpoints
- `POST /auth/login` - User login
- `POST /auth/refresh` - Refresh JWT token
- `POST /auth/logout` - Logout user
- `GET /auth/oauth/{provider}` - OAuth login initiation
- `GET /auth/oauth/{provider}/callback` - OAuth callback

### Secret Endpoints
- `GET /secret/secrets/{path}` - Get secret
- `POST /secret/secrets/{path}` - Create secret
- `PUT /secret/secrets/{path}` - Update secret
- `DELETE /secret/secrets/{path}` - Delete secret
- `GET /secret/secrets` - List secrets

### Key Management Endpoints
- `GET /secret/keys` - List keys
- `POST /secret/keys` - Create key
- `GET /secret/keys/{key_id}` - Get key info
- `PUT /secret/keys/{key_id}` - Update key
- `DELETE /secret/keys/{key_id}` - Delete key
- `POST /secret/keys/{key_id}/rotate` - Rotate key

### Encryption Endpoints
- `POST /secret/encrypt` - Encrypt data
- `POST /secret/decrypt` - Decrypt data
- `POST /secret/sign` - Sign data
- `POST /secret/verify` - Verify signature

### Administrative Endpoints
- `GET /admin/users` - List users
- `POST /admin/users` - Create user
- `GET /admin/users/{user_id}` - Get user
- `PUT /admin/users/{user_id}` - Update user
- `DELETE /admin/users/{user_id}` - Delete user
- `GET /admin/roles` - List roles
- `POST /admin/roles` - Create role
- `GET /admin/config` - Get system config
- `PUT /admin/config` - Update system config
- `GET /admin/metrics` - Get system metrics

### System Endpoints
- `GET /health` - Health check
- `GET /version` - Version info
- `GET /metrics` - Prometheus metrics

## Development

### Code Style

Format code with `rustfmt`:
```bash
cargo fmt --all
```

Lint with `clippy`:
```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Testing

Run all tests:
```bash
cargo test --workspace --all-features
```

Run tests with coverage:
```bash
cargo tarpaulin --workspace --all-features --out Lcov
```

Run specific crate tests:
```bash
cargo test -p secreton-api
cargo test -p secreton-crypto
```

### Watch Mode

Use `cargo-watch` for iterative development:
```bash
cargo watch -x test
```

### Security Audit

Run security audit:
```bash
cargo audit
```

## Architecture

Secreton is organized as a Rust workspace with multiple crates:

- `secreton-api`: HTTP REST API server using Axum
- `secreton-agent`: Sidecar agent for auto-authentication
- `secreton-auth`: Authentication and authorization logic
- `secreton-core`: Core business logic and services
- `secreton-crypto`: Cryptographic operations using RustCrypto
- `secreton-storage`: Storage backends (PostgreSQL, SQLite, Redis)
- `secreton-security`: Security monitoring and audit logging
- `secreton-errors`: Unified error handling
- `secreton-config`: Configuration management
- `secreton-common`: Shared utilities and types

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for detailed contribution guidelines.

### Quick Start for Contributors

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Run tests: `cargo test --workspace --all-features`
5. Format code: `cargo fmt --all`
6. Lint: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
7. Commit your changes
8. Push to your fork
9. Create a Pull Request

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

For support and questions:
- Open an issue on GitHub
- Check the documentation in [CONTRIBUTING.md](CONTRIBUTING.md)
- Review the codebase and tests for examples

## Security

Secreton takes security seriously. If you discover a security vulnerability, please report it responsibly by emailing the maintainers or opening a security advisory on GitHub.

Key security features:
- Memory-safe Rust implementation
- Zeroize for sensitive data cleanup
- Comprehensive audit logging
- Quantum-safe cryptographic algorithms
- Zero-trust architecture</content>
<parameter name="filePath">/workspaces/secreton/README.md
