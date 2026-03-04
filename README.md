# Secreton

> **⚠️ Project Status: Alpha / Early Development**
>
> Secreton is in active development and is **not yet production-ready**. Some features are partially implemented, and APIs or storage schemas may be subject to breaking changes. Use only in development or testing environments.

Secreton is a Rust-based secrets management platform. It provides secure storage, encryption, and access control for sensitive data.

## Overview

Secreton is organized as a Rust workspace with several domain-driven modules, including:
- **api**: REST API server (Axum & Warp)
- **agent**: Sidecar for auto-auth and templating
- **auth**: Authentication methods & identity
- **cli**: Command-line interface
- **core**: Core business logic
- **crypto**: Cryptographic operations using RustCrypto
- **storage**: Storage backend abstractions (PostgreSQL, Redis, File, etc.)
- **ui**: Web UI implemented with Leptos (WASM)

## Prerequisites

- **Rust**: 1.90+ (2024 edition)
- **Database**: PostgreSQL (recommended) or SQLite for development

## Quick Start

### 1. Clone and Build

```bash
git clone https://github.com/analisaperlengkapan/secreton.git
cd secreton
cargo build --workspace --release
```

### 2. Start Database (Optional, for PostgreSQL)

```bash
docker run -d --name secreton-db \
  -e POSTGRES_USER=secreton_user \
  -e POSTGRES_PASSWORD=secreton_pass \
  -e POSTGRES_DB=secreton_db \
  -p 5432:5432 \
  postgres:15
```

### 3. Run the API Server

```bash
cargo run -p secreton-api --release --bin api_server
```

The primary API server will start, alongside other configured services (like gRPC).

## Features & APIs

The API Server serves several categories of RESTful endpoints under the `/api/v1` path prefix:

### Authentication & Identity (`/auth`)
Handles user logins, token verification, and multi-factor authentication.
- **POST `/auth/login`**: Authenticate and retrieve a token.
- **POST `/auth/logout`**: Invalidate the current token.
- **POST `/auth/refresh`**: Refresh an existing authentication token.
- **POST `/auth/verify`**: Verify the validity of a token.
- **MFA Endpoints**: `/auth/mfa/setup`, `/auth/mfa/verify`, `/auth/mfa/disable` for managing two-factor authentication.
- **OAuth Endpoints**: `/auth/oauth/{provider}` for third-party logins.

### Secret Management (`/secret`)
The core functionality for creating, retrieving, and managing encrypted secrets and cryptographic keys.
- **GET/POST/PUT/DELETE `/secret/secrets/{path}`**: CRUD operations for individual secrets.
- **GET `/secret/secrets`**: List all available secrets in the root namespace.
- **GET `/secret/secret-versions/{path}`**: View the history and past versions of a secret.
- **GET/POST/PUT/DELETE `/secret/keys`**: Manage cryptographic keys.
- **POST `/secret/keys/{key_id}/rotate`**: Rotate a specific cryptographic key.

### Administration (`/admin`)
Endpoints for system administrators to manage users, roles, and access controls.
- **GET/POST/PUT/DELETE `/admin/users`**: Manage user accounts.
- **GET/POST `/admin/users/{user_id}/roles`**: Assign and retrieve roles for a user.
- **GET/POST `/admin/roles`**: Manage roles and policies.

### System & Health (`/sys`, `/health`)
Operations for system maintenance, monitoring, and configurations.
- **GET `/sys/config`**: Retrieve current system configuration.
- **GET `/health`**: Check the health and status of the Secreton server.
- **GET `/metrics`**: Export prometheus metrics for monitoring.

## Supported Storage Backends
Secreton abstracts the persistence layer, supporting multiple storage backends:
- **PostgreSQL**: Fully supported (recommended)
- **Redis**: Working backend with caching support
- **In-Memory/File**: For development and testing environments
- **Raft Consensus**: Built-in distributed consensus backend

## Cryptography & Security
- **Encryption**: Utilizes `RustCrypto` (AES-256-GCM, ChaCha20-Poly1305) for secure encryption of secrets at rest.
- **Memory Safety**: Uses `zeroize` to securely wipe sensitive data from memory after use.
- **Role-Based Access Control (RBAC)**: Fine-grained permissions and policy enforcement.
- **Audit Logging**: Comprehensive tracking of all security events and access logs.

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace --all-features
```

### Formatting and Linting

```bash
cargo fmt --all
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

## Security Policy

**DO NOT** open public GitHub issues for security vulnerabilities.

Please report them privately using the GitHub Security Advisory tab ("Report a vulnerability") or email the security contact in `Cargo.toml`. See [CONTRIBUTING.md](CONTRIBUTING.md) for more details.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
