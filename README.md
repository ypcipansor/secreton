# Secreton

> **High-Performance Secrets Management System in Rust**

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)

**Secreton** is a modular, high-performance secrets management system inspired by HashiCorp Vault, built entirely in Rust. It focuses on memory safety, zero-trust security, and modern cryptography standards.

**⚠️ Status: Early Development. Not for production use.**

## Features

- **Secrets Management**: Securely store and retrieve key-value secrets.
- **Transit Engine**: Encryption-as-a-Service to encrypt/decrypt data without storing it.
- **Cryptography**: Built on [RustCrypto](https://github.com/RustCrypto) primitives (AES-GCM, ChaCha20-Poly1305, Ed25519).
- **Authentication**: Modular authentication system (JWT, MFA support).
- **Storage Backends**: Pluggable storage (PostgreSQL, Redis, MongoDB).
- **Architecture**: Microservices-ready workspace structure.

## Architecture

Secreton is organized as a Rust workspace with specialized crates:

- `crates/api`: The main HTTP REST API server (Axum).
- `crates/cli`: Command-line interface tool.
- `crates/core`: Core business logic and types.
- `crates/crypto`: Cryptographic operations and abstractions.
- `crates/storage`: Storage backend implementations.
- `crates/auth`: Authentication and Identity management.

## Prerequisites

- **Rust**: Version 1.90 or later.
- **PostgreSQL**: Required for the default storage backend.
- **OpenSSL**: Development libraries (usually required for dependencies).

## Getting Started

### 1. Build the Project

```bash
# Build release binaries
cargo build --workspace --release
```

### 2. Run the API Server

The API server runs on port `8080` by default.

```bash
# Run directly with Cargo
cargo run -p secreton-api --bin api_server

# Or run the binary
./target/release/api_server
```

You can configure the port using the `PORT` environment variable:
```bash
PORT=9000 ./target/release/api_server
```

### 3. Use the CLI

The CLI tool allows you to interact with the Secreton API.
**Note:** The CLI defaults to port `8200`. Since the default server runs on `8080`, you must specify the server URL or update your configuration.

```bash
# Alias for convenience (optional)
alias secreton='cargo run -p secreton-cli --quiet --'

# Check Status (specifying the server URL)
secreton status --server http://localhost:8080
```

## Usage Examples

### Transit Engine (Encryption-as-a-Service)

Encrypt data without storing the plaintext.

```bash
# 1. Create a named encryption key
secreton transit create-key my-key --server http://localhost:8080

# 2. Encrypt data
secreton transit encrypt my-key --data "Secret Message" --server http://localhost:8080
# Output: 🔐 Encrypted data: ...ciphertext...

# 3. Decrypt data
secreton transit decrypt my-key --data "...ciphertext..." --server http://localhost:8080
# Output: 🔓 Decrypted data: Secret Message
```

### Secrets Engine (Key-Value)

Store and retrieve static secrets.

```bash
# 1. Store a secret
# Format: path key=value
secreton secret put app/db/prod username=admin password=secure123 --server http://localhost:8080

# 2. Get a secret
secreton secret get app/db/prod --server http://localhost:8080

# 3. List secrets
secreton secret list --server http://localhost:8080

# 4. Delete a secret
secreton secret delete app/db/prod --server http://localhost:8080
```

## Configuration

Secreton uses a layered configuration system (Environment variables, Config files).
Copy the example environment file to start:

```bash
cp .env.example .env
```

Key Environment Variables:
- `SECRETON_ADDR`: API Server address.
- `DATABASE_URL`: PostgreSQL connection string.
- `RUST_LOG`: Log level (e.g., `info`, `debug`).

## Development

Run tests for the entire workspace:

```bash
cargo test --workspace
```

Run linter:

```bash
cargo clippy --workspace -- -D warnings
```

## License

This project is licensed under the Apache License 2.0.
