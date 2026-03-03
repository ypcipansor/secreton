# Secreton

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

## Features

- **Storage Backends**: Support for multiple backends including PostgreSQL, Redis, and File-based storage.
- **Cryptography**: Utilizes `RustCrypto` for secure encryption (AES-GCM, ChaCha20-Poly1305).
- **Authentication**: JWT/Token-based authentication, with extensible MFA support.
- **REST API**: Fully-featured HTTP API using Axum and Warp.
- **Web UI**: Optional Leptos-based front-end interface.
- **CLI**: Command-line tools for interacting with the platform.

## Development

### Running Tests

```bash
# Run all tests
cargo test --workspace
```

### Formatting and Linting

```bash
cargo fmt --all
cargo clippy --workspace -- -D warnings
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.
