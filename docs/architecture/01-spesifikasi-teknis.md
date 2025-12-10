# Spesifikasi Teknis

**Versi:** 1.0
**Tanggal:** December 10, 2025
**Dibuat oleh:** Architecture Research Agent

---

## 1. Informasi Umum

### 1.1 Nama Aplikasi
Secreton

### 1.2 Deskripsi Singkat
Advanced Security & Secrets Management System built in Rust dengan arsitektur zero-trust untuk penyimpanan aman, enkripsi, kontrol akses, dan audit logging data sensitif.

### 1.3 Versi Aplikasi
0.1.0 (pre-1.0, early-stage project)

### 1.4 Lisensi
Apache-2.0

---

## 2. Daftar Modul

| No | Nama Modul | Path | Deskripsi Singkat |
|----|------------|------|-------------------|
| 1 | secreton-api | crates/api/ | REST API server menggunakan Axum framework |
| 2 | secreton-agent | crates/agent/ | Sidecar agent untuk auto-authentication |
| 3 | secreton-auth | crates/auth/ | Authentication methods (JWT, OAuth, LDAP, RADIUS) |
| 4 | secreton-cli | crates/cli/ | Command-line interface |
| 5 | secreton-common | crates/common/ | Shared utilities dan helpers |
| 6 | secreton-config | crates/config/ | Configuration management |
| 7 | secreton-core | crates/core/ | Core business logic dan services |
| 8 | secreton-crypto | crates/crypto/ | Cryptography operations (RustCrypto) |
| 9 | secreton-enterprise | crates/enterprise/ | Enterprise features |
| 10 | secreton-errors | crates/errors/ | Error types dan handling |
| 11 | secreton-infrastructure | crates/infrastructure/ | Infrastructure integrations |
| 12 | secreton-integrations | crates/integrations/ | Third-party integrations (AWS, GCP) |
| 13 | secreton-monitoring | crates/monitoring/ | Metrics dan observability |
| 14 | secreton-performance | crates/performance/ | Performance optimizations |
| 15 | secreton-replication | crates/replication/ | High availability dan replication |
| 16 | secreton-secrets | crates/secrets/ | Secret engines base |
| 17 | secreton-secrets-database | crates/secrets-database/ | Database secret engine |
| 18 | secreton-secrets-pki | crates/secrets-pki/ | PKI secret engine |
| 19 | secreton-security | crates/security/ | Security features dan audit |
| 20 | secreton-storage | crates/storage/ | Storage backends (PostgreSQL, Redis, etc.) |
| 21 | secreton-ui | crates/ui/ | Web UI (Leptos) |
| 22 | secreton-graphql | crates/graphql/ | GraphQL API (temporarily disabled) |
| 23 | secreton-grpc | crates/grpc/ | gRPC API (temporarily disabled) |

---

## 3. Detail Modul

### 3.1 secreton-core

#### 3.1.1 Lokasi
`crates/core/`

#### 3.1.2 Fungsi
Menyediakan abstraksi dasar untuk security levels, audit logging, error handling, dan common data structures yang digunakan di seluruh sistem Secreton.

#### 3.1.3 Manfaat
- Fondasi yang konsisten untuk semua komponen
- Reusability code tinggi
- Type safety dengan Rust
- Memory safety dengan zeroize

#### 3.1.4 Dependensi
- Internal: secreton-common, secreton-errors, secreton-auth
- Eksternal: serde, chrono, uuid

#### 3.1.5 Public API
```rust
pub use secreton_common::{Result as CommonResult, SecurityLevel};
pub use secreton_errors::{Result, SecretonError};
pub use secreton_auth::{AuthCredentials, AuthResult, User, UserInfo};
```

### 3.2 secreton-api

#### 3.2.1 Lokasi
`crates/api/`

#### 3.2.2 Fungsi
Menyediakan HTTP API endpoints untuk semua operasi security menggunakan Warp framework.

#### 3.2.3 Manfaat
- RESTful API lengkap
- OpenAPI/Swagger documentation
- High-performance async handling
- Comprehensive error responses

#### 3.2.4 Dependensi
- Internal: secreton-core, secreton-auth, secreton-security
- Eksternal: warp, serde, tokio

#### 3.2.5 Public API
```rust
pub struct ApiResponse<T> { ... }
pub struct AuthenticationRequest { ... }
```

### 3.3 secreton-crypto

#### 3.3.1 Lokasi
`crates/crypto/`

#### 3.3.2 Fungsi
High-performance cryptographic primitives dan protocols dengan RustCrypto integration.

#### 3.3.3 Manfaat
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)
- Hardware security module support
- Post-quantum cryptography (experimental)
- Transit encryption-as-a-service

#### 3.3.4 Dependensi
- Internal: secreton-core
- Eksternal: rust-crypto, rand, zeroize

#### 3.3.5 Public API
```rust
pub use cryptography::*;
pub use encryption::*;
pub use key_manager::*;
```

### 3.4 secreton-storage

#### 3.4.1 Lokasi
`crates/storage/`

#### 3.4.2 Fungsi
Unified interface untuk berbagai storage backends termasuk PostgreSQL, Redis, dan Raft.

#### 3.4.3 Manfaat
- Multi-backend support
- Automatic failover
- Data replication
- Backup & restore

#### 3.4.4 Dependensi
- Internal: secreton-core
- Eksternal: async-trait, tokio-postgres, redis

#### 3.4.5 Public API
```rust
pub struct SecretEntry { ... }
pub use backends::{PostgresBackend, RedisBackend, RaftStorageBackend};
```

### 3.5 secreton-auth

#### 3.5.1 Lokasi
`crates/auth/`

#### 3.5.2 Fungsi
Authentication methods dan token management termasuk JWT, OAuth2, LDAP, RADIUS.

#### 3.5.3 Manfaat
- Multi-method authentication
- Role-based access control
- Token hierarchy
- MFA support

#### 3.5.4 Dependensi
- Internal: secreton-core, secreton-crypto
- Eksternal: hmac, sha2, base64

#### 3.5.5 Public API
```rust
pub struct Claims { ... }
pub enum UserRole { Admin, SecretAdmin, KeyManager, ... }
```

---

## 4. Tech Stack

### 4.1 Bahasa Pemrograman
| Bahasa | Versi | Penggunaan |
|--------|-------|------------|
| Rust | 1.90+ (2024 edition) | Core application logic, cryptography, API server |

### 4.2 Framework & Library
| Nama | Versi | Fungsi |
|------|-------|--------|
| Tokio | 1.47.1 | Async runtime |
| Axum | - | Web framework untuk API |
| Serde | 1.0.228 | Serialization/deserialization |
| Warp | - | HTTP server framework |
| RustCrypto | - | Cryptographic primitives |
| Zeroize | 1.8.1 | Memory zeroing untuk sensitive data |

### 4.3 Build Tools
| Tool | Versi | Fungsi |
|------|-------|--------|
| Cargo | - | Rust package manager dan build tool |
| Docker | - | Containerization |
| Docker Compose | - | Multi-container orchestration |

---

## 5. Struktur Proyek

```
secreton/
├── Cargo.toml                 # Workspace configuration
├── crates/                    # Rust crates
│   ├── api/                  # REST API server
│   ├── auth/                 # Authentication
│   ├── crypto/               # Cryptography
│   ├── storage/              # Storage backends
│   └── ...                   # Other crates
├── config/                   # Configuration files
├── tests/                    # Integration tests
├── docs/                     # Documentation
├── scripts/                  # Utility scripts
├── docker-compose.yml        # Container orchestration
├── Dockerfile               # Container build
└── nginx/                   # Reverse proxy config
```

---

## 6. Konfigurasi

### 6.1 File Konfigurasi
| File | Lokasi | Fungsi |
|------|--------|--------|
| Cargo.toml | / | Workspace dan dependency management |
| docker-compose.yml | / | Multi-service container setup |
| nginx.conf | nginx/ | Reverse proxy configuration |
| prometheus.yml | monitoring/ | Monitoring configuration |

### 6.2 Environment Variables
| Variable | Deskripsi | Default |
|----------|-----------|---------|
| RUST_LOG | Logging level | debug |
| SECRETON_SERVER__HOST | Server bind address | 0.0.0.0 |
| SECRETON_SERVER__PORT | Server port | 8080 |
| SECRETON_DATABASE__URL | Database connection URL | sqlite:/app/data/secreton.db |
| SECRETON_AUTH__JWT_SECRET | JWT signing secret | (required) |
| REDIS_URL | Redis connection URL | redis://redis:6379 |

---

## 7. Build & Run

### 7.1 Prerequisites
- Rust 1.90+
- Docker & Docker Compose
- PostgreSQL 15+ (recommended)
- Redis 7+

### 7.2 Build Commands
```bash
# Development build
cargo build --workspace

# Release build
cargo build --workspace --release

# Build specific component
cargo build -p secreton-api --release
```

### 7.3 Run Commands
```bash
# Development run
cargo run -p secreton-api

# Docker run
docker-compose up

# Production run
docker-compose -f docker-compose.yml up -d
```</content>
<parameter name="filePath">/home/clouduser/secreton/secreton/docs/architecture/01-spesifikasi-teknis.md