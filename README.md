# Security & Compliance
- Zero Trust, memory-only, audit immutable, MFA, policy granular
- Mengikuti standar: PCI DSS, ISO 27001, NIST SP 800-53, OJK/BI
- Lihat `SECURITY.md` dan `docs/COMPLIANCE.md` untuk checklist dan mapping compliance
- Contoh konfigurasi TLS/mTLS: `docs/TLS_EXAMPLE.md`

# CI/CD Security
- Pipeline otomatis: audit dependency, static analysis, test, format
- Lihat `.github/workflows/security.yml`

# Fitur Utama
- Memory-only secrets engine (impossible to leak to disk)
- Policy & MFA enforcement di semua operasi
- Audit log immutable, siap integrasi SIEM
- Envelope encryption & Shamir’s Secret Sharing

# Catatan
- Tidak ada sistem yang benar-benar impossible to hack, tapi Brankas menekan risiko ke level minimum sesuai standar internasional dan perbankan.
- Lakukan security review eksternal dan update checklist secara berkala.
# Brankas Adhyaksa

A secure secret management system inspired by HashiCorp Vault, built with Rust and Axum.

## Features

- **Secrets Engine**: Store and manage secrets with versioning
- **Key-Value Store**: Simple key-value secret storage
- **Secure**: Encryption at rest and in transit
- **REST API**: HTTP/JSON API for all operations
- **Authentication**: JWT-based authentication
- **Authorization**: Fine-grained access control

## Getting Started

### Prerequisites

- Rust (latest stable version)
- SQLite (for default storage)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/brankas-adhyaksa.git
   cd brankas-adhyaksa
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

### Configuration

Create a `.env` file in the project root with the following variables:

```env
# Server configuration
BRANKAS_HOST=127.0.0.1
BRANKAS_PORT=8080
BRANKAS_LOG_LEVEL=info
BRANKAS_STORAGE_PATH=./data

# Database configuration
DATABASE_URL=sqlite:./data/brankas.db

# Authentication
JWT_SECRET=your-secret-key-here
JWT_EXPIRATION=3600
```

### Running the Server

```bash
# Run in development mode
cargo run

# Run in release mode
cargo run --release
```

## API Documentation

### Authentication

#### Login

```http
POST /v1/auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "password"
}
```

### Secrets API

#### Create/Update Secret

```http
POST /v1/secret/data/{path}
Authorization: Bearer {token}
Content-Type: application/json

{
  "data": {
    "key1": "value1",
    "key2": "value2"
  }
}
```

#### Read Secret

```http
GET /v1/secret/data/{path}
Authorization: Bearer {token}
```

#### Delete Secret

```http
DELETE /v1/secret/data/{path}
Authorization: Bearer {token}
```

## Development

### Running Tests

```bash
cargo test
```

### Building Documentation

```bash
cargo doc --open
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
