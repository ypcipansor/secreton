# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Real database transaction support for all storage backends (PostgreSQL, MySQL, MongoDB, Redis, Cassandra, etcd, Consul, S3, DynamoDB, CockroachDB, Azure Blob)
- Production-ready X.509 certificate generation in PKI secret engine with support for RSA, ECDSA, and Ed25519 keys
- Comprehensive fuzzing targets for security testing (40+ fuzz targets covering crypto operations, API endpoints, and storage operations)

### Changed
- Replaced mock transaction implementations with real database transactions across all storage backends
- Updated PKI engine to use rcgen library for actual certificate generation instead of mock responses
- Improved error handling in storage backends with proper transaction rollback support

### Fixed
- Compilation errors in PKI certificate generation implementation
- Missing StorageTransaction trait imports in MongoDB and Azure Blob backends
- Type mismatches in certificate parameter handling

### Technical Debt
- Extensive TODO placeholders remain in API handlers (authentication, vault operations)
- Mock implementations still present in OCI and AWS secret backends
- Numerous unused imports and dead code warnings throughout codebase
- Authentication endpoints not yet implemented (login, logout, token refresh)

## [1.0.0] - 2025-01-XX

### Added
- Initial release of Secreton, a security vault system for SIMPelv2
- Modular architecture with 18+ crates for different security components
- Support for 15+ storage backends (PostgreSQL, MySQL, MongoDB, Redis, Cassandra, etcd, Consul, S3, DynamoDB, Azure Blob, CockroachDB, and more)
- Multiple secret engines: PKI, KV, Transit, AWS, OCI, LDAP, SSH, TOTP, Database, RabbitMQ
- Comprehensive authentication methods: Token, UserPass, LDAP, OIDC, SAML, AWS IAM, Kubernetes, GitHub, Okta, RADIUS
- Pure Rust cryptography implementation using audited libraries (RustCrypto suite)
- Quantum-safe cryptography support (ML-DSA, ML-KEM, Falcon signatures)
- RESTful API with OpenAPI/Swagger documentation
- CLI tool for vault operations
- Extensive test suite with unit, integration, and performance tests
- Security fuzzing infrastructure with 40+ fuzz targets
- Audit logging and compliance features
- Multi-tenant architecture with namespaces
- Policy-based access control
- Secret versioning and rotation
- Backup and recovery capabilities

### Security
- Uses only audited, pure Rust cryptography libraries (no C dependencies)
- Zero-trust architecture with comprehensive access controls
- Secure key management with hardware security module support
- TLS 1.3 support with rustls
- Memory-safe implementations with zeroize for sensitive data

### Known Limitations
- Authentication API endpoints are placeholder implementations (TODO)
- Some secret backends use mock implementations (OCI, AWS)
- UI components are minimal/stub implementations
- Enterprise features require separate licensing
- Performance optimization for high-throughput scenarios pending

### Infrastructure
- Built with Rust 1.90+ for memory safety and performance
- Async runtime using Tokio
- Comprehensive error handling with thiserror
- Structured logging with tracing
- Configuration management with layered config sources
- Docker containerization support
- Kubernetes operator for automated deployment

---

## Development Status

This project is in active development. While the core architecture and many features are production-ready, some components are still under development:

- ✅ Storage backends (production-ready)
- ✅ Cryptographic operations (production-ready)
- ✅ PKI certificate generation (recently completed)
- ✅ Transit encryption engine (production-ready)
- ✅ Basic secret engines (KV, TOTP, SSH)
- 🚧 Authentication API endpoints (TODO implementations)
- 🚧 Cloud secret backends (mock implementations)
- 🚧 Web UI (minimal implementation)
- 🚧 Enterprise features (separate licensing)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and contribution guidelines.

## License

Licensed under Apache License 2.0. See [LICENSE](LICENSE) for details.