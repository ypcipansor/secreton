# Contributing to Secreton Security Vault System by Cipherce

Thank you for your interest in contributing to Secreton by Cipherce! This document provides comprehensive guidelines for contributing to our security-focused vault system.

## 🎯 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Architecture Overview](#architecture-overview)
- [Contributing Process](#contributing-process)
- [Code Standards](#code-standards)
- [Security Guidelines](#security-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)
- [Review Process](#review-process)
- [Security Reporting](#security-reporting)

## 📜 Code of Conduct

This project adheres to a professional code of conduct. By participating, you agree to:

- **Be respectful and inclusive** in all interactions
- **Focus on constructive feedback** and collaboration
- **Prioritize security and quality** in all contributions
- **Respect intellectual property** and licensing terms
- **Report security issues responsibly** through proper channels
- **Follow banking-grade security practices**

## 🚀 Getting Started

### Prerequisites

**Required Tools:**
- **Rust 1.70+**: Latest stable recommended (`rustup update`)
- **Cargo**: Package manager (comes with Rust)
- **PostgreSQL 13+**: Primary database backend
- **Git**: Version control system
- **OpenSSL**: Development libraries (`libssl-dev` on Ubuntu, `openssl-devel` on RHEL)

**Optional Tools:**
- **Docker**: For containerized development
- **cargo-audit**: Security vulnerability scanning (`cargo install cargo-audit`)
- **cargo-clippy**: Code linting (`rustup component add clippy`)
- **Postman/curl**: For API testing
- **jq**: JSON processing for testing scripts

### Quick Setup

1. **Fork and Clone**:
```bash
git clone https://github.com/your-username/secreton.git
cd secreton
```

2. **Environment Setup**:
```bash
# Install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian
# OR
sudo dnf install postgresql-server postgresql-contrib  # RHEL/Fedora

# Install development tools
cargo install cargo-audit cargo-watch
rustup component add clippy rustfmt
```

3. **Database Setup**:
```bash
# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

3. **Database Setup**:
```bash
# Install PostgreSQL
sudo apt-get install postgresql postgresql-contrib  # Ubuntu/Debian

# Start PostgreSQL service
sudo systemctl start postgresql
sudo systemctl enable postgresql

# Create database and user
sudo -u postgres psql
CREATE DATABASE secreton;
CREATE USER secreton_user WITH PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE secreton TO secreton_user;
\q

# Run database migrations
# Migrations are located in the migrations/ directory
# The application will automatically run migrations on startup
```

4. **Environment Configuration**:
```bash
# Copy environment template
cp .env.example .env

# Edit database connection
# DATABASE_URL=postgresql://secreton_user:password@localhost/secreton
```
```

4. **Build and Test**:
```bash
# Build the project
cargo build --release

# Run security audit
cargo audit

# Run tests
cargo test

# Check code quality
cargo clippy -- -D warnings
```

## 🔧 Development Environment

### Security-First Development

**Mandatory Security Checks:**
```bash
# Security audit (must pass with 0 vulnerabilities)
cargo audit

# Code quality (must pass with 0 warnings)
cargo clippy -- -D warnings

# Format code
cargo fmt

# Run full test suite
cargo test
```

### Database Configuration

Create `.env` file in project root:
```env
DATABASE_URL=postgresql://secreton_user:password@localhost/secreton
RUST_LOG=info
SECRET_KEY=your-256-bit-secret-key-here
```

### IDE Setup

**VS Code Recommended Extensions:**
- `rust-lang.rust-analyzer`
- `ms-vscode.vscode-json`
- `redhat.vscode-yaml`
- `ms-vscode.vscode-docker`

## 🏗️ Architecture Overview

### Core Components

```
secreton/
├── crates/
│   ├── core/           # Core security engine
│   ├── api/            # REST API layer
│   ├── cli/            # Command-line interface
│   ├── crypto/         # Cryptographic operations
│   ├── storage/        # Storage backends
│   └── ui/             # User interface
├── docs/               # Documentation
├── scripts/            # Build and deployment scripts
└── tests/              # Integration tests
```

### Security Architecture

- **Zero-Trust Model**: Every request authenticated and authorized
- **Quantum-Safe Crypto**: Post-quantum cryptographic algorithms
- **Multi-Layer Encryption**: AES-256-GCM + Post-quantum KEM
- **Audit Logging**: Comprehensive security event tracking
- **Compliance Frameworks**: Automated compliance validation

## 🤝 Contributing Process

### Development Workflow

1. **Choose Issue**: Select from [GitHub Issues](https://github.com/cipherce/secreton/issues)
2. **Create Branch**: `git checkout -b feature/your-feature-name`
3. **Security Review**: Run `cargo audit` and `cargo clippy`
4. **Write Tests**: Add comprehensive test coverage
5. **Commit**: Follow conventional commit format
6. **Pull Request**: Create PR with detailed description
7. **Code Review**: Address reviewer feedback
8. **Merge**: Squash and merge after approval

### Branch Naming Convention

```
feature/add-new-crypto-algorithm
bugfix/fix-audit-logging-issue
security/patch-vulnerability-cve-2023-12345
docs/update-contributing-guide
refactor/optimize-database-queries
```

## 📏 Code Standards

### Rust Code Quality

**Clippy Rules (Enforced):**
```rust
// ✅ Good: Use standard library functions
let clamped = value.clamp(min, max);

// ❌ Bad: Manual implementation
let clamped = if value < min { min } else if value > max { max } else { value };
```

**Async Best Practices:**
```rust
// ✅ Good: Proper async trait implementation
#[async_trait]
impl MyTrait for MyStruct {
    async fn my_method(&self) -> Result<(), Error> {
        // Implementation
    }
}

// ❌ Bad: Blocking operations in async context
async fn bad_example() {
    std::thread::sleep(Duration::from_secs(1)); // Blocks!
}
```

### Security Standards

**Cryptographic Requirements:**
- Use quantum-safe algorithms for new implementations
- Implement proper key rotation and lifecycle management
- Use authenticated encryption (AEAD) for data at rest
- Implement secure random number generation
- Validate all cryptographic inputs and outputs

**Input Validation:**
```rust
// ✅ Good: Comprehensive validation
pub fn process_secret(&self, secret: &str) -> Result<(), Error> {
    if secret.is_empty() {
        return Err(Error::InvalidInput("Secret cannot be empty".to_string()));
    }
    if secret.len() > MAX_SECRET_SIZE {
        return Err(Error::InvalidInput("Secret too large".to_string()));
    }
    // Process secret...
    Ok(())
}
```

## 🔒 Security Guidelines

### Security-First Development

**Critical Security Requirements:**

1. **Zero Vulnerability Policy**: All code must pass `cargo audit` with 0 vulnerabilities
2. **Input Validation**: Validate all inputs at system boundaries
3. **Secure Defaults**: Implement secure-by-default configurations
4. **Least Privilege**: Grant minimum required permissions
5. **Fail-Safe Design**: Default to secure behavior on errors

### Cryptographic Standards

**Algorithm Selection:**
- **Signatures**: Ed25519 (quantum-resistant)
- **Encryption**: AES-256-GCM (authenticated encryption)
- **Key Exchange**: Kyber (post-quantum KEM)
- **Hashing**: SHA-3-256 or BLAKE3

**Key Management:**
- Implement automatic key rotation
- Use hardware security modules (HSM) when available
- Never log sensitive key material
- Implement secure key backup and recovery

### Security Testing

**Required Security Tests:**
```rust
#[cfg(test)]
mod security_tests {
    #[test]
    fn test_no_timing_attacks() {
        // Test for timing attack resistance
    }

    #[test]
    fn test_input_validation() {
        // Test input validation boundaries
    }

    #[test]
    fn test_secure_defaults() {
        // Test secure default configurations
    }
}
```

## 🧪 Testing Requirements

### Test Coverage Standards

**Minimum Coverage Requirements:**
- **Unit Tests**: 80%+ coverage for all modules
- **Integration Tests**: Full API workflow coverage
- **Security Tests**: All security-critical paths tested
- **Performance Tests**: Benchmark critical operations

**Test Organization:**
```
tests/
├── unit/              # Unit tests
├── integration/       # Integration tests
├── security/          # Security-specific tests
└── performance/       # Performance benchmarks
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name

# Run with coverage
cargo tarpaulin --out Html

# Run security tests only
cargo test --test security

# Run performance benchmarks
cargo bench
```

## 📚 Documentation

### Documentation Standards

**Code Documentation:**
```rust
/// Processes a secret with comprehensive security validation
///
/// # Arguments
/// * `secret` - The secret data to process
/// * `metadata` - Additional processing metadata
///
/// # Returns
/// Returns `Ok(())` on success, `Err` with detailed error information
///
/// # Security Notes
/// This function implements multiple layers of validation and encryption
/// to ensure the confidentiality and integrity of secret data.
///
/// # Examples
/// ```
/// use secreton::vault::process_secret;
///
/// let result = process_secret("my-secret", &metadata);
/// assert!(result.is_ok());
/// ```
pub fn process_secret(secret: &str, metadata: &Metadata) -> Result<(), Error> {
    // Implementation...
}
```

**API Documentation:**
- OpenAPI/Swagger specifications for all endpoints
- Comprehensive error response documentation
- Authentication and authorization requirements
- Rate limiting and usage guidelines

## 📝 Commit Guidelines

### Conventional Commits

Format: `type(scope): description`

**Types:**
- `feat`: New features
- `fix`: Bug fixes
- `security`: Security-related changes
- `docs`: Documentation updates
- `refactor`: Code refactoring
- `test`: Test additions/updates
- `chore`: Maintenance tasks

**Examples:**
```
feat(auth): add multi-factor authentication support
security(crypto): patch RSA timing vulnerability CVE-2023-12345
fix(api): resolve memory leak in request handler
docs(readme): update installation instructions
refactor(db): optimize query performance
test(security): add timing attack resistance tests
```

### Security Commit Requirements

**Security-Related Commits:**
- Must include CVE reference if applicable
- Must not disclose vulnerability details in commit message
- Must reference security advisory or issue number
- Must be reviewed by security team before merge

## 🔄 Pull Request Process

### PR Template

**Required Information:**
- Detailed description of changes
- Security impact assessment
- Test coverage information
- Breaking changes documentation
- Migration guide if applicable

**PR Checklist:**
- [ ] Security audit passed (`cargo audit`)
- [ ] Code quality checks passed (`cargo clippy`)
- [ ] All tests passing (`cargo test`)
- [ ] Documentation updated
- [ ] Security review completed
- [ ] Performance impact assessed

### Review Process

**Review Requirements:**
1. **Automated Checks**: CI/CD pipeline must pass
2. **Security Review**: Security team review for security-critical changes
3. **Code Review**: At least 2 maintainer approvals
4. **Testing**: All tests must pass in CI environment
5. **Documentation**: Updated documentation reviewed

## 🚨 Security Reporting

### Responsible Disclosure

**Report Security Issues:**
- Email: security@cipherce.com
- PGP Key: Available at https://cipherce.com/security/pgp
- Response Time: Within 24 hours
- Disclosure: Coordinated disclosure after fix

**Bug Bounty Program:**
- Scope: Secreton core components and APIs
- Rewards: Up to $10,000 for critical vulnerabilities
- Exclusions: Third-party dependencies, user error

### Security Assessment

**Security Review Checklist:**
- [ ] Input validation implemented
- [ ] Output encoding applied
- [ ] Authentication required
- [ ] Authorization enforced
- [ ] Secure session management
- [ ] CSRF protection implemented
- [ ] XSS prevention measures
- [ ] SQL injection prevention
- [ ] Secure configuration defaults
- [ ] Error handling doesn't leak information
- [ ] Logging doesn't expose sensitive data

---

## 📞 Support

**Community Support:**
- GitHub Discussions: https://github.com/cipherce/secreton/discussions
- Discord: https://discord.gg/cipherce
- Documentation: https://docs.cipherce.com/secreton

**Enterprise Support:**
- Email: enterprise@cipherce.com
- Phone: +1 (555) 123-4567
- SLA: 24/7 enterprise support available

---

*Thank you for contributing to Secreton by Cipherce! Your contributions help make enterprise security more accessible and robust.*
   ```bash
   git clone https://github.com/your-username/secreton.git
   cd secreton
   ```

2. **Install Dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install build-essential libssl-dev pkg-config
   
   # RHEL/CentOS/Fedora  
   sudo dnf install gcc openssl-devel pkg-config
   
   # macOS
   brew install openssl pkg-config
   ```

3. **Build and Test**:
   ```bash
   cargo build --workspace
   cargo test --workspace
   ./demo_api.sh  # Test HTTP API
   ./demo_cli.sh  # Test CLI Tool
   ```

## 🏗️ Architecture Overview

Understanding Secreton architecture is crucial for effective contributions:

### System Components

```
secreton/
├── crates/
│   ├── core/          # Core types and traits
│   ├── crypto/        # Cryptographic implementations  
│   ├── api/           # HTTP API server (Axum-based)
│   ├── storage/       # Storage backends
│   ├── cli/           # Command-line interface ✨ NEW
│   └── agent/         # Future: HA agent
├── config/            # Configuration files
├── docs/              # Documentation
├── examples/          # Code examples
├── scripts/           # Utility scripts
└── tests/             # Integration tests
```

### Key Architecture Principles

### Development Workflow

1. **Create Feature Branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Development Environment**:
   ```bash
   # Set environment for development
   export RUST_LOG=debug
   export RUST_BACKTRACE=1
   export SECRETON_LOG_LEVEL=debug
   ```

3. **Build and Test**:
   ```bash
   # Full workspace build
   cargo build --workspace
   
   # Run all tests
   cargo test --workspace
   
   # Run specific crate tests
   cargo test -p secreton-core
   cargo test -p secreton-cli
   
   # Integration tests
   cargo test --test integration
   ```

4. **Code Quality**:
   ```bash
   # Format code (required)
   cargo fmt --all
   
   # Lint code (required)
   cargo clippy --workspace --all-targets -- -D warnings
   
   # Security audit
   cargo audit
   ```

## 🧰 Development Environment

### Recommended IDE Setup

**VS Code Extensions:**
- `rust-analyzer`: Rust language support with IntelliSense
- `CodeLLDB`: Debugging support for Rust
- `Better TOML`: Configuration file highlighting
- `GitLens`: Advanced Git integration
- `Thunder Client`: API testing (alternative to Postman)

**Alternative IDEs:**
- **IntelliJ IDEA**: With Rust plugin
- **Neovim/Vim**: With rust-analyzer LSP
- **Emacs**: With rust-mode and LSP support

### Environment Configuration

Create development configuration:

```bash
# Create .env file for development
cat > .env << EOF
# Development configuration
SECRETON_HOST=127.0.0.1
SECRETON_PORT=8200
SECRETON_LOG_LEVEL=debug
RUST_LOG=secreton=debug,tower_http=debug
RUST_BACKTRACE=full

# Testing settings
SECRETON_TEST_MODE=true
SECRETON_STORAGE_BACKEND=memory

# Security (development only)
SECRETON_TLS_ENABLED=false
SECRETON_AUTH_DISABLED=true  # Only for development!
EOF
```

### Build Targets

```bash
# Build specific components
cargo build -p secreton-core      # Core library
cargo build -p secreton-crypto    # Crypto engine
cargo build -p secreton-api       # HTTP API server
cargo build -p secreton-cli       # CLI tool
cargo build -p secreton-storage   # Storage backends

# Build with features
cargo build --features sqlite    # SQLite storage backend
cargo build --features postgres  # PostgreSQL backend
cargo build --all-features      # All available features

# Release builds
cargo build --release --workspace
```

# Lint code
cargo clippy
```

## Contributing Process

### 1. Issue Creation

Before starting work:

- **Search existing issues** to avoid duplication
- **Create detailed issue** with:
  - Clear problem description
  - Expected vs actual behavior
  - Steps to reproduce (for bugs)
  - Use case and requirements (for features)

### 2. Issue Types

- 🐛 **Bug Report**: Something is broken
- ✨ **Feature Request**: New functionality
- 🔒 **Security Issue**: Security vulnerabilities (use private channels)
- 📚 **Documentation**: Documentation improvements
- 🧹 **Refactoring**: Code cleanup without behavior changes
- ⚡ **Performance**: Performance improvements

### 3. Branch Strategy

- **main**: Stable release branch
- **develop**: Development integration branch
- **feature/xxx**: Feature development branches
- **bugfix/xxx**: Bug fix branches
- **hotfix/xxx**: Critical production fixes

### 4. Work Assignment

- Comment on issues to request assignment
- Wait for maintainer approval before starting work
- One person per issue to avoid duplicate effort

## Code Standards

### Rust Code Style

Follow standard Rust conventions:

```rust
// Use descriptive names
fn create_encryption_key(key_type: KeyType) -> CryptoResult<EncryptionKey> {
    // Implementation
}

// Document public APIs
/// Creates a new transit key for encryption operations.
/// 
/// # Arguments
/// 
/// * `name` - Unique name for the key
/// * `key_type` - Type of encryption algorithm to use
/// 
/// # Returns
/// 
/// Returns the created key or an error if creation fails.
pub fn create_key(name: &str, key_type: KeyType) -> CryptoResult<TransitKey> {
    // Implementation
}
```

### Error Handling

Use comprehensive error handling:

```rust
// Define custom error types
#[derive(Debug, thiserror::Error)]
pub enum SecretonError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(#[from] CryptoError),
    
    #[error("Storage operation failed: {0}")]
    StorageError(#[from] StorageError),
}

// Use Result types consistently
type SecretonResult<T> = Result<T, SecretonError>;
```

### Module Organization

Follow the established crate structure:

```
crates/
├── core/           # Shared types and traits
├── crypto/         # Cryptographic implementations
├── storage/        # Storage backends
├── api/            # HTTP API and routing
├── agent/          # Distributed agent
├── ui/             # Web interface
└── cli/            # Command-line tools
```

### Configuration Management

Use consistent configuration patterns:

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub tls_cert_file: Option<PathBuf>,
    pub tls_key_file: Option<PathBuf>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 8200,
            tls_cert_file: None,
            tls_key_file: None,
        }
    }
}
```

## Security Guidelines

### Security-First Development

- **Never log sensitive data** (keys, secrets, tokens)
- **Use secure random generation** for all cryptographic material
- **Implement constant-time comparisons** for sensitive operations
- **Zero memory** containing sensitive data after use
- **Validate all inputs** thoroughly

### Cryptographic Standards

- Use only **reviewed and approved algorithms**:
  - AES-256-GCM for symmetric encryption
  - ChaCha20-Poly1305 for high-performance scenarios
  - RSA-4096 or Ed25519 for asymmetric operations
- **No custom cryptography** - use established libraries
- **Key sizes**: Minimum 256-bit for symmetric, 4096-bit RSA, 256-bit Ed25519

### Memory Safety

```rust
// Zero sensitive memory
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(ZeroizeOnDrop)]
struct SecretKey {
    key_material: Vec<u8>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.key_material.zeroize();
    }
}
```

### Input Validation

```rust
fn validate_key_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() || name.len() > 64 {
        return Err(ValidationError::InvalidKeyName);
    }
    
    if !name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err(ValidationError::InvalidCharacters);
    }
    
    Ok(())
}
```

## Testing

### Test Categories

1. **Unit Tests**: Individual function testing
2. **Integration Tests**: Component interaction testing
3. **Security Tests**: Cryptographic and security validation
4. **Performance Tests**: Benchmarking and load testing

### Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_key_creation() {
        let engine = TransitEngine::new();
        let result = engine.create_key("test-key", KeyType::Aes256Gcm);
        
        assert!(result.is_ok());
        let key = result.unwrap();
        assert_eq!(key.name(), "test-key");
    }
    
    #[tokio::test]
    async fn test_encryption_roundtrip() {
        // Async test implementation
    }
}
```

### Security Testing

```rust
#[test]
fn test_key_material_not_logged() {
    // Ensure sensitive data doesn't appear in logs
    let key = create_test_key();
    let log_output = capture_log_output();
    
    assert!(!log_output.contains(&hex::encode(&key.material())));
}
```

### Performance Testing

```rust
#[bench]
fn bench_encryption_performance(b: &mut Bencher) {
    let engine = TransitEngine::new();
    let key = engine.create_key("bench-key", KeyType::Aes256Gcm).unwrap();
    let data = b"Hello, World!";
    
    b.iter(|| {
        let _encrypted = engine.encrypt(&key, data).unwrap();
    });
}
```

### Running Tests

```bash
# All tests
cargo test

# Specific test module
cargo test crypto::tests

# Integration tests only
cargo test --test integration

# Security tests
cargo test --test security

# Benchmarks
cargo bench

# With coverage
cargo tarpaulin --out html
```

## Documentation

### Code Documentation

Document all public APIs:

```rust
/// Transit engine for cryptographic operations.
///
/// The `TransitEngine` provides encryption, decryption, and key management
/// services following HashiCorp Vault's transit backend API.
///
/// # Examples
///
/// ```
/// use secreton_crypto::TransitEngine;
/// 
/// let engine = TransitEngine::new();
/// let key = engine.create_key("my-key", KeyType::Aes256Gcm)?;
/// 
/// let plaintext = b"Hello, World!";
/// let ciphertext = engine.encrypt(&key, plaintext)?;
/// let decrypted = engine.decrypt(&key, &ciphertext)?;
/// 
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
pub struct TransitEngine {
    // Implementation
}
```

### README Updates

Update relevant documentation:
- API examples for new endpoints
- Configuration options for new features
- Installation instructions for new dependencies

### Changelog Entries

Follow [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
### Added
- New transit key rotation endpoint `/v1/transit/keys/{name}/rotate`
- Support for Ed25519 digital signatures

### Changed
- Improved error messages for validation failures
- Updated default key size from 2048 to 4096 bits for RSA

### Fixed
- Memory leak in key cleanup process
- Race condition in concurrent key operations

### Security
- Fixed timing attack vulnerability in key comparison
```

## Commit Guidelines

### Commit Message Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Test additions or changes
- `chore`: Build process or auxiliary tool changes
- `security`: Security-related changes

### Examples

```
feat(crypto): add ChaCha20-Poly1305 encryption support

Implement ChaCha20-Poly1305 as an alternative to AES-256-GCM
for high-performance encryption scenarios. Includes key generation,
encryption, and decryption operations.

- Add ChaCha20Poly1305 key type
- Implement encrypt/decrypt operations
- Add comprehensive tests
- Update API documentation

Closes #123
```

```
security(auth): fix timing attack in token comparison

Replace string comparison with constant-time comparison
to prevent timing-based attacks on authentication tokens.

This addresses a potential security vulnerability where
attackers could determine valid token prefixes through
timing analysis.

CVE: Pending
```

### Commit Best Practices

- **Atomic commits**: One logical change per commit
- **Descriptive subjects**: Clear, concise descriptions
- **Detailed body**: Explain the "why", not just "what"
- **Reference issues**: Link to related issues/PRs
- **Sign commits**: Use GPG signing for security

## Pull Request Process

### Before Creating PR

1. **Ensure tests pass**:
   ```bash
   cargo test
   cargo clippy
   cargo fmt --check
   ```

2. **Update documentation** if needed
3. **Add changelog entry** for user-facing changes
4. **Rebase on latest main**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### PR Description Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
- [ ] Unit tests
- [ ] Integration tests  
- [ ] Manual testing
- [ ] Security testing

## Checklist
- [ ] My code follows the style guidelines
- [ ] I have performed a self-review
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Security Considerations
(If applicable) Describe any security implications of this change.

## Breaking Changes
(If applicable) Describe any breaking changes and migration steps.
```

### PR Requirements

- **Descriptive title** and detailed description
- **All tests passing** in CI
- **Code coverage** maintained or improved
- **Documentation updated** for user-facing changes
- **Changelog entry** added
- **Security review** for security-related changes

## Review Process

### Review Criteria

Reviewers will check for:

1. **Functionality**: Does the code work as intended?
2. **Security**: Are there any security implications?
3. **Performance**: Any performance impacts?
4. **Style**: Follows project code standards?
5. **Tests**: Adequate test coverage?
6. **Documentation**: Properly documented?

### Review Guidelines

**For Contributors:**
- Respond promptly to review feedback
- Make requested changes in separate commits
- Don't force-push after review starts
- Be open to suggestions and criticism

**For Reviewers:**
- Be constructive and respectful
- Explain the reasoning behind suggestions
- Focus on code quality and security
- Approve only when confident in the changes

### Security Review

Security-sensitive changes require additional review:

- **Two-person review rule**: At least two maintainers must approve
- **Security expert review**: Must include someone with security expertise
- **Extended review period**: Minimum 48 hours before merge
- **Audit trail**: Document security considerations

## Release Process

### Release Planning

1. **Feature freeze**: Stop accepting new features
2. **Release candidate**: Create RC branch for testing
3. **Testing period**: Comprehensive testing and validation
4. **Documentation review**: Ensure all docs are updated
5. **Security audit**: Final security review
6. **Release**: Tag and publish new version

### Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped in all relevant files
- [ ] Security review completed
- [ ] Performance benchmarks run
- [ ] Release notes prepared
- [ ] Deployment tested

## Getting Help

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Security Email**: security@secreton.io (for security issues only)
- **Documentation**: See [docs/](docs/) directory

### Mentorship

New contributors can request mentorship for:
- Understanding the codebase
- Learning Rust best practices
- Security-focused development
- Code review process

### Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Cryptography Best Practices](https://paragonie.com/blog/2017/12/2018-guide-building-secure-php-software)
- [HashiCorp Vault Documentation](https://www.vaultproject.io/docs)

---

Thank you for contributing to Secreton! Your contributions help make secure secret management accessible and reliable for everyone.
