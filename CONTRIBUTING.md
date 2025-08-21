# Contributing to Brankas Security Vault System

Thank you for your interest in contributing to Brankas! This document provides comprehensive guidelines for contributing to our security-focused vault system.

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
- **Git**: Version control system
- **OpenSSL**: Development libraries (`libssl-dev` on Ubuntu, `openssl-devel` on RHEL)

**Optional Tools:**
- **Docker**: For containerized development
- **SQLite3**: For local storage backend testing
- **Postman/curl**: For API testing
- **jq**: JSON processing for testing scripts

### Quick Setup

1. **Fork and Clone**:
   ```bash
   git clone https://github.com/your-username/brankas.git
   cd brankas
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

Understanding Brankas architecture is crucial for effective contributions:

### System Components

```
brankas/
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
   export BRANKAS_LOG_LEVEL=debug
   ```

3. **Build and Test**:
   ```bash
   # Full workspace build
   cargo build --workspace
   
   # Run all tests
   cargo test --workspace
   
   # Run specific crate tests
   cargo test -p brankas-core
   cargo test -p brankas-cli
   
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
BRANKAS_HOST=127.0.0.1
BRANKAS_PORT=8200
BRANKAS_LOG_LEVEL=debug
RUST_LOG=brankas=debug,tower_http=debug
RUST_BACKTRACE=full

# Testing settings
BRANKAS_TEST_MODE=true
BRANKAS_STORAGE_BACKEND=memory

# Security (development only)
BRANKAS_TLS_ENABLED=false
BRANKAS_AUTH_DISABLED=true  # Only for development!
EOF
```

### Build Targets

```bash
# Build specific components
cargo build -p brankas-core      # Core library
cargo build -p brankas-crypto    # Crypto engine
cargo build -p brankas-api       # HTTP API server
cargo build -p brankas-cli       # CLI tool
cargo build -p brankas-storage   # Storage backends

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
pub enum BrankasError {
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(#[from] CryptoError),
    
    #[error("Storage operation failed: {0}")]
    StorageError(#[from] StorageError),
}

// Use Result types consistently
type BrankasResult<T> = Result<T, BrankasError>;
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
/// use brankas_crypto::TransitEngine;
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
- **Security Email**: security@brankas.io (for security issues only)
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

Thank you for contributing to Brankas! Your contributions help make secure secret management accessible and reliable for everyone.
