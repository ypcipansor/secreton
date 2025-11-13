# Contributing to Secreton

Thank you for your interest in contributing to Secreton! We're building an enterprise-grade secrets management system, and we appreciate your help in making it better.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Issue Guidelines](#issue-guidelines)
- [Security](#security)
- [Community](#community)

## 📜 Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment for everyone. We expect all contributors to:

- Be respectful and considerate
- Welcome newcomers and help them get started
- Accept constructive criticism gracefully
- Focus on what's best for the community
- Show empathy towards other community members

### Unacceptable Behavior

- Harassment, discriminatory language, or personal attacks
- Trolling, insulting comments, or derogatory remarks
- Publishing private information without permission
- Any conduct that could be considered inappropriate in a professional setting

## 🚀 Getting Started

### Prerequisites

Before you begin, ensure you have:

- **Rust 1.90+**: `rustup update stable`
- **PostgreSQL 15+**: For local development
- **Git**: For version control
- **Docker** (optional): For containerized testing
- **Basic knowledge**: Rust, async programming, cryptography concepts

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/secreton.git
   cd secreton
   ```

3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/analisaperlengkapan/secreton.git
   ```

4. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## 🛠️ Development Environment

### Initial Setup

1. **Install Rust Components**
   ```bash
   rustup component add rustfmt clippy
   rustup component add llvm-tools-preview  # For coverage
   ```

2. **Install Development Tools**
   ```bash
   # Essential tools
   cargo install cargo-watch      # Watch for file changes
   cargo install cargo-tarpaulin  # Code coverage
   cargo install cargo-audit      # Security auditing
   cargo install cargo-outdated   # Check outdated deps
   cargo install cargo-deny       # License and security checks
   cargo install cargo-llvm-cov   # Coverage reporting
   ```

3. **Setup Database**
   ```bash
   # Using Docker
   docker run --name secreton-dev-db \
     -e POSTGRES_USER=secreton_user \
     -e POSTGRES_PASSWORD=dev_password \
     -e POSTGRES_DB=secreton_db \
     -p 5432:5432 \
     -d postgres:15-alpine
   
   # Or install PostgreSQL natively
   # Ubuntu/Debian
   sudo apt-get install postgresql postgresql-contrib
   
   # macOS
   brew install postgresql@15
   ```

4. **Configure Environment**
   ```bash
   cp .env.example .env
   # Edit .env with your local settings
   nano .env
   ```

5. **Verify Setup**
   ```bash
   # Check all tools are installed
   rustc --version
   cargo --version
   psql --version
   
   # Build project
   cargo build --workspace
   
   # Run tests
   cargo test --workspace
   ```

## 📁 Project Structure

Secreton is organized as a Cargo workspace with multiple crates:

```
secreton/
├── .github/              # GitHub Actions workflows
│   ├── workflows/        # CI/CD pipelines
│   └── codeql-config.yml # CodeQL configuration
├── crates/               # Rust crates (workspace members)
│   ├── api/             # REST API server (Axum)
│   ├── agent/           # Sidecar agent for auto-auth
│   ├── auth/            # Authentication methods (JWT, OAuth, LDAP, RADIUS)
│   ├── cli/             # Command-line interface
│   ├── common/          # Shared utilities and helpers
│   ├── config/          # Configuration management
│   ├── core/            # Core business logic and services
│   ├── crypto/          # Cryptography operations (RustCrypto)
│   ├── enterprise/      # Enterprise features
│   ├── errors/          # Error types and handling
│   ├── infrastructure/  # Infrastructure integrations (K8s, Docker)
│   ├── integrations/    # Third-party integrations (AWS, GCP)
│   ├── monitoring/      # Metrics and observability
│   ├── performance/     # Performance optimizations
│   ├── replication/     # High availability and replication
│   ├── secrets/         # Secret engines base
│   ├── secrets-database/ # Database secret engine
│   ├── secrets-pki/     # PKI secret engine
│   ├── security/        # Security features and audit
│   ├── storage/         # Storage backends (PostgreSQL, Redis, etc.)
│   └── ui/              # Web UI (optional, Leptos)
├── config/              # Configuration files
├── tests/               # Integration tests
├── docs/                # Documentation
├── Cargo.toml           # Workspace manifest
├── deny.toml            # Cargo deny configuration
└── .env.example         # Example environment variables
```

### Key Crates

- **secreton-api**: Main HTTP API server, REST endpoints, OpenAPI docs
- **secreton-core**: Core business logic, secret engines, policies
- **secreton-crypto**: All cryptographic operations, encryption, signing
- **secreton-auth**: Authentication methods and token management
- **secreton-storage**: Storage backend abstraction and implementations
- **secreton-cli**: Command-line tool for users

## 🔄 Development Workflow

### Day-to-Day Development

1. **Sync with Upstream**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Make Changes**
   - Write code following our standards
   - Add tests for new functionality
   - Update documentation

3. **Test Locally**
   ```bash
   # Run tests continuously
   cargo watch -x test
   
   # Or run manually
   cargo test --workspace --all-features
   ```

4. **Format and Lint**
   ```bash
   # Auto-format code
   cargo fmt --all
   
   # Check for issues
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   ```

5. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature"
   # Follow conventional commits format
   ```

6. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

### Running the Project

**API Server:**
```bash
# Development mode with auto-reload
cargo watch -x 'run -p secreton-api --bin api_server'

# Or run directly
cargo run -p secreton-api --bin api_server

# With debug logging
RUST_LOG=debug cargo run -p secreton-api --bin api_server
```

**Agent:**
```bash
cargo run -p secreton-agent
```

**CLI:**
```bash
cargo run -p secreton-cli -- --help
cargo run -p secreton-cli -- kv put secret/test value=hello
```

## 📝 Coding Standards

### Rust Style Guide

We follow the official Rust style guide with some additions:

1. **Formatting**: Use `rustfmt` (no exceptions)
   ```bash
   cargo fmt --all
   ```

2. **Linting**: All `clippy` warnings must be addressed
   ```bash
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   ```

3. **Naming Conventions**:
   - **Crates**: `secreton-{module}` (kebab-case)
   - **Modules**: `snake_case`
   - **Types/Structs**: `PascalCase`
   - **Functions/Methods**: `snake_case`
   - **Constants**: `SCREAMING_SNAKE_CASE`
   - **Lifetimes**: `'a`, `'b`, short and descriptive

4. **Error Handling**:
   - Use `Result<T, SecretonError>` for fallible operations
   - Never use `unwrap()` or `expect()` in production code
   - Use `?` operator for error propagation
   - Add context to errors: `.context("what failed")?`

5. **Async Code**:
   - Use `async fn` for all I/O operations
   - Use `tokio` as the async runtime
   - Prefer `async_trait` for async traits
   - Avoid blocking operations in async code

6. **Comments**:
   - Use `///` for public API documentation
   - Use `//` for implementation comments
   - Write doc tests in documentation
   - Explain "why", not "what"

7. **Security**:
   - Use `zeroize` for sensitive data in memory
   - Never log secrets or credentials
   - Use constant-time operations for crypto
   - Validate all inputs
   - Sanitize all outputs

### Code Organization

**File Structure:**
```rust
// Standard ordering:
// 1. Module documentation
//! Module description

// 2. Imports (grouped)
use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::SecretonError;
use crate::types::SecretData;

// 3. Types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MyType {
    // fields
}

// 4. Implementations
impl MyType {
    // Public methods first
    pub fn new() -> Self { }
    
    // Private methods after
    fn internal_method(&self) { }
}

// 5. Traits
impl MyTrait for MyType { }

// 6. Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_something() { }
}
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting)
- `refactor`: Code refactoring
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `ci`: CI/CD changes
- `build`: Build system changes

**Examples:**
```
feat(crypto): add ChaCha20-Poly1305 cipher support

fix(api): correct token validation error handling

docs(readme): update installation instructions

test(storage): add integration tests for PostgreSQL backend
```

## 🧪 Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions/methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Benchmarks and load tests
5. **Security Tests**: Cryptography and vulnerability tests

### Writing Tests

**Unit Tests:**
```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_secret_encryption() {
        let secret = Secret::new("password123");
        let encrypted = secret.encrypt().unwrap();
        
        assert_ne!(secret.data(), encrypted.data());
        assert_eq!(encrypted.decrypt().unwrap(), secret);
    }
    
    #[tokio::test]
    async fn test_async_operation() {
        let service = MyService::new().await;
        let result = service.do_something().await;
        
        assert!(result.is_ok());
    }
}
```

**Integration Tests:**
```rust
// tests/integration_test.rs
use secreton_api::Server;
use secreton_core::SecretEngine;

#[tokio::test]
async fn test_api_secret_storage() {
    let server = Server::new_test().await;
    let client = server.client();
    
    // Test create
    let response = client
        .post("/v1/secret/data/myapp")
        .json(&json!({"value": "secret"}))
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
    
    // Test retrieve
    let response = client
        .get("/v1/secret/data/myapp")
        .send()
        .await
        .unwrap();
    
    assert_eq!(response.status(), 200);
}
```

### Running Tests

```bash
# Run all tests
cargo test --workspace --all-features

# Run specific crate tests
cargo test -p secreton-core

# Run with output
cargo test --workspace -- --nocapture

# Run ignored tests
cargo test --workspace -- --ignored

# Run single test
cargo test test_name

# Run tests matching pattern
cargo test secret
```

### Test Coverage

```bash
# Generate coverage report
cargo tarpaulin --workspace --all-features --out Html

# Or use llvm-cov
cargo llvm-cov --workspace --all-features --html

# View report
open tarpaulin-report.html
```

**Coverage Requirements:**
- New features: **minimum 80% coverage**
- Critical paths (crypto, auth): **minimum 90% coverage**
- Bug fixes: **must add test that catches the bug**

### Benchmarks

```bash
# Run benchmarks
cargo bench --workspace

# Run specific benchmark
cargo bench -p secreton-crypto -- encryption

# Compare results
cargo bench --workspace -- --save-baseline main
# Make changes
cargo bench --workspace -- --baseline main
```

## 📚 Documentation

### Code Documentation

1. **Public APIs**: All public items must have documentation
   ```rust
   /// Encrypts data using AES-256-GCM.
   ///
   /// # Arguments
   ///
   /// * `data` - The plaintext data to encrypt
   /// * `key` - The encryption key (must be 32 bytes)
   ///
   /// # Returns
   ///
   /// Returns the encrypted data wrapped in a `Result`.
   ///
   /// # Errors
   ///
   /// Returns `CryptoError` if encryption fails.
   ///
   /// # Examples
   ///
   /// ```
   /// use secreton_crypto::encrypt;
   ///
   /// let key = [0u8; 32];
   /// let data = b"secret data";
   /// let encrypted = encrypt(data, &key).unwrap();
   /// ```
   pub fn encrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
       // implementation
   }
   ```

2. **Modules**: Document module purpose
   ```rust
   //! Authentication module.
   //!
   //! This module provides various authentication methods including:
   //! - JWT tokens
   //! - OAuth 2.0 / OIDC
   //! - LDAP
   //! - Multi-factor authentication
   ```

3. **Examples**: Provide runnable examples
   ```rust
   /// # Examples
   ///
   /// ```
   /// use secreton_core::Secret;
   ///
   /// let secret = Secret::new("my_password");
   /// assert!(!secret.is_empty());
   /// ```
   ```

### Documentation Generation

```bash
# Generate documentation
cargo doc --workspace --all-features --no-deps

# Open in browser
cargo doc --workspace --all-features --no-deps --open

# Check for broken links
cargo doc --workspace --all-features --no-deps 2>&1 | grep warning
```

### README and Guides

- Keep README.md up to date
- Add examples for new features
- Update API documentation
- Write migration guides for breaking changes

## 🔀 Pull Request Process

### Before Submitting

1. **Ensure Tests Pass**
   ```bash
   cargo test --workspace --all-features
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo fmt --all -- --check
   ```

2. **Update Documentation**
   - Add/update inline documentation
   - Update README if needed
   - Add examples for new features

3. **Add Changelog Entry**
   - Document changes for users
   - Note any breaking changes

4. **Rebase on Latest**
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

### Submitting PR

1. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Open Pull Request**
   - Use descriptive title (conventional commits format)
   - Fill out PR template completely
   - Link related issues
   - Add screenshots for UI changes
   - Mark as draft if work in progress

3. **PR Description Should Include**:
   - Summary of changes
   - Motivation and context
   - Testing performed
   - Breaking changes (if any)
   - Related issues

### PR Review Process

1. **Automated Checks**: CI must pass (GitHub Actions)
2. **Code Review**: At least one approval required
3. **Changes Requested**: Address feedback promptly
4. **Approval**: Maintainer will merge

### After Merge

1. **Delete Branch**
   ```bash
   git branch -d feature/your-feature-name
   git push origin --delete feature/your-feature-name
   ```

2. **Sync Your Fork**
   ```bash
   git checkout main
   git pull upstream main
   git push origin main
   ```

## 🐛 Issue Guidelines

### Reporting Bugs

**Before Opening an Issue:**
- Search existing issues
- Check if it's already fixed in latest version
- Reproduce with minimal example

**Bug Report Should Include:**
- Clear, descriptive title
- Steps to reproduce
- Expected behavior
- Actual behavior
- Environment (OS, Rust version, etc.)
- Logs and error messages
- Minimal reproducible example

**Template:**
```markdown
### Description
Brief description of the bug.

### Steps to Reproduce
1. Step one
2. Step two
3. Step three

### Expected Behavior
What should happen.

### Actual Behavior
What actually happened.

### Environment
- OS: Ubuntu 22.04
- Rust: 1.90.0
- Secreton: 0.1.0

### Logs
```
Error logs here
```

### Minimal Example
```rust
// Code to reproduce
```
```

### Feature Requests

**Template:**
```markdown
### Feature Description
Clear description of the feature.

### Use Case
Why is this feature needed? What problem does it solve?

### Proposed Solution
How should this feature work?

### Alternatives Considered
Other approaches you've considered.

### Additional Context
Any other relevant information.
```

## 🔒 Security

### Security Policy

- **DO NOT** open public issues for security vulnerabilities
- Email security issues to: **security@secreton.io**
- We will respond within 48 hours
- Coordinated disclosure process
- Security advisory will be published after fix

### Security Testing

Before submitting security-related PRs:

1. **Run Security Audit**
   ```bash
   cargo audit
   cargo deny check advisories
   ```

2. **Check for Secrets**
   ```bash
   # Never commit secrets or credentials
   git log -p | grep -i "password\|secret\|key" --color
   ```

3. **Test Cryptography**
   ```bash
   cargo test -p secreton-crypto --all-features
   cargo bench -p secreton-crypto
   ```

### Secure Coding Checklist

- [ ] Input validation on all user inputs
- [ ] Output encoding to prevent injection
- [ ] Use parameterized queries (no SQL injection)
- [ ] Sensitive data wiped from memory (`zeroize`)
- [ ] Constant-time operations for crypto
- [ ] No secrets in logs or error messages
- [ ] TLS for all network communication
- [ ] Authentication and authorization checks

## 🤝 Community

### Getting Help

- **GitHub Discussions**: For questions and discussions
- **GitHub Issues**: For bugs and feature requests
- **Discord**: Join our community chat (link in README)
- **Email**: support@secreton.io

### Resources

- **Documentation**: https://secreton.io/docs
- **API Reference**: https://secreton.io/api
- **Examples**: https://github.com/analisaperlengkapan/secreton-examples
- **Blog**: https://secreton.io/blog

### Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Invited to contributor events

## 📋 Checklist for Contributors

Before submitting your PR, ensure:

- [ ] Code follows Rust style guidelines
- [ ] All tests pass (`cargo test --workspace --all-features`)
- [ ] Code is formatted (`cargo fmt --all`)
- [ ] No clippy warnings (`cargo clippy --workspace -- -D warnings`)
- [ ] Documentation is updated
- [ ] Changelog entry added (if applicable)
- [ ] Commit messages follow conventional format
- [ ] PR description is complete
- [ ] Tests cover new functionality (>80% coverage)
- [ ] Security considerations addressed
- [ ] No secrets or credentials in code
- [ ] Branch is up to date with main

## 🎉 Thank You!

Thank you for contributing to Secreton! Your efforts help make enterprise-grade security accessible to everyone.

Questions? Feel free to ask in GitHub Discussions or reach out to the maintainers.

**Happy Coding! 🚀🔒**
