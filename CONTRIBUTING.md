# Contributing to Secreton

Thank you for your interest in contributing to Secreton! This document provides comprehensive guidelines for contributors to ensure a smooth and effective development process.

## Table of Contents

- [Development Setup](#development-setup)
- [Code Style and Standards](#code-style-and-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Security Considerations](#security-considerations)
- [Architecture Overview](#architecture-overview)
- [Adding New Features](#adding-new-features)
- [Documentation](#documentation)

## Development Setup

### Prerequisites

- **Rust**: Latest stable version (minimum 1.90)
- **PostgreSQL**: For development and testing (recommended)
- **Git**: For version control
- **Docker**: Optional, for containerized testing

### Initial Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/secreton.git
   cd secreton
   ```

2. **Install Rust Toolchain**
   ```bash
   rustup update stable
   rustup component add rustfmt clippy
   ```

3. **Install Development Tools**
   ```bash
   cargo install cargo-watch cargo-tarpaulin cargo-audit
   ```

4. **Setup Development Database**
   ```bash
   # Using Docker for PostgreSQL
   docker run --name secreton-dev-db -e POSTGRES_PASSWORD=dev_password -e POSTGRES_USER=secreton_user -e POSTGRES_DB=secreton_db -p 5432:5432 -d postgres:15
   ```

5. **Environment Configuration**
   ```bash
   cp .env.example .env
   # Edit .env with your development settings
   ```

### Building the Project

```bash
# Build all workspace members
cargo build --workspace

# Build with all features
cargo build --workspace --all-features

# Build release version
cargo build --workspace --release
```

### Running Tests

```bash
# Run all tests
cargo test --workspace --all-features

# Run tests with coverage
cargo tarpaulin --workspace --all-features --out Lcov

# Run specific crate tests
cargo test -p secreton-core
cargo test -p secreton-api
```

## Code Style and Standards

### Formatting

All code must be formatted with `rustfmt`:

```bash
cargo fmt --all
```

### Linting

We use `clippy` for linting. All warnings must be addressed:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

### Code Quality Standards

- **Memory Safety**: All code must be memory-safe and use Rust's ownership system properly
- **Error Handling**: Use the `secreton-errors` crate for consistent error handling
- **Logging**: Use structured logging with `tracing` crate
- **Async/Await**: Use async/await for all I/O operations
- **Security**: Follow security best practices, use constant-time operations for crypto

### Naming Conventions

- **Crates**: `secreton-{module}` (e.g., `secreton-core`, `secreton-api`)
- **Modules**: `snake_case`
- **Types**: `PascalCase`
- **Functions**: `snake_case`
- **Constants**: `SCREAMING_SNAKE_CASE`

## Testing Guidelines

### Test Organization

- **Unit Tests**: In the same module as the code being tested
- **Integration Tests**: In the `tests/` directory
- **Performance Tests**: In `tests/performance/`
- **Security Tests**: In `tests/security/`

### Test Requirements

1. **Coverage**: All new code must have adequate test coverage
2. **Async Tests**: Use `#[tokio::test]` for async functions
3. **Mock Dependencies**: Use mock implementations for external dependencies
4. **Property-Based Testing**: Use `proptest` for complex logic

### Example Test Structure

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;
    
    #[tokio::test]
    async fn test_feature_functionality() {
        // Arrange
        let setup = create_test_setup().await;
        
        // Act
        let result = setup.test_function().await;
        
        // Assert
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_error_conditions() {
        // Test error scenarios
    }
}
```

## Pull Request Process

### Before Submitting

1. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Ensure All Tests Pass**
   ```bash
   cargo test --workspace --all-features
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo fmt --all -- --check
   ```

3. **Update Documentation**
   - Update relevant documentation
   - Add API documentation for new endpoints
   - Update README if needed

4. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   ```

### Pull Request Requirements

- **Descriptive Title**: Use conventional commit format
- **Detailed Description**: Explain what the PR does and why
- **Test Coverage**: Include tests for new functionality
- **Documentation**: Update relevant documentation
- **Breaking Changes**: Clearly document any breaking changes

### Conventional Commit Format

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

## Issue Reporting

### Bug Reports

When reporting bugs, include:

1. **Environment**: OS, Rust version, PostgreSQL version
2. **Reproduction Steps**: Clear steps to reproduce the issue
3. **Expected Behavior**: What you expected to happen
4. **Actual Behavior**: What actually happened
5. **Logs**: Relevant log output
6. **Stack Trace**: If available

### Feature Requests

For feature requests:

1. **Use Case**: Describe the problem you're trying to solve
2. **Proposed Solution**: How you envision the feature working
3. **Alternatives**: Other approaches you've considered
4. **Impact**: Who would benefit from this feature

## Security Considerations

### Secure Coding Practices

1. **Input Validation**: Always validate and sanitize inputs
2. **Cryptography**: Use audited crypto libraries (RustCrypto suite)
3. **Secrets**: Never log sensitive information
4. **Memory**: Use `zeroize` for sensitive data in memory
5. **Dependencies**: Regularly audit dependencies with `cargo audit`

### Security Testing

- **Fuzzing**: Use cargo-fuzz for critical components
- **Security Scans**: Run security scans in CI/CD
- **Penetration Testing**: Regular security assessments

### Reporting Security Issues

For security vulnerabilities, please email: security@secreton.com

Do not open public issues for security vulnerabilities.

## Architecture Overview

### Workspace Structure

```
secreton/
├── crates/
│   ├── common/          # Shared utilities
│   ├── errors/          # Error handling
│   ├── config/          # Configuration management
│   ├── core/            # Core business logic
│   ├── auth/            # Authentication methods
│   ├── secrets/         # Secret engines
│   ├── crypto/          # Cryptographic operations
│   ├── storage/         # Storage backends
│   ├── api/             # HTTP API server
│   ├── cli/             # Command-line interface
│   ├── agent/           # Sidecar agent
│   ├── monitoring/      # Metrics and monitoring
│   └── security/        # Security features
├── tests/               # Integration tests
├── config/              # Configuration files
└── docs/                # Documentation
```

### Design Principles

- **Domain-Driven Design**: Clear domain boundaries
- **Zero-Trust Architecture**: Security by default
- **Modular Design**: Loosely coupled, highly cohesive modules
- **Async-First**: Non-blocking operations throughout
- **Memory Safety**: Leverage Rust's ownership system

## Adding New Features

### 1. Planning

- Create an issue for discussion
- Get feedback from maintainers
- Plan the implementation approach

### 2. Implementation

- Follow existing patterns and conventions
- Add comprehensive tests
- Update documentation
- Consider backward compatibility

### 3. Adding New Authentication Methods

```rust
// In secreton-auth crate
pub mod your_auth_method {
    use super::*;
    
    pub struct YourAuthMethod {
        // Configuration and state
    }
    
    #[async_trait]
    impl AuthMethod for YourAuthMethod {
        async fn authenticate(&self, request: AuthRequest) -> AuthResult {
            // Implementation
        }
    }
}
```

### 4. Adding New Secret Engines

```rust
// In secreton-secrets crate
pub mod your_engine {
    use super::*;
    
    pub struct YourEngine {
        // Engine state
    }
    
    #[async_trait]
    impl SecretEngine for YourEngine {
        async fn store_secret(&self, path: &str, data: SecretData) -> Result<()> {
            // Implementation
        }
    }
}
```

## Documentation

### Code Documentation

- Use `///` for public API documentation
- Include examples for complex functions
- Document error conditions
- Use `#[doc(hidden)]` for internal APIs

### API Documentation

- Document all REST endpoints
- Include request/response examples
- Document authentication requirements
- Provide curl examples

### README Updates

When adding significant features:

1. Update the features list
2. Add usage examples
3. Update installation instructions
4. Add configuration examples

## Development Workflow

### Daily Development

```bash
# Watch for changes and run tests
cargo watch -x test

# Run specific tests
cargo test -p secreton-core -- auth::tests

# Check for security vulnerabilities
cargo audit

# Format code
cargo fmt

# Run linter
cargo clippy
```

### Performance Testing

```bash
# Run benchmarks
cargo bench

# Profile performance
cargo build --release
perf record ./target/release/secreton-api
```

### Memory Safety

```bash
# Run with sanitizers (nightly Rust)
RUSTFLAGS="-Z sanitizer=address" cargo +nightly run
```

## Getting Help

- **Discord**: Join our development community
- **GitHub Issues**: For bugs and feature requests
- **Documentation**: Check the `/docs` directory
- **Examples**: Look at existing implementations

## License

By contributing to Secreton, you agree that your contributions will be licensed under the Apache-2.0 license.

---

Thank you for contributing to Secreton! Your contributions help make enterprise-grade security accessible to everyone.
