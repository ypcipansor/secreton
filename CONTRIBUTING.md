# Contributing to Secreton

Thank you for your interest in contributing to Secreton! This document provides guidelines and information for contributors.

## 🚀 Quick Start

### Development Environment Setup

1. **Prerequisites**
   ```bash
   # Install Rust 1.90+
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup update

   # Install development tools
   cargo install cargo-audit cargo-fuzz cargo-miri cargo-tarpaulin
   ```

2. **Clone and Setup**
   ```bash
   git clone https://github.com/analisaperlengkapan/secreton.git
   cd secreton

   # Install pre-commit hooks (if available)
   # This will run formatting, linting, and tests before commits
   ```

3. **Verify Setup**
   ```bash
   cargo check
   cargo test
   cargo clippy
   ```

### Development Workflow

1. **Create a Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make Changes**
   - Follow the existing code style
   - Add tests for new functionality
   - Update documentation as needed
   - Run checks frequently: `cargo check && cargo test`

3. **Commit Changes**
   ```bash
   git add .
   git commit -m "feat: add new feature description"
   # Follow conventional commit format
   ```

4. **Create Pull Request**
   - Push your branch
   - Create PR with clear description
   - Link to any relevant issues

## 📋 Development Guidelines

### Code Style

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `rustfmt` for formatting: `cargo fmt`
- Follow `clippy` linting recommendations: `cargo clippy`
- Use meaningful variable and function names
- Add documentation comments for public APIs

### Testing

- **Unit Tests**: Required for all new code
- **Integration Tests**: For API changes
- **Fuzz Tests**: For cryptographic and parsing code
- **Performance Tests**: For performance-critical code

```bash
# Run all tests
cargo test

# Run specific tests
cargo test test_name

# Run with coverage
cargo tarpaulin --out Html

# Run fuzzing
cargo fuzz run target_name
```

### Security

- **Cryptography**: Only use audited libraries (RustCrypto preferred)
- **Memory Safety**: Zeroize sensitive data
- **Input Validation**: Validate all inputs
- **Audit Logging**: Log security-relevant events

### Documentation

- **API Docs**: Document all public functions/structs
- **Code Comments**: Explain complex logic
- **Examples**: Provide usage examples
- **Changelogs**: Update CHANGELOG.md for user-facing changes

## 🏗️ Architecture Overview

### Project Structure

```
crates/
├── common/          # Shared types and utilities
├── errors/          # Error types and handling
├── config/          # Configuration management
├── core/            # Core vault functionality
├── crypto/          # Cryptographic operations
├── storage/         # Storage backend implementations
├── replication/     # Data replication
├── api/             # REST API server
├── cli/             # Command-line interface
├── security/        # Audit logging and security
├── integrations/    # Third-party integrations
├── infrastructure/  # Infrastructure components
├── enterprise/      # Enterprise features
├── secrets/         # Secret engine implementations
├── auth/            # Authentication framework
├── auth-methods/    # Authentication method implementations
├── policies/        # Policy engine
└── ui/              # Web interface (minimal)
```

### Key Components

- **Storage Backends**: Pluggable storage with transaction support
- **Secret Engines**: Modular secret management engines
- **Auth Methods**: Pluggable authentication mechanisms
- **Policy Engine**: Attribute-based access control
- **Audit System**: Comprehensive security event logging

## 🔧 Development Tasks

### High Priority

1. **Complete Authentication API**
   - Implement login/logout endpoints
   - Add token refresh functionality
   - Complete MFA implementation

2. **Replace Mock Implementations**
   - OCI backend: Real Oracle Cloud integration
   - AWS backend: Real AWS credential generation
   - Other cloud backends

3. **Clean Up Technical Debt**
   - Remove unused imports
   - Fix dead code warnings
   - Complete TODO implementations

### Medium Priority

4. **Performance Optimization**
   - Connection pooling improvements
   - Caching layer implementation
   - Async operation optimizations

5. **Additional Secret Engines**
   - Azure credentials
   - GCP credentials
   - Kubernetes secrets

### Low Priority

6. **Web UI Development**
   - Modern React/Vue interface
   - Administrative dashboard
   - User self-service portal

## 🧪 Testing Strategy

### Test Categories

- **Unit Tests**: Individual function/component testing
- **Integration Tests**: End-to-end API testing
- **Performance Tests**: Benchmarking and load testing
- **Security Tests**: Fuzzing and vulnerability testing
- **Compatibility Tests**: Multi-platform testing

### Test Organization

```
tests/
├── unit/            # Unit tests by crate
├── integration/     # Integration tests
├── performance/     # Performance benchmarks
├── security/        # Security-focused tests
└── common/          # Shared test utilities
```

### Fuzzing

Extensive fuzzing targets are available:

```bash
# List all fuzz targets
cargo fuzz list

# Run specific fuzz target
cargo fuzz run crypto_operations -- -max_len=1000

# Run with crash minimization
cargo fuzz run --release api_endpoints
```

## 🔒 Security Considerations

### Cryptographic Code
- Use only audited cryptographic libraries
- Implement proper key management
- Zeroize sensitive data from memory
- Follow cryptographic best practices

### Input Validation
- Validate all user inputs
- Use safe parsing libraries
- Implement rate limiting
- Log suspicious activities

### Access Control
- Implement principle of least privilege
- Use secure defaults
- Regular security audits
- Prompt security updates

## 📝 Pull Request Process

1. **Fork** the repository
2. **Create** a feature branch
3. **Make** your changes with tests
4. **Run** all checks: `cargo check && cargo test && cargo clippy`
5. **Update** documentation if needed
6. **Commit** with conventional commit messages
7. **Push** to your fork
8. **Create** a Pull Request

### PR Requirements

- [ ] Tests pass: `cargo test`
- [ ] Code formatted: `cargo fmt`
- [ ] Linting passes: `cargo clippy`
- [ ] Security audit: `cargo audit`
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (if user-facing)
- [ ] Conventional commit messages

### PR Review Process

1. Automated checks run
2. Code review by maintainers
3. Security review for crypto changes
4. Merge when approved

## 📚 Resources

### Documentation
- [Rust Book](https://doc.rust-lang.org/book/)
- [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- [Tokio Documentation](https://tokio.rs/docs/)
- [RustCrypto Libraries](https://github.com/RustCrypto)

### Security
- [Rust Security Advisories](https://rustsec.org/)
- [Cryptographic Right Answers](https://www.latacora.com/blog/2018/04/03/cryptographic-right-answers/)
- [OWASP Guidelines](https://owasp.org/www-project-top-ten/)

### Tools
- [cargo-audit](https://github.com/RustSec/cargo-audit) - Security vulnerability scanner
- [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) - Fuzz testing
- [cargo-miri](https://github.com/rust-lang/miri) - Interpreter for Rust's mid-level IR

## 🤝 Code of Conduct

This project follows a code of conduct to ensure a welcoming environment for all contributors.

### Expected Behavior
- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn
- Maintain professional communication

### Unacceptable Behavior
- Harassment or discrimination
- Personal attacks
- Disruptive behavior
- Violation of privacy

## 📞 Getting Help

- **Issues**: [GitHub Issues](https://github.com/analisaperlengkapan/secreton/issues)
- **Discussions**: [GitHub Discussions](https://github.com/analisaperlengkapan/secreton/discussions)
- **Documentation**: Check the `docs/` directory

## 🙏 Recognition

Contributors are recognized in CHANGELOG.md and release notes. Significant contributions may be acknowledged in the main README.

---

Thank you for contributing to Secreton! Your efforts help make secrets management more secure and reliable.