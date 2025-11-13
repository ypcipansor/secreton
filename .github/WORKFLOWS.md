# GitHub Actions Workflows Documentation

This document provides a comprehensive overview of all GitHub Actions workflows configured for the Secreton repository.

## Table of Contents

- [Core CI/CD Workflows](#core-cicd-workflows)
- [Security Workflows](#security-workflows)
- [Automation Workflows](#automation-workflows)
- [Deployment Workflows](#deployment-workflows)
- [Dependabot Configuration](#dependabot-configuration)

## Core CI/CD Workflows

### 1. Rust CI (`rust-ci.yml`)

**Triggers:**
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches
- Manual dispatch

**Jobs:**

#### Check Job
- Runs `cargo check --workspace --all-features` on stable, beta, and nightly Rust
- Validates that code compiles without errors
- Allows nightly failures

#### Build Job
- Runs `cargo build --workspace --all-features` on stable and beta
- Creates release builds on stable
- Depends on check job passing

#### Clippy Job
- Runs `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Enforces all clippy warnings as errors
- Ensures code quality standards

#### Test Job
- Runs `cargo test --workspace --all-features` with PostgreSQL service
- Executes integration and doc tests
- Matrix testing on stable and beta Rust

#### Coverage Job
- Generates code coverage using `cargo-llvm-cov`
- Uploads coverage to Codecov
- Creates coverage artifacts

#### Format Check Job
- Runs `cargo fmt --all -- --check`
- Ensures consistent code formatting

#### Audit Job
- Runs `cargo-audit` to check for security vulnerabilities
- Uses RustSec advisory database

#### Deny Job
- Runs `cargo-deny` to check licenses and banned dependencies
- Enforces dependency policies

#### Documentation Job
- Generates documentation with `cargo doc`
- Validates documentation warnings

**Best Practices:**
- ✅ Multi-stage pipeline with proper job dependencies
- ✅ Rust caching for faster builds
- ✅ Matrix testing across Rust versions
- ✅ PostgreSQL service for integration tests
- ✅ Comprehensive test coverage

## Security Workflows

### 2. CodeQL Analysis (`codeql-analysis.yml`)

**Purpose:** GitHub native code scanning for security vulnerabilities

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Weekly schedule (Monday 02:00 UTC)
- Manual dispatch

**Features:**
- Security and quality query sets
- SARIF upload to GitHub Security tab
- Rust language analysis
- Ignores test files and build artifacts

### 3. Secret Scanning (`secret-scanning.yml`)

**Purpose:** Multi-tool secret detection and scanning

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Daily schedule (03:00 UTC)
- Manual dispatch

**Tools:**
- **Gitleaks:** Comprehensive secret scanner
- **TruffleHog:** Deep secret detection with verification
- **Trivy Secrets:** Container-focused secret scanning
- **Manual Patterns:** Custom regex patterns for hardcoded secrets

**Patterns Checked:**
- AWS credentials (AKIA...)
- GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)
- API keys and tokens
- Password/secret assignments
- OpenAI keys (sk-...)
- Slack tokens (xoxb-...)

**Output:** SARIF results uploaded to GitHub Security tab

### 4. Comprehensive Security Scan (`security-comprehensive.yml`)

**Purpose:** Complete security audit suite

**Triggers:**
- Push to `main` or `develop`
- Pull requests
- Weekly schedule (Sunday 00:00 UTC)
- Manual dispatch

**Tools:**

#### Trivy Vulnerability Scanner
- Scans for known vulnerabilities in dependencies
- Checks configuration issues
- SARIF upload to Security tab

#### Cargo Audit
- Checks Cargo dependencies against RustSec advisory database
- Fails on security warnings

#### Cargo Geiger
- Analyzes unsafe code usage
- Generates reports on unsafe code statistics
- Creates JSON and Markdown reports

#### Dependency Review
- Reviews PR dependencies for security issues
- Blocks moderate+ severity vulnerabilities
- Enforces license policies (blocks GPL-3.0, AGPL-3.0)

#### OSV Scanner
- Scans for Open Source Vulnerabilities
- Checks multiple package ecosystems

#### Semgrep
- Security pattern scanning
- Uses security-audit, secrets, and rust rulesets
- SARIF output

#### Snyk (Optional)
- Additional vulnerability scanning
- Requires SNYK_TOKEN secret
- Continues on error if token not set

## Automation Workflows

### 5. Auto Fix (`auto-fix.yml`)

**Purpose:** Automatically fix and format code

**Triggers:**
- Weekly schedule (Monday 00:00 UTC)
- Manual dispatch

**Process:**
1. Runs `cargo fix --allow-dirty --allow-staged` to fix compiler warnings
2. Runs `cargo fmt --all` to format code
3. Detects changes
4. Creates pull request if changes exist

**PR Details:**
- Branch: `auto-fix/format-{run_number}`
- Labels: `automated`, `code-quality`
- Assignee: Repository owner
- Auto-deletes branch after merge

### 6. PR Validation (`pr-validation.yml`)

**Purpose:** Validate pull requests for quality and standards

**Triggers:**
- PR opened, synchronized, or reopened

**Validations:**

#### PR Title Format
- Enforces semantic commit format
- Allowed types: feat, fix, docs, style, refactor, perf, test, chore, ci, build, revert
- Requires uppercase first letter in subject

#### PR Size Analysis
- Small: <100 lines
- Medium: 100-500 lines
- Large: 500-1000 lines
- XL: >1000 lines
- Auto-labels by size

#### Breaking Changes Detection
- Checks PR body for "BREAKING CHANGE"
- Labels PR with `breaking-change`
- Adds warning in comments

#### Changelog Check
- Verifies if CHANGELOG.md is updated
- Recommends update for medium+ PRs

**Output:** Automated comment with validation report

### 7. Dependabot Auto-Merge (`dependabot.yml`)

**Purpose:** Automatically approve and merge Dependabot PRs

**Triggers:**
- Dependabot PR opened, synchronized, reopened, or ready for review

**Strategy:**

#### Auto-Approve & Auto-Merge
- **Patch updates:** Automatic approval and merge
- **Minor updates:** Automatic approval and merge
- Waits for CI checks to pass
- Uses squash merge strategy

#### Manual Review Required
- **Major updates:** Requires manual review
- Labels: `needs-review`, `major-update`
- Adds comment explaining manual review needed

**Safety:**
- Only acts on Dependabot PRs
- Waits for all CI checks
- Validates update type before merging

## Deployment Workflows

### 8. Deploy to Staging (`deploy-staging.yml`)

**Purpose:** Deploy to staging environment

**Triggers:**
- Push to `develop` branch
- Manual dispatch

**Process:**
1. Run tests and security audit
2. Build release binary
3. Build and push Docker image to GHCR
4. Deploy to staging environment
5. Run integration tests

**Environment:** staging

## Dependabot Configuration

### Configuration File (`.github/dependabot.yml`)

**Update Schedules:**
- All ecosystems: Weekly on Monday 09:00 UTC

**Ecosystems:**

#### 1. Cargo (Rust Dependencies)
- **Limit:** 25 open PRs
- **Grouping Strategy:**
  - RustCrypto packages (aes, chacha20, sha, ring, ed25519, etc.)
  - Async ecosystem (tokio, async-*, futures)
  - Serde ecosystem (serde, toml, config)
  - Security crates (zeroize, secrecy, rustls)
  - Database crates (tokio-postgres, redis, mongodb)
  - AWS SDK crates
  - HTTP/network crates (axum, hyper, tower, tonic)
  - CLI crates (clap)
  - Monitoring crates (prometheus, opentelemetry, tracing)

**Benefits of Grouping:**
- Reduces PR count
- Tests related updates together
- Easier to review related changes
- Maintains compatibility between related crates

#### 2. GitHub Actions
- **Limit:** 10 open PRs
- **Grouping:** All actions grouped together
- Updates workflow actions to latest versions

#### 3. Docker
- **Limit:** 5 open PRs
- Updates base images in Dockerfiles

**Labels Applied:**
- `dependencies`
- Ecosystem-specific labels (rust, github-actions, docker)

## Workflow Best Practices

### Caching
All workflows use `Swatinem/rust-cache@v2` for:
- Cargo registry cache
- Cargo build cache
- Target directory cache

**Benefits:**
- Faster build times (5-10x speedup)
- Reduced GitHub Actions minutes
- Consistent across jobs

### Permissions
All workflows use **least privilege** principle:
- `contents: read` - Read repository content
- `security-events: write` - Upload security results
- `pull-requests: write` - Comment on PRs
- `checks: write` - Update check status

### Matrix Testing
- **Rust versions:** stable, beta, nightly
- **Platforms:** ubuntu-latest (can expand to macOS/Windows)
- **Features:** Tests with all features enabled

### SARIF Upload
All security tools output SARIF format and upload to GitHub Security tab:
- Centralized security findings
- GitHub-native vulnerability management
- Automated security alerts

## Monitoring and Notifications

### GitHub Security Tab
All security findings appear in the Security tab:
- CodeQL findings
- Secret scanning results
- Trivy vulnerabilities
- Semgrep findings
- Dependency review alerts

### PR Comments
Automated comments on PRs for:
- Validation results
- Size analysis
- Breaking changes warnings
- Auto-merge status

### Status Checks
Required status checks for merging:
- Check (stable, beta)
- Build (stable, beta)
- Clippy
- Test (stable, beta)
- Format Check
- Security Audit
- Cargo Deny

## Troubleshooting

### Failed Workflows

**Check Job Fails:**
- Review Cargo.toml for dependency issues
- Check for compilation errors
- Verify feature flags

**Clippy Job Fails:**
- Fix clippy warnings in code
- Update clippy.toml if needed
- Check for pedantic lints

**Test Job Fails:**
- Review test logs
- Check database connectivity
- Verify test dependencies

**Security Scans Fail:**
- Review security findings in Security tab
- Update vulnerable dependencies
- Fix hardcoded secrets

### Dependabot Issues

**PRs Not Auto-Merging:**
- Check CI status
- Verify update type (patch/minor)
- Review workflow logs

**Too Many PRs:**
- Adjust `open-pull-requests-limit`
- Review grouping strategy
- Consider weekly vs daily schedule

## Maintenance

### Regular Tasks

**Weekly:**
- Review Dependabot PRs
- Check security findings
- Review auto-fix PRs

**Monthly:**
- Review workflow performance
- Update action versions
- Adjust caching strategies

**Quarterly:**
- Review and update security policies
- Evaluate new security tools
- Update Rust version matrix

## Additional Resources

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Dependabot Documentation](https://docs.github.com/en/code-security/dependabot)
- [Rust CI Best Practices](https://doc.rust-lang.org/cargo/guide/continuous-integration.html)
- [GitHub Security Features](https://docs.github.com/en/code-security)

## Support

For issues or questions:
1. Check workflow logs in Actions tab
2. Review this documentation
3. Open an issue in the repository
4. Contact repository maintainers

---

*Last Updated: 2025-11-13*
*This documentation is maintained alongside the workflows.*
