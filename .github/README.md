# GitHub Configuration

This directory contains the GitHub-specific configuration for the Secreton repository.

## Structure

```
.github/
├── workflows/              # GitHub Actions workflows
│   ├── rust-ci.yml        # Main CI pipeline
│   ├── auto-fix.yml       # Auto-fix and format
│   ├── codeql-analysis.yml # Code scanning
│   ├── secret-scanning.yml # Secret detection
│   ├── security-comprehensive.yml # Full security suite
│   ├── pr-validation.yml  # PR quality gates
│   ├── dependabot.yml     # Dependabot auto-merge
│   └── deploy-staging.yml # Staging deployment
├── dependabot.yml         # Dependabot configuration
├── WORKFLOWS.md           # Detailed workflow documentation
└── README.md             # This file
```

## Quick Reference

### Main CI Pipeline (`rust-ci.yml`)

**Commands executed:**
```bash
cargo check --workspace --all-features
cargo build --workspace --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo fmt --all -- --check
cargo audit
cargo deny check
cargo doc --workspace --no-deps
```

**When it runs:**
- Every push to `main` or `develop`
- Every pull request
- Manual trigger

### Auto-Fix Workflow (`auto-fix.yml`)

**Commands executed:**
```bash
cargo fix --allow-dirty --allow-staged
cargo fmt --all
```

**When it runs:**
- Weekly (Monday 00:00 UTC)
- Manual trigger

**What it does:**
- Automatically fixes compiler warnings
- Formats code consistently
- Creates PR with changes if any

### Security Workflows

**CodeQL Analysis** - Native GitHub code scanning
**Secret Scanning** - Multi-tool secret detection (Gitleaks, TruffleHog, Trivy)
**Comprehensive Security** - Full suite (Trivy, Semgrep, OSV, Snyk)

**When they run:**
- Every push/PR
- Weekly/daily schedules
- Manual trigger

### PR Validation (`pr-validation.yml`)

**Validates:**
- ✅ Semantic PR title format
- ✅ PR size (auto-labels)
- ✅ Breaking changes declaration
- ✅ Changelog updates

### Dependabot

**Auto-merges:**
- ✅ Patch updates (automatically)
- ✅ Minor updates (automatically)
- ⚠️ Major updates (manual review required)

**Grouped updates for:**
- RustCrypto packages
- Async ecosystem
- AWS SDK
- Database crates
- HTTP/network crates
- Monitoring crates

## Status Badges

Add these to your README.md:

```markdown
[![Rust CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions?query=workflow%3A%22Rust+CI%22)
[![CodeQL](https://github.com/analisaperlengkapan/secreton/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions?query=workflow%3A%22CodeQL+Analysis%22)
[![Security](https://github.com/analisaperlengkapan/secreton/workflows/Comprehensive%20Security%20Scan/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions?query=workflow%3A%22Comprehensive+Security+Scan%22)
[![Secret Scanning](https://github.com/analisaperlengkapan/secreton/workflows/Secret%20Scanning/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions?query=workflow%3A%22Secret+Scanning%22)
```

## Required Secrets

Configure these in repository settings (Settings → Secrets and variables → Actions):

### Optional but Recommended:
- `CODECOV_TOKEN` - For code coverage upload
- `SNYK_TOKEN` - For Snyk security scanning
- `DOCKER_USERNAME` - For Docker Hub (if using)
- `DOCKER_PASSWORD` - For Docker Hub (if using)

### Already Available:
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

## Branch Protection Rules

Recommended settings for `main` and `develop` branches:

### Required Status Checks
- ✅ Check (stable)
- ✅ Build (stable)
- ✅ Clippy
- ✅ Test (stable)
- ✅ Format Check
- ✅ Security Audit
- ✅ Cargo Deny

### Additional Settings
- ✅ Require pull request before merging
- ✅ Require approvals: 1
- ✅ Dismiss stale reviews
- ✅ Require review from Code Owners
- ✅ Require status checks to pass
- ✅ Require branches to be up to date
- ✅ Require conversation resolution
- ✅ Include administrators

## Workflow Triggers

### Push Triggers
- `main` branch - Full CI + deployment
- `develop` branch - Full CI + staging deployment

### PR Triggers
- To `main` or `develop` - Full CI + validation

### Schedule Triggers
- **Daily (03:00 UTC):** Secret scanning
- **Weekly (Sunday 00:00 UTC):** Comprehensive security scan
- **Weekly (Monday 00:00 UTC):** Auto-fix workflow
- **Weekly (Monday 02:00 UTC):** CodeQL analysis
- **Weekly (Monday 09:00 UTC):** Dependabot updates

### Manual Triggers
All workflows support `workflow_dispatch` for manual execution

## Monitoring

### GitHub Actions Tab
- View all workflow runs
- Check logs and artifacts
- Re-run failed workflows

### Security Tab
- CodeQL findings
- Dependabot alerts
- Secret scanning results
- Vulnerability reports

### Pull Requests
- Automated status checks
- Validation comments
- Size labels
- Auto-merge status

## Best Practices

### For Contributors
1. **Before submitting PR:**
   ```bash
   cargo fmt --all
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ```

2. **PR title format:**
   ```
   type(scope): description
   
   Examples:
   feat(auth): add OAuth2 support
   fix(api): correct token validation
   docs: update API documentation
   ```

3. **Keep PRs small:**
   - Aim for <500 lines changed
   - Focus on single responsibility
   - Break large features into smaller PRs

### For Maintainers
1. **Review Dependabot PRs weekly**
2. **Check security findings regularly**
3. **Merge auto-fix PRs after review**
4. **Update workflows quarterly**

## Troubleshooting

### Workflow fails with "Permission denied"
- Check workflow permissions in `.github/workflows/*.yml`
- Verify repository settings allow Actions

### Dependabot not creating PRs
- Check `dependabot.yml` syntax
- Verify update schedule
- Check Insights → Dependency graph → Dependabot

### CI is slow
- Review caching configuration
- Consider reducing matrix dimensions
- Check for redundant jobs

### Security scan false positives
- Review findings in Security tab
- Add exceptions to `deny.toml` if needed
- Update security tool configurations

## Documentation

- [Detailed Workflow Documentation](./WORKFLOWS.md)
- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Dependabot Docs](https://docs.github.com/en/code-security/dependabot)

## Support

For issues:
1. Check workflow logs
2. Review documentation
3. Open an issue
4. Contact maintainers

---

*For detailed information about each workflow, see [WORKFLOWS.md](./WORKFLOWS.md)*
