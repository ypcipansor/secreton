# Status Badges for README

Add these badges to your main README.md to show the status of all workflows:

## All Workflows

```markdown
## CI/CD Status

[![Rust CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/rust-ci.yml)
[![CodeQL](https://github.com/analisaperlengkapan/secreton/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/codeql-analysis.yml)
[![Secret Scanning](https://github.com/analisaperlengkapan/secreton/workflows/Secret%20Scanning/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/secret-scanning.yml)
[![Security](https://github.com/analisaperlengkapan/secreton/workflows/Comprehensive%20Security%20Scan/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/security-comprehensive.yml)
[![Auto Fix](https://github.com/analisaperlengkapan/secreton/workflows/Auto%20Fix/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/auto-fix.yml)
```

## Compact Version

```markdown
[![CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions)
[![Security](https://github.com/analisaperlengkapan/secreton/workflows/Comprehensive%20Security%20Scan/badge.svg)](https://github.com/analisaperlengkapan/secreton/security)
```

## Visual Rendering

When added to your README, they will appear like this:

[![Rust CI](https://img.shields.io/badge/Rust_CI-passing-brightgreen?style=flat-square&logo=github-actions)](https://github.com/analisaperlengkapan/secreton/actions)
[![CodeQL](https://img.shields.io/badge/CodeQL-passing-brightgreen?style=flat-square&logo=github)](https://github.com/analisaperlengkapan/secreton/security/code-scanning)
[![Secret Scanning](https://img.shields.io/badge/Secret_Scanning-active-blue?style=flat-square&logo=github)](https://github.com/analisaperlengkapan/secreton/security)
[![Security](https://img.shields.io/badge/Security_Scan-comprehensive-blue?style=flat-square&logo=dependabot)](https://github.com/analisaperlengkapan/secreton/security)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?style=flat-square&logo=dependabot)](https://github.com/analisaperlengkapan/secreton/network/updates)

## Additional Badges

```markdown
![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/analisaperlengkapan/secreton/rust-ci.yml?branch=main&label=Build&style=flat-square)
![GitHub last commit](https://img.shields.io/github/last-commit/analisaperlengkapan/secreton?style=flat-square)
![GitHub issues](https://img.shields.io/github/issues/analisaperlengkapan/secreton?style=flat-square)
![GitHub pull requests](https://img.shields.io/github/issues-pr/analisaperlengkapan/secreton?style=flat-square)
![License](https://img.shields.io/github/license/analisaperlengkapan/secreton?style=flat-square)
```

## Coverage Badges

If you configure Codecov:

```markdown
[![codecov](https://codecov.io/gh/analisaperlengkapan/secreton/branch/main/graph/badge.svg)](https://codecov.io/gh/analisaperlengkapan/secreton)
```

## Security Badges

```markdown
[![Security Rating](https://img.shields.io/badge/security-A+-brightgreen?style=flat-square)](https://github.com/analisaperlengkapan/secreton/security)
[![Known Vulnerabilities](https://img.shields.io/badge/vulnerabilities-0-brightgreen?style=flat-square)](https://github.com/analisaperlengkapan/secreton/security/advisories)
```

## Example README Section

Here's a complete example of how to add these to your README:

```markdown
# Secreton

> Advanced Security System with Quantum-Safe Cryptography

## Status

[![Rust CI](https://github.com/analisaperlengkapan/secreton/workflows/Rust%20CI/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/rust-ci.yml)
[![CodeQL](https://github.com/analisaperlengkapan/secreton/workflows/CodeQL%20Analysis/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/codeql-analysis.yml)
[![Security](https://github.com/analisaperlengkapan/secreton/workflows/Comprehensive%20Security%20Scan/badge.svg)](https://github.com/analisaperlengkapan/secreton/actions/workflows/security-comprehensive.yml)
[![Dependabot](https://img.shields.io/badge/Dependabot-enabled-brightgreen?style=flat-square&logo=dependabot)](https://github.com/analisaperlengkapan/secreton/network/updates)

## Features

...
```

## Customization

You can customize badge styles:

- `?style=flat` - Flat style
- `?style=flat-square` - Flat square style
- `?style=for-the-badge` - Large badge style
- `?style=plastic` - Plastic style
- `?style=social` - Social style

Example:
```markdown
![Build](https://img.shields.io/github/actions/workflow/status/analisaperlengkapan/secreton/rust-ci.yml?style=for-the-badge&logo=rust)
```

## Dynamic Badges

Use shields.io for dynamic badges:

```markdown
![Build](https://img.shields.io/github/actions/workflow/status/analisaperlengkapan/secreton/rust-ci.yml?branch=main)
![Coverage](https://img.shields.io/codecov/c/github/analisaperlengkapan/secreton)
![Version](https://img.shields.io/github/v/release/analisaperlengkapan/secreton)
```
