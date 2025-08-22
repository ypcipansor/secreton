# Project Structure Guide

## Organized Directory Layout

After recent optimization and cleanup, Secreton Enterprise Vault by Cipherce follows a clean, professional structure:

```
secreton/
├── 📄 Cargo.toml               # Workspace configuration
├── 📄 README.md                # Main project documentation  
├── 📄 LICENSE                  # Apache 2.0 license
├── 📄 Makefile                 # Build automation
├── 📄 CHANGELOG.md             # Version history
├── 📄 CLI_GUIDE.md             # CLI usage documentation
├── 📄 CONTRIBUTING.md          # Contribution guidelines
├── 📄 EXAMPLES.md              # Usage examples
├── 📄 NEXT_STEPS.md            # Development roadmap
├── 📄 STATUS.md                # Current project status
├── 📄 .env.example             # Environment template
├── 📄 .gitignore               # Git ignore rules
├── 📁 .github/                 # GitHub workflows & templates
├── 📁 config/                  # Configuration files
│   ├── default.toml            # Default configuration
│   └── vault.toml              # Vault-specific config
├── 📁 crates/                  # Rust workspace crates
│   ├── agent/                  # Vault agent implementation
│   ├── core/                   # Core security libraries
│   ├── cli/                    # Command-line interface
│   ├── api/                    # HTTP REST API server
│   └── ui/                     # Web user interface
├── 📁 docs/                    # Documentation
│   ├── ALERTING_WEBHOOK.md     # Alert configuration
│   ├── COMPLIANCE.md           # Compliance documentation
│   ├── PENTEST_TEMPLATE.md     # Penetration testing
│   ├── SECURITY_REVIEW.md      # Security review process
│   ├── TLS_EXAMPLE.md          # TLS configuration
│   └── setup/                  # Setup documentation
├── 📁 examples/                # Code examples
│   ├── key_management_example.rs  # Key management demo
│   └── policy_example.rs       # Policy configuration demo
├── 📁 migrations/              # Database migrations
│   ├── 20240101000001_create_mfa_tables.sql
│   └── audit/                  # Audit table migrations
├── 📁 scripts/                 # **ORGANIZED SCRIPTS**
│   ├── 📁 demos/               # Demo & showcase scripts
│   │   ├── client_demo.rs      # Client demo implementation
│   │   ├── demo-raft.sh        # Raft consensus demo
│   │   ├── demo_cli.sh         # CLI demonstration
│   │   └── demo_complete.sh    # Complete system demo
│   ├── 📁 testing/             # Testing scripts
│   │   ├── quick_test.sh       # Quick validation tests
│   │   ├── run_tests.sh        # Full test suite runner
│   │   └── test_kv.sh          # Key-value testing
│   ├── 📁 cluster/             # Cluster management
│   │   ├── start-cluster.sh    # Start cluster
│   │   ├── start-raft.sh       # Start Raft node
│   │   └── stop-cluster.sh     # Stop cluster
│   ├── secreton-control.sh      # Main control script
│   ├── configure-optimize.sh   # System optimization
│   ├── deploy.sh               # Deployment script
│   ├── monitoring.rs           # Monitoring utilities
│   ├── production-readiness-check.sh  # Production validation
│   ├── rotate_and_alert.rs     # Key rotation & alerts
│   ├── security-monitor.sh     # Security monitoring
│   └── test_api.sh             # API testing
├── 📁 tests/                   # Test files
│   ├── mfa_test.rs             # MFA testing
│   └── mocks/                  # Test mocks
├── 📁 temp/                    # Temporary files (ignored)
│   ├── server.log              # Runtime logs
│   ├── server_kv.log           # KV server logs
│   └── test_*.rs               # Temporary test files
└── 📁 target/                  # Build artifacts (ignored)
    ├── debug/                  # Debug builds
    └── release/                # Release builds
```

## Script Organization Benefits

### 📁 scripts/demos/
- **Purpose**: Demonstration and showcase scripts
- **Usage**: For presentations, tutorials, and feature demonstrations
- **Files**: Interactive demos, client examples, complete workflows

### 📁 scripts/testing/
- **Purpose**: Testing and validation scripts  
- **Usage**: Automated testing, CI/CD integration, quality assurance
- **Files**: Unit test runners, integration tests, performance tests

### 📁 scripts/cluster/
- **Purpose**: Cluster and distributed system management
- **Usage**: High availability deployments, multi-node operations
- **Files**: Cluster lifecycle management, Raft consensus operations

### 📁 temp/
- **Purpose**: Temporary files and logs
- **Usage**: Runtime artifacts that shouldn't be committed
- **Files**: Log files, temporary test files, build artifacts

## Quick Navigation

### Development Workflows
```bash
# Start development environment
./scripts/demos/demo_complete.sh

# Run comprehensive tests  
./scripts/testing/run_tests.sh

# Start production cluster
./scripts/cluster/start-cluster.sh
```

### Documentation Access
- **Main Docs**: `docs/` directory
- **Setup Guides**: `docs/setup/` directory  
- **Examples**: `examples/` directory
- **CLI Help**: `CLI_GUIDE.md`

This organized structure provides:
- ✅ **Professional Appearance**: Clean root directory
- ✅ **Logical Grouping**: Scripts organized by function
- ✅ **Easy Navigation**: Predictable file locations
- ✅ **Development Friendly**: Clear separation of concerns
- ✅ **Production Ready**: Proper structure for deployment
