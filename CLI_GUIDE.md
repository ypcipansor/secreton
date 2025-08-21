# 🖥️ Brankas CLI Tool - Complete User Guide

**Version:** 1.0.0  
**Status:** ✅ Production Ready  
**Compatibility:** Works with Brankas Vault API Server v1.1.0+

## 📋 Overview

The Brankas CLI is a powerful command-line interface that provides complete access to both the Transit Engine (encryption/decryption services) and KV Secrets Engine (versioned secret storage) of the Brankas Vault system.

## 🚀 Quick Start

### Installation & Build
```bash
# Build the CLI from source
cd /home/clouduser/vault/brankas
cargo build -p brankas-cli

# The binary will be available at:
./target/debug/brankas-cli

# Or for production builds:
cargo build --release -p brankas-cli
./target/release/brankas-cli
```

### Basic Usage
```bash
# Check system status
./target/debug/brankas-cli status

# Get help for any command
./target/debug/brankas-cli --help
./target/debug/brankas-cli transit --help
./target/debug/brankas-cli secret --help
```

## 🔐 Transit Engine Commands

The Transit Engine provides encryption-as-a-service functionality.

### Key Management

#### Create Encryption Key
```bash
# Create a new encryption key
brankas-cli transit create-key my-app-key

# Create multiple keys for different purposes
brankas-cli transit create-key user-data-key
brankas-cli transit create-key payment-key
brankas-cli transit create-key logs-key
```

#### List All Keys
```bash
# List all available encryption keys
brankas-cli transit list-keys
```

### Data Encryption/Decryption

#### Encrypt Data
```bash
# Encrypt data directly with --data flag
brankas-cli transit encrypt my-key --data "Hello World"

# Encrypt from stdin (pipeline support)
echo "secret data" | brankas-cli transit encrypt my-key

# Encrypt multi-line data
cat secrets.txt | brankas-cli transit encrypt my-key
```

#### Decrypt Data
```bash
# Decrypt data with ciphertext
brankas-cli transit decrypt my-key --data "vault:v1:abc123..."

# Decrypt from stdin
echo "vault:v1:abc123..." | brankas-cli transit decrypt my-key

# Pipeline decryption
cat encrypted.txt | brankas-cli transit decrypt my-key
```

### Transit Engine Examples

```bash
# Complete encryption workflow
brankas-cli transit create-key demo-key
brankas-cli transit encrypt demo-key --data "Confidential Information"
# Output: vault:v1:randomstring:encrypteddata

# Decrypt the result
brankas-cli transit decrypt demo-key --data "vault:v1:randomstring:encrypteddata"
# Output: Confidential Information

# Batch encryption
for file in *.txt; do
  cat "$file" | brankas-cli transit encrypt batch-key > "$file.encrypted"
done
```

## 🗄️ KV Secrets Engine Commands

The KV Secrets Engine provides versioned secret storage with metadata.

### Secret Storage Operations

#### Store Secrets
```bash
# Store a secret with key-value pairs
brankas-cli secret put myapp --data password=secret123 --data api_key=abc123

# Store multiple secrets
brankas-cli secret put database --data host=localhost --data port=5432 --data user=admin
brankas-cli secret put redis --data url=redis://localhost:6379 --data timeout=30
```

#### Retrieve Secrets
```bash
# Get the latest version of a secret
brankas-cli secret get myapp

# Get a specific secret
brankas-cli secret get database
```

#### List All Secrets
```bash
# List all secret paths
brankas-cli secret list
```

#### Delete Secrets
```bash
# Soft delete a secret (can be recovered)
brankas-cli secret delete myapp
```

### KV Engine Examples

```bash
# Application configuration management
brankas-cli secret put app-config \
  --data db_url=postgresql://localhost:5432/myapp \
  --data redis_url=redis://localhost:6379 \
  --data debug=false \
  --data log_level=info

# User credentials
brankas-cli secret put admin-user \
  --data username=admin \
  --data password=super-secure-password \
  --data role=administrator \
  --data last_login=2025-08-21

# API keys and tokens
brankas-cli secret put external-apis \
  --data stripe_key=sk_live_abc123 \
  --data twilio_token=xyz789 \
  --data sendgrid_key=SG.abc123xyz

# Retrieve and use secrets
brankas-cli secret get app-config
brankas-cli secret get admin-user
```

## 🔄 Combined Workflows

### Scenario 1: Encrypt-then-Store
```bash
# 1. Create dedicated encryption key
brankas-cli transit create-key sensitive-data-key

# 2. Encrypt sensitive information
ENCRYPTED_PASSWORD=$(brankas-cli transit encrypt sensitive-data-key --data "super-secret-password" | tail -n 1)

# 3. Store encrypted data in secrets
brankas-cli secret put app-secure \
  --data encrypted_password="$ENCRYPTED_PASSWORD" \
  --data db_host=secure-database.com \
  --data connection_timeout=30

# 4. Retrieve and decrypt when needed
STORED_SECRET=$(brankas-cli secret get app-secure)
ENCRYPTED_PASS=$(echo "$STORED_SECRET" | jq -r '.encrypted_password')
brankas-cli transit decrypt sensitive-data-key --data "$ENCRYPTED_PASS"
```

### Scenario 2: Configuration Management
```bash
# Environment-specific configurations
brankas-cli secret put prod-config \
  --data database_url=prod-db.example.com \
  --data redis_cluster=prod-redis.example.com \
  --data log_level=warn

brankas-cli secret put dev-config \
  --data database_url=localhost:5432 \
  --data redis_cluster=localhost:6379 \
  --data log_level=debug

# Application startup script can retrieve appropriate config
ENV=${ENVIRONMENT:-dev}
brankas-cli secret get "${ENV}-config"
```

### Scenario 3: Secure Data Pipeline
```bash
# Create pipeline encryption key
brankas-cli transit create-key pipeline-key

# Encrypt sensitive data in pipeline
cat sensitive_data.csv | brankas-cli transit encrypt pipeline-key > encrypted_data.vault

# Store pipeline metadata
brankas-cli secret put pipeline-job-123 \
  --data input_file=sensitive_data.csv \
  --data output_file=encrypted_data.vault \
  --data processed_at="$(date -Iseconds)" \
  --data status=completed

# Later: decrypt for processing
cat encrypted_data.vault | brankas-cli transit decrypt pipeline-key > decrypted_data.csv
```

## ⚙️ Configuration

### Default Configuration
The CLI uses the following default settings:
- **Server URL**: `http://127.0.0.1:8200`
- **Log Level**: INFO (use `--verbose` for DEBUG)

### Command-Line Options
```bash
# Global options (work with any command)
--server <URL>     # Override server URL
--config <FILE>    # Load config from file
--verbose          # Enable debug logging
--help             # Show help information

# Examples
brankas-cli --server http://vault.company.com:8200 status
brankas-cli --verbose secret list
brankas-cli --config ~/.config/brankas/config.toml transit list-keys
```

### Configuration File
Create a TOML configuration file:

```toml
# ~/.config/brankas/config.toml
server_url = "https://vault.company.com:8200"
```

Load with:
```bash
brankas-cli --config ~/.config/brankas/config.toml status
```

## 📊 Output Formats

All CLI commands provide clean, human-readable output with color-coded status indicators:

- ✅ **Success operations** (green checkmark)
- ❌ **Failed operations** (red X)  
- 🔍 **Information display** (magnifying glass)
- 🔑 **Key operations** (key emoji)
- 📋 **List operations** (clipboard emoji)

### Status Indicators
```bash
# System status
🟢 Brankas Vault Status: HEALTHY    # System operational
🔴 Brankas Vault Status: UNHEALTHY  # System issues

# Operation results  
✅ Created encryption key: my-key    # Success
❌ Failed to create key: 409 Conflict  # Error

# Data display
🔐 Encrypted data:                  # Encryption result
🔓 Decrypted data:                  # Decryption result
📋 Available secrets:               # List results
🔍 Secret at path 'config':         # Secret retrieval
```

## 🔧 Advanced Usage

### Scripting and Automation
```bash
#!/bin/bash
# Example: Automated secret rotation script

OLD_PASSWORD=$(brankas-cli secret get db-config | jq -r '.password')
NEW_PASSWORD=$(openssl rand -base64 32)

# Encrypt new password
ENCRYPTED_NEW=$(brankas-cli transit encrypt rotation-key --data "$NEW_PASSWORD" | tail -n 1)

# Update secret with new password
brankas-cli secret put db-config \
  --data password="$NEW_PASSWORD" \
  --data previous_password="$OLD_PASSWORD" \
  --data rotated_at="$(date -Iseconds)"

echo "✅ Password rotated successfully"
```

### Integration with Other Tools
```bash
# Integration with jq for JSON processing
DB_HOST=$(brankas-cli secret get database | jq -r '.host')
DB_PORT=$(brankas-cli secret get database | jq -r '.port')

# Integration with environment variables
eval $(brankas-cli secret get env-vars | jq -r 'to_entries[] | "export \(.key)=\(.value)"')

# Integration with Docker
docker run -e DB_PASSWORD="$(brankas-cli secret get db | jq -r '.password')" myapp

# Integration with Kubernetes
kubectl create secret generic app-secrets \
  --from-literal=db-password="$(brankas-cli secret get database | jq -r '.password')" \
  --from-literal=api-key="$(brankas-cli secret get apis | jq -r '.stripe_key')"
```

## 🚨 Error Handling

### Common Error Scenarios

#### Server Connectivity
```bash
# Server not running
🔴 Brankas Vault Status: UNHEALTHY
   HTTP Status: Connection refused

# Wrong server URL
❌ Failed to connect: Network unreachable
```

#### Authentication Issues
```bash
# Invalid key name
❌ Failed to create key: 400 Bad Request

# Key not found
❌ Failed to encrypt: 404 Not Found
```

#### Path Limitations
```bash
# Current limitation: paths with slashes may not work
❌ Failed to store secret: 404 Not Found

# Workaround: use simple paths without slashes
brankas-cli secret put appconfig --data key=value  # ✅ Works
brankas-cli secret put app/config --data key=value # ❌ May fail
```

## 🎯 Best Practices

### Security Best Practices
1. **Key Management**: Use descriptive key names that indicate their purpose
2. **Access Control**: Run CLI with minimal required permissions
3. **Secret Rotation**: Regularly rotate sensitive secrets
4. **Audit Trail**: Use version history to track secret changes

### Operational Best Practices
1. **Automation**: Use CLI in scripts for consistent operations
2. **Error Checking**: Always check command exit codes in scripts
3. **Logging**: Use `--verbose` for debugging, standard output for production
4. **Configuration**: Use configuration files for consistent server settings

### Performance Best Practices
1. **Batch Operations**: Group related operations together
2. **Pipeline Usage**: Use stdin/stdout for large data processing
3. **Connection Reuse**: CLI automatically reuses HTTP connections

## 📚 Examples Repository

### Quick Reference Commands
```bash
# System check
brankas-cli status

# Transit operations
brankas-cli transit create-key mykey
brankas-cli transit encrypt mykey --data "secret"
brankas-cli transit decrypt mykey --data "vault:v1:..."
brankas-cli transit list-keys

# Secret operations  
brankas-cli secret put mypath --data key=value
brankas-cli secret get mypath
brankas-cli secret list
brankas-cli secret delete mypath
```

## 🔗 Integration Guide

The Brankas CLI integrates seamlessly with:
- **Shell Scripts**: Bash, Zsh, Fish automation
- **CI/CD Pipelines**: Jenkins, GitHub Actions, GitLab CI
- **Container Orchestration**: Docker, Kubernetes, Docker Compose
- **Configuration Management**: Ansible, Terraform, Puppet
- **Monitoring Systems**: Prometheus metrics, log aggregation

---

**🎉 The Brankas CLI provides complete command-line access to all vault functionality!**  
**🚀 Ready for production use in automated workflows and manual operations**
