# Secreton Enterprise Vault - Administration Guide

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 👥 Overview

This administration guide provides comprehensive procedures for managing Secreton Enterprise Vault in production environments. It covers user management, policy administration, system configuration, backup and recovery, and operational maintenance tasks.

## 🏢 Administrative Roles and Responsibilities

### System Administrator
- **Primary Responsibilities:**
  - System installation and configuration
  - User and policy management
  - Backup and recovery operations
  - Performance monitoring and tuning
  - Security hardening and compliance

### Security Administrator
- **Primary Responsibilities:**
  - Access control and authorization
  - Security policy implementation
  - Audit log monitoring and analysis
  - Incident response and forensics
  - Compliance reporting

### Database Administrator
- **Primary Responsibilities:**
  - Database performance optimization
  - Backup and recovery procedures
  - Schema management and migrations
  - Query optimization and indexing
  - High availability configuration

## 👤 User Management

### Creating Users

#### Local User Authentication
```bash
# Enable userpass auth method
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "userpass"}' \
  https://vault.example.com/v1/sys/auth/userpass

# Create user account
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "password": "SecurePass123!",
    "policies": ["developer", "default"]
  }' \
  https://vault.example.com/v1/auth/userpass/users/john.doe

# Create admin user
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "password": "AdminSecure123!",
    "policies": ["admin"]
  }' \
  https://vault.example.com/v1/auth/userpass/users/admin
```

#### LDAP Authentication
```bash
# Enable LDAP auth method
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "ldap"}' \
  https://vault.example.com/v1/sys/auth/ldap

# Configure LDAP
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "url": "ldap://ldap.example.com",
    "userdn": "ou=Users,dc=example,dc=com",
    "groupdn": "ou=Groups,dc=example,dc=com",
    "binddn": "cn=admin,dc=example,dc=com",
    "bindpass": "ldap_password",
    "userattr": "uid",
    "groupattr": "memberOf"
  }' \
  https://vault.example.com/v1/auth/ldap/config

# Create LDAP group mapping
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"policies": ["developer"]}' \
  https://vault.example.com/v1/auth/ldap/groups/developers
```

#### Multi-Factor Authentication (MFA)
```bash
# Enable TOTP MFA method
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "totp"}' \
  https://vault.example.com/v1/sys/mfa/method/totp

# Create MFA method
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "issuer": "Secreton",
    "period": 30,
    "algorithm": "SHA256",
    "digits": 6
  }' \
  https://vault.example.com/v1/sys/mfa/method/totp/methods/totp_admin

# Enforce MFA for admin users
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "mfa_method_ids": ["totp_admin"],
    "mfa_enforcement_config": {
      "enforcement_type": "mandatory"
    }
  }' \
  https://vault.example.com/v1/sys/mfa/enforcement/admin_enforcement
```

### Managing User Accounts

#### Password Management
```bash
# Change user password
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"password": "NewSecurePass123!"}' \
  https://vault.example.com/v1/auth/userpass/users/john.doe/password

# Force password change on next login
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"password": "TempPass123!", "force_password_change": true}' \
  https://vault.example.com/v1/auth/userpass/users/john.doe

# Password policies
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policy": "password_policy",
    "config": {
      "min_length": 12,
      "require_uppercase": true,
      "require_lowercase": true,
      "require_numbers": true,
      "require_symbols": true
    }
  }' \
  https://vault.example.com/v1/sys/policies/password
```

#### Account Lockout Management
```bash
# Check user lockout status
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users/john.doe

# Unlock user account
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users/john.doe/unlock

# Configure lockout policy
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "max_login_failures": 5,
    "lockout_period": "15m"
  }' \
  https://vault.example.com/v1/sys/auth/userpass/config
```

### User Deactivation and Deletion
```bash
# Deactivate user (disable login)
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"disabled": true}' \
  https://vault.example.com/v1/auth/userpass/users/john.doe

# Delete user account
curl -X DELETE \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users/john.doe

# List all users
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users | jq .
```

## 🛡️ Policy Management

### Access Control Policies

#### Creating Policies
```bash
# Create developer policy
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policy": "path \"secret/data/dev/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\n\npath \"transit/encrypt/my-key\" {\n  capabilities = [\"update\"]\n}\n\npath \"transit/decrypt/my-key\" {\n  capabilities = [\"update\"]\n}"
  }' \
  https://vault.example.com/v1/sys/policies/acl/developer

# Create admin policy
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policy": "path \"*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\", \"sudo\"]\n}"
  }' \
  https://vault.example.com/v1/sys/policies/acl/admin

# Create auditor policy
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policy": "path \"sys/audit*\" {\n  capabilities = [\"read\", \"list\"]\n}\n\npath \"sys/audit-hash/*\" {\n  capabilities = [\"read\"]\n}"
  }' \
  https://vault.example.com/v1/sys/policies/acl/auditor
```

#### Policy Templates
```bash
# Department-based policy template
cat > department_policy.hcl << EOF
# Department: {{DEPARTMENT}}
# Manager: {{MANAGER}}

path "secret/data/{{DEPARTMENT}}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "transit/encrypt/{{DEPARTMENT}}-key" {
  capabilities = ["update"]
}

path "transit/decrypt/{{DEPARTMENT}}-key" {
  capabilities = ["update"]
}

# Read-only access to shared resources
path "secret/data/shared/*" {
  capabilities = ["read", "list"]
}
EOF

# Apply template
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d @department_policy.hcl \
  https://vault.example.com/v1/sys/policies/acl/engineering
```

#### Policy Testing and Validation
```bash
# Test policy capabilities
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "paths": ["secret/data/test"],
    "capabilities": ["read"]
  }' \
  https://vault.example.com/v1/sys/capabilities-self

# Validate policy syntax
vault policy fmt developer.hcl
vault policy validate developer.hcl

# List all policies
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/policies/acl | jq .
```

### Role-Based Access Control (RBAC)

#### Creating Roles
```bash
# Create developer role
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policies": ["developer", "default"],
    "max_ttl": "8h",
    "default_ttl": "1h"
  }' \
  https://vault.example.com/v1/auth/userpass/role/developer

# Create service account role
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policies": ["service"],
    "max_ttl": "24h",
    "default_ttl": "1h",
    "bound_service_account_names": ["app-service"],
    "bound_service_account_namespaces": ["production"]
  }' \
  https://vault.example.com/v1/auth/kubernetes/role/app-service
```

#### Role Management
```bash
# List roles
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/role | jq .

# Update role
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "policies": ["developer", "auditor"],
    "max_ttl": "12h"
  }' \
  https://vault.example.com/v1/auth/userpass/role/developer

# Delete role
curl -X DELETE \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/role/developer
```

## 🔐 Secret Management

### Secret Engines Configuration

#### KV Secrets Engine
```bash
# Enable KV v2 secrets engine
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "kv", "config": {"version": "2"}}' \
  https://vault.example.com/v1/sys/mounts/secret

# Configure KV settings
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "max_versions": 10,
    "cas_required": false,
    "delete_version_after": "3h30m"
  }' \
  https://vault.example.com/v1/secret/config
```

#### Transit Engine
```bash
# Enable transit engine
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "transit"}' \
  https://vault.example.com/v1/sys/mounts/transit

# Create encryption key
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "type": "rsa-4096",
    "exportable": false,
    "allow_plaintext_backup": false
  }' \
  https://vault.example.com/v1/transit/keys/my-key

# Configure key rotation
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"policy": "rotate"}' \
  https://vault.example.com/v1/transit/keys/my-key/config
```

#### Database Secrets Engine
```bash
# Enable database secrets engine
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{"type": "database"}' \
  https://vault.example.com/v1/sys/mounts/database

# Configure PostgreSQL connection
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "plugin_name": "postgresql-database-plugin",
    "allowed_roles": ["readonly", "readwrite"],
    "connection_url": "postgresql://{{username}}:{{password}}@localhost:5432/secreton_db",
    "username": "vault_admin",
    "password": "vault_admin_password"
  }' \
  https://vault.example.com/v1/database/config/postgresql

# Create database role
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "db_name": "postgresql",
    "creation_statements": [
      "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}';",
      "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
    ],
    "default_ttl": "1h",
    "max_ttl": "24h"
  }' \
  https://vault.example.com/v1/database/roles/readonly
```

### Secret Lifecycle Management

#### Secret Rotation
```bash
# Rotate transit key
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/transit/keys/my-key/rotate

# Rotate database credentials
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/database/rotate-role/readonly

# Check rotation status
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/transit/keys/my-key | jq .data.latest_version
```

#### Secret Expiration and Cleanup
```bash
# Configure automatic cleanup
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "delete_version_after": "168h",
    "max_versions": 20
  }' \
  https://vault.example.com/v1/secret/config

# Manual cleanup
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/secret/metadata/my-secret

# List expired secrets
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/secret/metadata | jq '.data | to_entries[] | select(.value.deletion_time != null)'
```

## 📊 Audit and Compliance

### Audit Log Management

#### Audit Device Configuration
```bash
# Enable file audit device
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "type": "file",
    "options": {
      "file_path": "/opt/secreton/logs/audit.log"
    }
  }' \
  https://vault.example.com/v1/sys/audit/file-audit

# Enable syslog audit device
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d '{
    "type": "syslog",
    "options": {
      "facility": "AUTH",
      "tag": "secreton"
    }
  }' \
  https://vault.example.com/v1/sys/audit/syslog-audit
```

#### Audit Log Analysis
```bash
# Query audit logs
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/audit-hash/file-audit

# Search audit logs for specific events
grep "authentication" /opt/secreton/logs/audit.log | tail -20

# Analyze access patterns
awk '/"request":/ {print $0}' /opt/secreton/logs/audit.log | \
  jq -r '.request.path' | sort | uniq -c | sort -nr | head -10

# Check for suspicious activity
grep '"error":' /opt/secreton/logs/audit.log | \
  grep -E "(authentication|authorization)" | tail -10
```

### Compliance Reporting

#### Generate Compliance Reports
```bash
# Create compliance report script
cat > compliance_report.sh << 'EOF'
#!/bin/bash
REPORT_DATE=$(date +%Y%m%d)
REPORT_FILE="compliance_report_$REPORT_DATE.txt"

echo "Secreton Compliance Report - $REPORT_DATE" > $REPORT_FILE
echo "========================================" >> $REPORT_FILE

# User access summary
echo -e "\nUser Access Summary:" >> $REPORT_FILE
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users | \
  jq '.data | keys[]' | wc -l >> $REPORT_FILE

# Policy summary
echo -e "\nPolicy Summary:" >> $REPORT_FILE
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/policies/acl | \
  jq '.data | keys[]' >> $REPORT_FILE

# Secret engine usage
echo -e "\nSecret Engine Usage:" >> $REPORT_FILE
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/mounts | \
  jq '.data | to_entries[] | select(.value.type != "system") | .key' >> $REPORT_FILE

# Audit events summary
echo -e "\nAudit Events (Last 24h):" >> $REPORT_FILE
grep "$(date -d 'yesterday' +%Y-%m-%d)" /opt/secreton/logs/audit.log | wc -l >> $REPORT_FILE

echo "Compliance report generated: $REPORT_FILE"
EOF

chmod +x compliance_report.sh
./compliance_report.sh
```

#### Automated Compliance Checks
```bash
# Password policy compliance
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users | \
  jq '.data | to_entries[] | select(.value.policies[] | contains("weak_password")) | .key'

# MFA compliance
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/mfa/enforcement | \
  jq '.data | to_entries[] | select(.value.enforcement_type == "mandatory") | .key'

# Key rotation compliance
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/transit/keys | \
  jq '.data | to_entries[] | select(.value.latest_version > 10) | .key'
```

## 💾 Backup and Recovery

### Backup Procedures

#### Configuration Backup
```bash
# Backup vault configuration
tar -czf vault_config_backup_$(date +%Y%m%d).tar.gz /opt/secreton/config/

# Backup policies
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/policies/acl > policies_backup.json

# Backup authentication methods
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/auth > auth_backup.json
```

#### Database Backup
```bash
# Create database backup
pg_dump -U secreton -h localhost secreton_db | \
  gzip > vault_db_backup_$(date +%Y%m%d).sql.gz

# Backup with timestamp
BACKUP_FILE="vault_backup_$(date +%Y%m%d_%H%M%S).sql.gz"
pg_dump -U secreton -h localhost secreton_db | gzip > $BACKUP_FILE

# Verify backup integrity
gunzip -c $BACKUP_FILE | head -20
```

#### Raft Storage Backup
```bash
# Create raft snapshot
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/storage/raft/snapshot

# Download snapshot
curl -H "X-Vault-Token: $ADMIN_TOKEN" \
  -o raft_snapshot_$(date +%Y%m%d).snap \
  https://vault.example.com/v1/sys/storage/raft/snapshot
```

### Recovery Procedures

#### Database Recovery
```bash
# Stop vault service
sudo systemctl stop secreton

# Restore database
createdb -U secreton secreton_recovery
gunzip -c vault_db_backup_20231201.sql.gz | psql -U secreton secreton_recovery

# Switch databases
psql -U secreton -c "ALTER DATABASE secreton_db RENAME TO secreton_old;"
psql -U secreton -c "ALTER DATABASE secreton_recovery RENAME TO secreton_db;"

# Start vault service
sudo systemctl start secreton
```

#### Configuration Recovery
```bash
# Restore configuration files
tar -xzf vault_config_backup_20231201.tar.gz -C /

# Restore policies
curl -X POST \
  -H "X-Vault-Token: $ADMIN_TOKEN" \
  -d @policies_backup.json \
  https://vault.example.com/v1/sys/policies/acl

# Restart service
sudo systemctl restart secreton
```

### Backup Automation
```bash
# Create automated backup script
cat > automated_backup.sh << 'EOF'
#!/bin/bash

BACKUP_DIR="/opt/secreton/backups"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

# Create backup directory
mkdir -p $BACKUP_DIR

# Database backup
echo "Creating database backup..."
pg_dump -U secreton -h localhost secreton_db | \
  gzip > $BACKUP_DIR/vault_db_$DATE.sql.gz

# Configuration backup
echo "Creating configuration backup..."
tar -czf $BACKUP_DIR/vault_config_$DATE.tar.gz /opt/secreton/config/

# Raft snapshot
echo "Creating raft snapshot..."
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  -o $BACKUP_DIR/raft_snapshot_$DATE.snap \
  https://vault.example.com/v1/sys/storage/raft/snapshot

# Clean old backups
echo "Cleaning old backups..."
find $BACKUP_DIR -name "*.sql.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +$RETENTION_DAYS -delete
find $BACKUP_DIR -name "*.snap" -mtime +$RETENTION_DAYS -delete

# Verify backups
echo "Verifying backups..."
ls -lh $BACKUP_DIR/*$DATE*

echo "Backup completed successfully"
EOF

# Schedule automated backup
echo "0 2 * * * /opt/secreton/bin/automated_backup.sh" | crontab -
```

## 🔧 System Maintenance

### Performance Tuning

#### Database Optimization
```sql
-- Analyze table statistics
ANALYZE;

-- Check for unused indexes
SELECT schemaname, tablename, indexname
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

-- Optimize autovacuum settings
ALTER TABLE secrets SET (autovacuum_vacuum_scale_factor = 0.1);
ALTER TABLE audit_log SET (autovacuum_analyze_scale_factor = 0.05);

-- Monitor query performance
SELECT query, calls, total_time, mean_time, rows
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;
```

#### Memory and Cache Tuning
```bash
# Adjust PostgreSQL memory settings
sudo -u postgres psql -c "ALTER SYSTEM SET shared_buffers = '256MB';"
sudo -u postgres psql -c "ALTER SYSTEM SET effective_cache_size = '1GB';"
sudo -u postgres psql -c "ALTER SYSTEM SET work_mem = '4MB';"

# Reload PostgreSQL configuration
sudo systemctl reload postgresql

# Monitor cache hit ratio
psql -U secreton -d secreton_db -c "
SELECT
  sum(heap_blks_read) as heap_read,
  sum(heap_blks_hit) as heap_hit,
  (sum(heap_blks_hit) - sum(heap_blks_read)) / sum(heap_blks_hit) as ratio
FROM pg_statio_user_tables;
"
```

### Log Management

#### Log Rotation
```bash
# Configure logrotate
cat > /etc/logrotate.d/secreton << EOF
/opt/secreton/logs/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 secreton secreton
    postrotate
        systemctl reload secreton
    endscript
}
EOF

# Test log rotation
logrotate -f /etc/logrotate.d/secreton
```

#### Log Analysis
```bash
# Create log analysis script
cat > log_analysis.sh << 'EOF'
#!/bin/bash

LOG_FILE="/opt/secreton/logs/secreton.log"
ANALYSIS_FILE="log_analysis_$(date +%Y%m%d).txt"

echo "Log Analysis Report - $(date)" > $ANALYSIS_FILE
echo "=================================" >> $ANALYSIS_FILE

# Error summary
echo -e "\nError Summary:" >> $ANALYSIS_FILE
grep -i "error\|failed\|exception" $LOG_FILE | \
  awk '{print $4}' | sort | uniq -c | sort -nr >> $ANALYSIS_FILE

# Request patterns
echo -e "\nTop Request Paths:" >> $ANALYSIS_FILE
grep "request" $LOG_FILE | \
  awk -F'"' '{print $4}' | sort | uniq -c | sort -nr | head -10 >> $ANALYSIS_FILE

# Performance issues
echo -e "\nSlow Requests (>1s):" >> $ANALYSIS_FILE
grep "duration.*[0-9]\{4,\}ms" $LOG_FILE | wc -l >> $ANALYSIS_FILE

# Authentication failures
echo -e "\nAuthentication Failures:" >> $ANALYSIS_FILE
grep "authentication failed" $LOG_FILE | wc -l >> $ANALYSIS_FILE

echo "Analysis complete: $ANALYSIS_FILE"
EOF

chmod +x log_analysis.sh
./log_analysis.sh
```

### Security Maintenance

#### Certificate Management
```bash
# Check certificate expiration
openssl x509 -in /opt/secreton/certs/server.crt -text -noout | \
  grep -E "(Not Before|Not After)"

# Renew certificates
sudo -u secreton openssl req -x509 -newkey rsa:4096 \
  -keyout /opt/secreton/certs/server.key \
  -out /opt/secreton/certs/server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault.example.com"

# Update certificate permissions
sudo chmod 600 /opt/secreton/certs/server.key
sudo chmod 644 /opt/secreton/certs/server.crt

# Reload configuration
sudo systemctl reload secreton
```

#### Security Updates
```bash
# Update system packages
sudo apt update && sudo apt upgrade -y

# Update Rust and dependencies
rustup update
cargo update

# Rebuild and redeploy
cargo build --release
sudo systemctl stop secreton
sudo cp target/release/secreton /opt/secreton/bin/
sudo systemctl start secreton

# Verify update
curl -k https://vault.example.com/v1/sys/health | jq .version
```

## 📊 Reporting and Analytics

### Usage Reports

#### User Activity Report
```bash
# Generate user activity report
cat > user_activity_report.sh << 'EOF'
#!/bin/bash

REPORT_FILE="user_activity_$(date +%Y%m%d).txt"

echo "User Activity Report - $(date)" > $REPORT_FILE
echo "================================" >> $REPORT_FILE

# Active users
echo -e "\nActive Users:" >> $REPORT_FILE
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/auth/userpass/users | \
  jq '.data | keys[]' | wc -l >> $REPORT_FILE

# Recent logins
echo -e "\nRecent Logins (Last 24h):" >> $REPORT_FILE
grep "$(date +%Y-%m-%d)" /opt/secreton/logs/audit.log | \
  grep "authentication" | wc -l >> $REPORT_FILE

# Top accessed secrets
echo -e "\nTop Accessed Secrets:" >> $REPORT_FILE
grep "secret" /opt/secreton/logs/audit.log | \
  awk -F'"' '{print $4}' | sort | uniq -c | sort -nr | head -10 >> $REPORT_FILE

# Failed authentication attempts
echo -e "\nFailed Auth Attempts:" >> $REPORT_FILE
grep "authentication failed" /opt/secreton/logs/audit.log | wc -l >> $REPORT_FILE

echo "Report generated: $REPORT_FILE"
EOF

chmod +x user_activity_report.sh
./user_activity_report.sh
```

#### System Performance Report
```bash
# Generate performance report
cat > performance_report.sh << 'EOF'
#!/bin/bash

REPORT_FILE="performance_$(date +%Y%m%d).txt"

echo "Performance Report - $(date)" > $REPORT_FILE
echo "============================" >> $REPORT_FILE

# System resources
echo -e "\nSystem Resources:" >> $REPORT_FILE
echo "CPU Usage:" >> $REPORT_FILE
top -b -n 1 | head -5 >> $REPORT_FILE

echo -e "\nMemory Usage:" >> $REPORT_FILE
free -h >> $REPORT_FILE

echo -e "\nDisk Usage:" >> $REPORT_FILE
df -h /opt/secreton >> $REPORT_FILE

# Vault metrics
echo -e "\nVault Metrics:" >> $REPORT_FILE
curl -s -H "X-Vault-Token: $ADMIN_TOKEN" \
  https://vault.example.com/v1/sys/metrics?format=prometheus | \
  grep -E "(vault_core_handle_request|vault_database)" >> $REPORT_FILE

# Database performance
echo -e "\nDatabase Performance:" >> $REPORT_FILE
psql -U secreton -d secreton_db -c "
SELECT
  schemaname, tablename,
  pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as size
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
LIMIT 5;
" >> $REPORT_FILE

echo "Performance report generated: $REPORT_FILE"
EOF

chmod +x performance_report.sh
./performance_report.sh
```

## 📚 Additional Resources

### Documentation Links
- [Deployment Guide](../docs/DEPLOYMENT_GUIDE.md)
- [Monitoring Guide](../docs/MONITORING_GUIDE.md)
- [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)
- [Security Hardening](../docs/SECURITY_HARDENING.md)

### Training Resources
- [Administrator Training Course](https://learn.secreton.com/admin-training)
- [Policy Management Workshop](https://learn.secreton.com/policy-workshop)
- [Security Best Practices](https://learn.secreton.com/security-best-practices)

### Support and Escalation
- **Tier 1 Support**: Basic administration questions
- **Tier 2 Support**: Advanced configuration and troubleshooting
- **Tier 3 Support**: Critical system issues and escalations

---

**This administration guide provides comprehensive procedures for managing Secreton Enterprise Vault in production. Regular review and updates to administrative procedures are essential for maintaining system security and compliance.**
