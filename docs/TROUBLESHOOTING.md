# Secreton Enterprise Vault - Troubleshooting Guide

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 🔧 Overview

This troubleshooting guide provides systematic approaches to diagnose and resolve common issues with Secreton Enterprise Vault. It covers operational problems, performance issues, security incidents, and cluster-related challenges.

## 🚨 Emergency Procedures

### Critical System Down
```bash
# 1. Check system status
systemctl status secreton
ps aux | grep secreton

# 2. Review recent logs
tail -f /opt/secreton/logs/secreton.log
journalctl -u secreton -n 50

# 3. Check system resources
top -p $(pgrep secreton)
free -h
df -h /opt/secreton/data

# 4. Restart service if safe
sudo systemctl restart secreton

# 5. Check health endpoint
curl -k https://localhost:8200/v1/sys/health
```

### Vault Sealed Emergency
```bash
# 1. Check seal status
curl -k https://vault.example.com/v1/sys/seal-status

# 2. Gather unseal key holders
# Contact designated key holders per DR plan

# 3. Unseal vault (requires threshold keys)
for key in "${UNSEAL_KEYS[@]}"; do
  curl -X POST \
    -d "{\"key\": \"$key\"}" \
    https://vault.example.com/v1/sys/unseal
done

# 4. Verify unseal
curl -k https://vault.example.com/v1/sys/seal-status
```

## 🔍 Diagnostic Tools

### System Diagnostics
```bash
# Create diagnostic script
cat > /opt/secreton/bin/diagnostics.sh << 'EOF'
#!/bin/bash
echo "=== Secreton Diagnostics ==="
echo "Timestamp: $(date)"
echo "Uptime: $(uptime)"
echo ""

echo "=== Service Status ==="
systemctl status secreton --no-pager
echo ""

echo "=== Process Information ==="
ps aux | grep secreton | grep -v grep
echo ""

echo "=== System Resources ==="
echo "CPU Usage:"
top -b -n 1 | head -20
echo ""
echo "Memory Usage:"
free -h
echo ""
echo "Disk Usage:"
df -h /opt/secreton
echo ""

echo "=== Network Status ==="
netstat -tlnp | grep :8200
echo ""

echo "=== Recent Logs ==="
tail -20 /opt/secreton/logs/secreton.log
echo ""

echo "=== Health Check ==="
curl -k -s https://localhost:8200/v1/sys/health | jq . || echo "Health check failed"
EOF

chmod +x /opt/secreton/bin/diagnostics.sh
```

### Log Analysis Tools
```bash
# Search for specific errors
grep -i "error\|failed\|exception" /opt/secreton/logs/secreton.log | tail -20

# Find authentication failures
grep "authentication failed" /opt/secreton/logs/audit.log | tail -10

# Check for high latency requests
grep "duration.*[0-9]\{3,\}ms" /opt/secreton/logs/secreton.log

# Monitor error patterns
tail -f /opt/secreton/logs/secreton.log | grep --line-buffered "ERROR"
```

### Performance Profiling
```bash
# Enable profiling
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/profiling/start

# Wait for data collection
sleep 300

# Stop profiling and get report
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/profiling/stop

# Analyze thread dumps
jstack $(pgrep secreton) > thread_dump.txt
```

## 🐛 Common Issues and Solutions

### 1. Startup Failures

#### Database Connection Issues
**Symptoms:**
- Service fails to start
- Logs show "connection refused" or "authentication failed"
- PostgreSQL connection errors

**Diagnosis:**
```bash
# Check database status
sudo systemctl status postgresql

# Test database connection
psql -h localhost -U secreton -d secreton_db -c "SELECT 1;"

# Check connection string
grep "database" /opt/secreton/config/vault.toml

# Verify database credentials
sudo -u postgres psql -c "SELECT usename, passwd FROM pg_shadow WHERE usename = 'secreton';"
```

**Solutions:**
```bash
# 1. Reset database password
sudo -u postgres psql
ALTER USER secreton PASSWORD 'new_secure_password';
\q

# 2. Update configuration
sed -i 's/password = "old_password"/password = "new_secure_password"/' /opt/secreton/config/vault.toml

# 3. Restart services
sudo systemctl restart postgresql
sudo systemctl restart secreton
```

#### TLS Certificate Issues
**Symptoms:**
- HTTPS connection failures
- Certificate validation errors
- "SSL handshake failed" messages

**Diagnosis:**
```bash
# Check certificate validity
openssl x509 -in /opt/secreton/certs/server.crt -text -noout | grep -E "(Not Before|Not After)"

# Test certificate chain
openssl verify -CAfile /opt/secreton/certs/ca.crt /opt/secreton/certs/server.crt

# Check certificate permissions
ls -la /opt/secreton/certs/

# Test TLS connection
openssl s_client -connect localhost:8200 -servername vault.example.com
```

**Solutions:**
```bash
# 1. Renew expired certificate
sudo -u secreton openssl req -x509 -newkey rsa:4096 \
  -keyout /opt/secreton/certs/server.key \
  -out /opt/secreton/certs/server.crt \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=vault.example.com"

# 2. Fix permissions
sudo chown secreton:secreton /opt/secreton/certs/*
sudo chmod 600 /opt/secreton/certs/server.key
sudo chmod 644 /opt/secreton/certs/server.crt

# 3. Restart service
sudo systemctl restart secreton
```

### 2. Performance Issues

#### High Memory Usage
**Symptoms:**
- System memory usage > 90%
- Out of memory errors
- Service restarts due to OOM

**Diagnosis:**
```bash
# Check memory usage
free -h
ps aux --sort=-%mem | head -10

# Monitor memory growth
vmstat 1 10

# Check for memory leaks
pmap -x $(pgrep secreton) | tail -10

# Review memory configuration
grep -i "memory\|cache" /opt/secreton/config/vault.toml
```

**Solutions:**
```bash
# 1. Increase system memory or add swap
sudo fallocate -l 4G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 2. Tune memory settings
echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# 3. Restart with memory limits
sudo systemctl edit secreton
# Add: [Service]
# MemoryLimit=2G
sudo systemctl daemon-reload
sudo systemctl restart secreton
```

#### High CPU Usage
**Symptoms:**
- CPU usage > 80%
- Slow response times
- System becomes unresponsive

**Diagnosis:**
```bash
# Check CPU usage
top -p $(pgrep secreton)
iostat -c 1 5

# Profile CPU usage
perf record -p $(pgrep secreton) -g -- sleep 30
perf report

# Check for infinite loops
strace -p $(pgrep secreton) -c
```

**Solutions:**
```bash
# 1. Enable CPU limits
sudo systemctl edit secreton
# Add: [Service]
# CPUQuota=80%
sudo systemctl daemon-reload
sudo systemctl restart secreton

# 2. Check for runaway processes
pkill -f secreton
sudo systemctl restart secreton

# 3. Review configuration for performance settings
grep -i "workers\|threads\|concurrency" /opt/secreton/config/vault.toml
```

#### Slow Database Queries
**Symptoms:**
- API requests timeout
- Database connection pool exhausted
- High query latency

**Diagnosis:**
```sql
-- Check active queries
SELECT pid, age(clock_timestamp(), query_start), usename, query
FROM pg_stat_activity
WHERE query != '<IDLE>' AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY query_start desc;

-- Check slow queries
SELECT query, calls, total_time, mean_time, rows
FROM pg_stat_statements
ORDER BY mean_time DESC
LIMIT 10;

-- Check table bloat
SELECT schemaname, tablename, n_dead_tup, n_live_tup
FROM pg_stat_user_tables
ORDER BY n_dead_tup DESC;
```

**Solutions:**
```sql
-- 1. Analyze slow queries
EXPLAIN ANALYZE SELECT * FROM audit_log WHERE timestamp > '2023-01-01';

-- 2. Add indexes for common queries
CREATE INDEX CONCURRENTLY idx_audit_timestamp ON audit_log (timestamp);
CREATE INDEX CONCURRENTLY idx_audit_operation ON audit_log (operation);

-- 3. Vacuum and reindex
VACUUM ANALYZE audit_log;
REINDEX TABLE audit_log;

-- 4. Increase connection pool
-- Update vault.toml
[database]
max_connections = 50
```

### 3. Cluster Issues

#### Node Communication Failures
**Symptoms:**
- Nodes can't join cluster
- Leader election failures
- Replication lag

**Diagnosis:**
```bash
# Check cluster status
curl -k https://vault.example.com/v1/sys/leader

# Check node connectivity
for node in vault-node1 vault-node2 vault-node3; do
  curl -k https://$node.example.com:8200/v1/sys/health
done

# Check raft logs
tail -f /opt/secreton/logs/secreton.log | grep raft

# Verify cluster configuration
grep -A 10 "cluster" /opt/secreton/config/vault.toml
```

**Solutions:**
```bash
# 1. Check network connectivity
telnet vault-node2.example.com 8201

# 2. Verify TLS certificates
openssl s_client -connect vault-node2.example.com:8201

# 3. Restart cluster communication
sudo systemctl restart secreton

# 4. Force leader election
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/step-down
```

#### Split Brain Scenario
**Symptoms:**
- Multiple leaders detected
- Inconsistent data across nodes
- Client connection failures

**Diagnosis:**
```bash
# Check leader status on all nodes
for node in vault-node1 vault-node2 vault-node3; do
  echo "=== $node ==="
  curl -k https://$node.example.com:8200/v1/sys/leader
done

# Check raft state
curl -k https://vault-node1.example.com:8200/v1/sys/raft/state

# Review cluster logs
grep "leader\|election\|split" /opt/secreton/logs/secreton.log
```

**Solutions:**
```bash
# 1. Identify legitimate leader
# Check which node has the most recent data
curl -k https://vault-node1.example.com:8200/v1/sys/raft/configuration

# 2. Remove faulty nodes
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"server_id": "faulty-node-id"}' \
  https://vault-node1.example.com:8200/v1/sys/raft/remove-peer

# 3. Add healthy nodes back
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "server_id": "healthy-node-id",
    "server_address": "vault-node2.example.com:8201"
  }' \
  https://vault-node1.example.com:8200/v1/sys/raft/add-peer
```

### 4. Security Issues

#### Authentication Failures
**Symptoms:**
- Login attempts failing
- Token validation errors
- MFA authentication issues

**Diagnosis:**
```bash
# Check authentication methods
curl -k https://vault.example.com/v1/sys/auth

# Review authentication logs
grep "authentication\|login" /opt/secreton/logs/audit.log | tail -20

# Check user lockouts
curl -k \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/auth/userpass/users | jq .

# Verify MFA configuration
curl -k \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/mfa/method
```

**Solutions:**
```bash
# 1. Reset user password
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"password": "new_secure_password"}' \
  https://vault.example.com/v1/auth/userpass/users/admin

# 2. Check MFA settings
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"method": "totp"}' \
  https://vault.example.com/v1/sys/mfa/method/totp

# 3. Review security policies
curl -k \
  -H "X-Vault-Token: $TOKEN" \
  https://vault.example.com/v1/sys/policies/acl
```

#### Certificate Validation Issues
**Symptoms:**
- mTLS authentication failing
- Certificate chain validation errors
- Client certificate rejected

**Diagnosis:**
```bash
# Check certificate validity
openssl x509 -in /opt/secreton/certs/client.crt -text -noout

# Verify certificate chain
openssl verify -CAfile /opt/secreton/certs/ca.crt /opt/secreton/certs/client.crt

# Check CRL status
openssl crl -in /opt/secreton/certs/ca.crl -text

# Test client certificate
curl --cert /opt/secreton/certs/client.crt \
     --key /opt/secreton/certs/client.key \
     --cacert /opt/secreton/certs/ca.crt \
     https://vault.example.com/v1/sys/health
```

**Solutions:**
```bash
# 1. Renew client certificate
openssl req -new -key client.key -out client.csr
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out client.crt -days 365

# 2. Update CRL
openssl ca -gencrl -out ca.crl -crldays 365

# 3. Restart service
sudo systemctl restart secreton
```

### 5. Data Issues

#### Data Corruption
**Symptoms:**
- Inconsistent secret values
- Decryption failures
- Database integrity errors

**Diagnosis:**
```sql
-- Check database integrity
SELECT schemaname, tablename
FROM pg_tables
WHERE schemaname = 'public';

-- Verify data consistency
SELECT COUNT(*) FROM secrets;
SELECT COUNT(*) FROM audit_log;

-- Check for orphaned records
SELECT s.id FROM secrets s
LEFT JOIN secret_versions sv ON s.id = sv.secret_id
WHERE sv.secret_id IS NULL;
```

**Solutions:**
```bash
# 1. Create backup before repair
pg_dump secreton_db > backup_$(date +%Y%m%d_%H%M%S).sql

# 2. Repair corrupted data
REINDEX DATABASE secreton_db;
VACUUM FULL;

# 3. Verify repair
psql -d secreton_db -c "SELECT * FROM pg_stat_database WHERE datname = 'secreton_db';"
```

#### Storage Full
**Symptoms:**
- Write operations failing
- Service becoming unresponsive
- Disk space alerts

**Diagnosis:**
```bash
# Check disk usage
df -h /opt/secreton/data

# Find large files
find /opt/secreton/data -type f -size +100M -exec ls -lh {} \;

# Check log file sizes
ls -lh /opt/secreton/logs/

# Monitor disk I/O
iostat -x 1
```

**Solutions:**
```bash
# 1. Clean old logs
find /opt/secreton/logs -name "*.log" -mtime +30 -delete

# 2. Rotate audit logs
logrotate -f /etc/logrotate.d/secreton

# 3. Clean database
psql -d secreton_db -c "VACUUM FULL;"

# 4. Add more storage
# Extend disk or add new volume
sudo resize2fs /dev/sda1  # if extending partition
```

## 🔄 Recovery Procedures

### Database Recovery
```bash
# 1. Stop vault service
sudo systemctl stop secreton

# 2. Restore from backup
createdb secreton_recovery
psql secreton_recovery < backup.sql

# 3. Verify recovery
psql secreton_recovery -c "SELECT COUNT(*) FROM secrets;"

# 4. Switch databases
psql -c "ALTER DATABASE secreton_db RENAME TO secreton_old;"
psql -c "ALTER DATABASE secreton_recovery RENAME TO secreton_db;"

# 5. Restart service
sudo systemctl start secreton
```

### Cluster Recovery
```bash
# 1. Identify healthy node
curl -k https://vault-node1.example.com:8200/v1/sys/health

# 2. Remove failed nodes
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"server_id": "failed-node-id"}' \
  https://vault-node1.example.com:8200/v1/sys/raft/remove-peer

# 3. Add replacement nodes
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "server_id": "new-node-id",
    "server_address": "vault-node4.example.com:8201"
  }' \
  https://vault-node1.example.com:8200/v1/sys/raft/add-peer

# 4. Verify cluster
curl -k https://vault-node1.example.com:8200/v1/sys/raft/configuration
```

### Disaster Recovery
```bash
# 1. Activate DR site
# Follow DR plan procedures

# 2. Restore from offsite backup
aws s3 cp s3://secreton-backups/latest.sql.gz - | gunzip | psql secreton_db

# 3. Restore configuration
aws s3 cp s3://secreton-backups/config.tar.gz - | tar -xzf -

# 4. Start services
sudo systemctl start postgresql
sudo systemctl start secreton

# 5. Unseal vault
# Use DR unseal keys

# 6. Verify functionality
curl -k https://vault-dr.example.com/v1/sys/health
```

## 📊 Monitoring and Alerting

### Key Metrics to Monitor
```bash
# System health
curl -k https://vault.example.com/v1/sys/health

# Performance metrics
curl -k https://vault.example.com/v1/sys/metrics?format=prometheus

# Error rates
grep "ERROR\|FAILED" /opt/secreton/logs/secreton.log | wc -l

# Response times
curl -w "@curl-format.txt" -o /dev/null -s https://vault.example.com/v1/sys/health
```

### Alert Configuration
```yaml
# Prometheus alert rules
groups:
  - name: vault_troubleshooting
    rules:
      - alert: VaultServiceDown
        expr: up{job="secreton"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Secreton service is down"
          runbook: "https://docs.secreton.com/troubleshooting#service-down"

      - alert: VaultHighErrorRate
        expr: rate(vault_core_handle_request_total{status="error"}[5m]) / rate(vault_core_handle_request_total[5m]) > 0.1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
          runbook: "https://docs.secreton.com/troubleshooting#error-rate"
```

## 📞 Support and Escalation

### Support Tiers
1. **Tier 1**: Basic troubleshooting, documentation review
2. **Tier 2**: Advanced diagnostics, configuration changes
3. **Tier 3**: Code-level analysis, emergency fixes

### Escalation Procedures
- **Critical Issues**: Immediate escalation to Tier 3
- **Production Down**: Page on-call engineer
- **Security Incidents**: Follow security incident response plan

### Information to Collect
```bash
# System information
uname -a
lsb_release -a
docker --version 2>/dev/null || echo "Docker not installed"

# Secreton information
secreton version
cat /opt/secreton/config/vault.toml | grep -v password

# Log excerpts
tail -100 /opt/secreton/logs/secreton.log
tail -50 /opt/secreton/logs/audit.log

# Performance data
top -b -n 1 | head -20
free -h
df -h
```

## 📚 Additional Resources

### Documentation Links
- [Deployment Guide](../docs/DEPLOYMENT_GUIDE.md)
- [Monitoring Guide](../docs/MONITORING_GUIDE.md)
- [Security Hardening](../docs/SECURITY_HARDENING.md)
- [API Reference](../docs/API_REFERENCE.md)

### Community Resources
- [GitHub Issues](https://github.com/cipherce/secreton/issues)
- [Discussion Forum](https://github.com/cipherce/secreton/discussions)
- [Stack Overflow](https://stackoverflow.com/questions/tagged/secreton)

### Professional Services
- 24/7 Enterprise Support
- On-site Consulting
- Custom Training
- Emergency Response Team

---

**This troubleshooting guide provides comprehensive diagnostic and resolution procedures for Secreton Enterprise Vault. For critical production issues, contact enterprise support immediately.**
