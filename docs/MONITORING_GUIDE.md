# Secreton Enterprise Vault - Monitoring Guide

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 📊 Overview

This guide provides comprehensive monitoring and observability strategies for Secreton Enterprise Vault. Effective monitoring ensures system reliability, performance optimization, and proactive issue resolution.

## 🎯 Monitoring Objectives

### Key Metrics to Monitor
- **System Health**: CPU, memory, disk, network utilization
- **Application Performance**: Request latency, throughput, error rates
- **Security Events**: Authentication failures, access patterns, audit logs
- **Database Performance**: Connection pools, query performance, replication lag
- **Cluster Health**: Node status, leader elections, consensus state

### Monitoring Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Monitoring Stack                         │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ Prometheus  │    │   Grafana   │    │  AlertMgr   │     │
│  │  Metrics    │    │ Dashboards  │    │   Alerts    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                             │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │   Loki      │    │   Tempo     │    │   Jaeger    │     │
│  │    Logs     │    │   Traces    │    │   Tracing   │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

## 📈 Metrics Collection

### Built-in Metrics Endpoints

#### Health Check Endpoints
```bash
# Basic health check
curl https://vault.example.com/v1/sys/health

# Response format
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1638360000,
  "version": "2.1.1",
  "cluster_name": "vault-cluster",
  "cluster_id": "cluster-id-here"
}

# Detailed health check
curl https://vault.example.com/v1/sys/health?standbyok=true&performancestandbyok=true&drsecondaryok=true

# Seal status
curl https://vault.example.com/v1/sys/seal-status

# Leader status
curl https://vault.example.com/v1/sys/leader
```

#### Prometheus Metrics
```bash
# Enable metrics endpoint
curl -X POST \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"prometheus_retention_time": "24h"}' \
  https://vault.example.com/v1/sys/metrics

# Retrieve metrics
curl https://vault.example.com/v1/sys/metrics?format=prometheus

# Sample metrics output
# HELP vault_core_handle_request_total Total number of requests handled
# TYPE vault_core_handle_request_total counter
vault_core_handle_request_total{cluster="vault-cluster",host="vault-node1"} 12345

# HELP vault_core_handle_request_duration_seconds Request duration histogram
# TYPE vault_core_handle_request_duration_seconds histogram
vault_core_handle_request_duration_seconds_bucket{cluster="vault-cluster",host="vault-node1",le="0.1"} 1000
vault_core_handle_request_duration_seconds_bucket{cluster="vault-cluster",host="vault-node1",le="1"} 5000
```

### System Metrics

#### CPU and Memory Monitoring
```bash
# CPU usage
top -p $(pgrep secreton) -b -n 1 | grep "secreton"

# Memory usage
ps aux --no-headers -o pmem,comm | grep secreton

# System load
uptime
cat /proc/loadavg

# CPU details
lscpu
```

#### Disk and Storage Monitoring
```bash
# Disk usage
df -h /opt/secreton/data

# Inode usage
df -i /opt/secreton/data

# Disk I/O statistics
iostat -x 1

# Storage performance
fio --name=randread --rw=randread --bs=4k --size=1g --numjobs=4 --runtime=60
```

#### Network Monitoring
```bash
# Network connections
netstat -tlnp | grep :8200
ss -tlnp | grep :8200

# Network statistics
ip -s link
netstat -i

# Traffic monitoring
iftop -i eth0
```

### Database Metrics

#### PostgreSQL Monitoring
```sql
-- Connection count
SELECT count(*) as connections FROM pg_stat_activity;

-- Active queries
SELECT pid, age(clock_timestamp(), query_start), usename, query
FROM pg_stat_activity
WHERE query != '<IDLE>' AND query NOT ILIKE '%pg_stat_activity%'
ORDER BY query_start desc;

-- Database size
SELECT pg_size_pretty(pg_database_size('secreton_db'));

-- Table sizes
SELECT schemaname, tablename, pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename))
FROM pg_tables
WHERE schemaname = 'public'
ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC;

-- Index usage
SELECT schemaname, tablename, indexname, idx_scan, idx_tup_read, idx_tup_fetch
FROM pg_stat_user_indexes
ORDER BY idx_scan DESC;
```

#### Connection Pool Monitoring
```bash
# Check connection pool status
curl https://vault.example.com/v1/sys/metrics | grep "vault_database"

# Database connection metrics
vault_database_connection_count{cluster="vault-cluster",database="postgresql"} 15
vault_database_connection_max{cluster="vault-cluster",database="postgresql"} 20
vault_database_connection_idle{cluster="vault-cluster",database="postgresql"} 5
```

## 📊 Prometheus Configuration

### Prometheus Server Setup
```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alert_rules.yml"

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093

scrape_configs:
  - job_name: 'secreton'
    static_configs:
      - targets: ['vault.example.com:8200']
    metrics_path: '/v1/sys/metrics'
    params:
      format: ['prometheus']
    tls_config:
      ca_file: /etc/prometheus/certs/ca.crt
      cert_file: /etc/prometheus/certs/client.crt
      key_file: /etc/prometheus/certs/client.key
    scrape_interval: 30s
    scrape_timeout: 10s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres:9187']
    scrape_interval: 30s

  - job_name: 'node'
    static_configs:
      - targets: ['vault-node1:9100', 'vault-node2:9100', 'vault-node3:9100']
    scrape_interval: 30s

  - job_name: 'redis'
    static_configs:
      - targets: ['redis:9121']
    scrape_interval: 30s
```

### Alert Rules
```yaml
# alert_rules.yml
groups:
  - name: vault
    rules:
      - alert: VaultDown
        expr: up{job="secreton"} == 0
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Secreton vault is down"
          description: "Secreton vault has been down for more than 5 minutes."

      - alert: VaultSealed
        expr: vault_core_unsealed == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Secreton vault is sealed"
          description: "Secreton vault is sealed and needs to be unsealed."

      - alert: VaultHighRequestLatency
        expr: histogram_quantile(0.95, rate(vault_core_handle_request_duration_seconds_bucket[5m])) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High request latency"
          description: "95th percentile request latency is above 1 second."

      - alert: VaultHighErrorRate
        expr: rate(vault_core_handle_request_total{status="error"}[5m]) / rate(vault_core_handle_request_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate"
          description: "Error rate is above 5%."

      - alert: VaultLowDiskSpace
        expr: (1 - node_filesystem_avail_bytes / node_filesystem_size_bytes) * 100 > 85
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Low disk space"
          description: "Disk usage is above 85%."

      - alert: VaultHighMemoryUsage
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 90
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High memory usage"
          description: "Memory usage is above 90%."

      - alert: VaultDatabaseConnectionPoolExhausted
        expr: vault_database_connection_count / vault_database_connection_max > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Database connection pool exhausted"
          description: "Database connection pool usage is above 90%."

      - alert: VaultAuthFailures
        expr: rate(vault_audit_log_request_failure_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"
          description: "Authentication failure rate is above 10 per minute."
```

## 📈 Grafana Dashboards

### Main Dashboard
```json
{
  "dashboard": {
    "title": "Secreton Enterprise Vault - Overview",
    "tags": ["secreton", "vault", "security"],
    "timezone": "browser",
    "refresh": "30s",
    "panels": [
      {
        "title": "System Health",
        "type": "stat",
        "targets": [
          {
            "expr": "up{job=\"secreton\"}",
            "legendFormat": "Vault Status"
          }
        ],
        "fieldConfig": {
          "defaults": {
            "mappings": [
              {
                "options": {
                  "0": {
                    "text": "DOWN",
                    "color": "red"
                  },
                  "1": {
                    "text": "UP",
                    "color": "green"
                  }
                },
                "type": "value"
              }
            ]
          }
        }
      },
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_core_handle_request_total[5m])",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Response Time (95th percentile)",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(vault_core_handle_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_core_handle_request_total{status=\"error\"}[5m]) / rate(vault_core_handle_request_total[5m]) * 100",
            "legendFormat": "Error Rate %"
          }
        ]
      },
      {
        "title": "Active Connections",
        "type": "singlestat",
        "targets": [
          {
            "expr": "vault_core_active_connections",
            "legendFormat": "Active Connections"
          }
        ]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100",
            "legendFormat": "Memory Usage %"
          }
        ]
      },
      {
        "title": "Disk Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "(1 - node_filesystem_avail_bytes{mountpoint=\"/opt/secreton/data\"} / node_filesystem_size_bytes{mountpoint=\"/opt/secreton/data\"}) * 100",
            "legendFormat": "Disk Usage %"
          }
        ]
      },
      {
        "title": "Database Connections",
        "type": "graph",
        "targets": [
          {
            "expr": "vault_database_connection_count",
            "legendFormat": "Active Connections"
          },
          {
            "expr": "vault_database_connection_max",
            "legendFormat": "Max Connections"
          }
        ]
      }
    ]
  }
}
```

### Security Dashboard
```json
{
  "dashboard": {
    "title": "Secreton Enterprise Vault - Security",
    "tags": ["secreton", "vault", "security"],
    "timezone": "browser",
    "refresh": "30s",
    "panels": [
      {
        "title": "Authentication Attempts",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_audit_log_request_total{operation=\"login\"}[5m])",
            "legendFormat": "Login Attempts"
          }
        ]
      },
      {
        "title": "Authentication Failures",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_audit_log_request_failure_total{operation=\"login\"}[5m])",
            "legendFormat": "Login Failures"
          }
        ]
      },
      {
        "title": "Token Creations",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_audit_log_request_total{operation=\"create\",path=~\"auth/token.*\"}[5m])",
            "legendFormat": "Token Creations"
          }
        ]
      },
      {
        "title": "Secret Access Patterns",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, rate(vault_audit_log_request_total{path=~\"secret.*\"}[1h]))",
            "legendFormat": "Secret Access"
          }
        ]
      },
      {
        "title": "Transit Engine Usage",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_audit_log_request_total{path=~\"transit/encrypt.*\"}[5m])",
            "legendFormat": "Encryption Operations"
          },
          {
            "expr": "rate(vault_audit_log_request_total{path=~\"transit/decrypt.*\"}[5m])",
            "legendFormat": "Decryption Operations"
          }
        ]
      },
      {
        "title": "Unusual Access Patterns",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_audit_log_request_total{client_ip!~\"10\\.0\\.0\\..*\"}[5m])",
            "legendFormat": "External Access"
          }
        ]
      }
    ]
  }
}
```

### Performance Dashboard
```json
{
  "dashboard": {
    "title": "Secreton Enterprise Vault - Performance",
    "tags": ["secreton", "vault", "performance"],
    "timezone": "browser",
    "refresh": "30s",
    "panels": [
      {
        "title": "Request Latency Distribution",
        "type": "heatmap",
        "targets": [
          {
            "expr": "rate(vault_core_handle_request_duration_seconds_bucket[5m])",
            "legendFormat": "Request Duration"
          }
        ]
      },
      {
        "title": "Throughput by Endpoint",
        "type": "table",
        "targets": [
          {
            "expr": "topk(10, rate(vault_core_handle_request_total[5m]))",
            "legendFormat": "Requests/sec"
          }
        ]
      },
      {
        "title": "Database Query Performance",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(vault_database_query_duration_seconds_sum[5m]) / rate(vault_database_query_duration_seconds_count[5m])",
            "legendFormat": "Avg Query Time"
          }
        ]
      },
      {
        "title": "Cache Hit Rate",
        "type": "singlestat",
        "targets": [
          {
            "expr": "rate(vault_cache_hit_total[5m]) / (rate(vault_cache_hit_total[5m]) + rate(vault_cache_miss_total[5m])) * 100",
            "legendFormat": "Cache Hit Rate %"
          }
        ]
      },
      {
        "title": "Network I/O",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(node_network_receive_bytes_total[5m])",
            "legendFormat": "Network In"
          },
          {
            "expr": "rate(node_network_transmit_bytes_total[5m])",
            "legendFormat": "Network Out"
          }
        ]
      },
      {
        "title": "Disk I/O",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(node_disk_read_bytes_total[5m])",
            "legendFormat": "Disk Read"
          },
          {
            "expr": "rate(node_disk_written_bytes_total[5m])",
            "legendFormat": "Disk Write"
          }
        ]
      }
    ]
  }
}
```

## 📝 Log Aggregation

### Loki Configuration
```yaml
# loki-config.yaml
auth_enabled: false

server:
  http_listen_port: 3100
  grpc_listen_port: 9096

common:
  instance_addr: 127.0.0.1
  path_prefix: /tmp/loki
  storage:
    filesystem:
      chunks_directory: /tmp/loki/chunks
      rules_directory: /tmp/loki/rules
  replication_factor: 1
  ring:
    kvstore:
      store: inmemory

query_range:
  results_cache:
    cache:
      embedded_cache:
        enabled: true
        max_size_mb: 100

schema_config:
  configs:
    - from: 2020-10-24
      store: boltdb-shipper
      object_store: filesystem
      schema: v11
      index:
        prefix: index_
        period: 24h

ruler:
  alertmanager_url: http://localhost:9093
```

### Promtail Configuration
```yaml
# promtail-config.yaml
server:
  http_listen_port: 9080
  grpc_listen_port: 0

positions:
  filename: /tmp/positions.yaml

clients:
  - url: http://localhost:3100/loki/api/v1/push

scrape_configs:
  - job_name: vault_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: vault
          __path__: /opt/secreton/logs/secreton.log
    pipeline_stages:
      - match:
          selector: '{job="vault"}'
          stages:
            - regex:
                expression: '^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\s+(?P<level>\w+)\s+(?P<message>.+)$'
            - labels:
                level:
                timestamp:
            - timestamp:
                source: timestamp
                format: RFC3339Nano

  - job_name: audit_logs
    static_configs:
      - targets:
          - localhost
        labels:
          job: vault_audit
          __path__: /opt/secreton/logs/audit.log
    pipeline_stages:
      - match:
          selector: '{job="vault_audit"}'
          stages:
            - json:
                expressions:
                  timestamp: time
                  request_id: request_id
                  operation: operation
                  path: path
                  client_ip: remote_address
                  user: auth.display_name
            - labels:
                operation:
                path:
                client_ip:
                user:
            - timestamp:
                source: timestamp
                format: RFC3339Nano
```

### Log Queries
```bash
# Query vault logs
curl "http://localhost:3100/loki/api/v1/query_range?query={job=\"vault\"}&start=2023-01-01T00:00:00Z&end=2023-01-02T00:00:00Z&limit=100"

# Query error logs
curl "http://localhost:3100/loki/api/v1/query?query={job=\"vault\",level=\"error\"}"

# Query authentication failures
curl "http://localhost:3100/loki/api/v1/query?query={job=\"vault_audit\",operation=\"login\",response_status=\"403\"}"

# Query high latency requests
curl "http://localhost:3100/loki/api/v1/query?query={job=\"vault\"} |~ \"duration.*[0-9]{3,}ms\""
```

## 🔍 Distributed Tracing

### Jaeger Configuration
```yaml
# jaeger-config.yaml
service:
  extensions: [jaeger_storage, jaeger_query]
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [jaeger_storage]

extensions:
  jaeger_storage:
    backends:
      memory:
        max_traces: 100000
  jaeger_query:
    storage:
      traces:
        backend: memory

receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    send_batch_size: 1024
    timeout: 1s

exporters:
  jaeger_storage:
    trace_storage: memory
```

### Application Tracing
```rust
// Add tracing to Secreton
use tracing::{info, error, instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[instrument]
async fn handle_request(request: Request) -> Result<Response, Error> {
    info!("Processing request: {:?}", request);

    // Add custom spans
    let span = tracing::span!(tracing::Level::INFO, "database_query");
    let _enter = span.enter();

    match database_query(request).await {
        Ok(result) => {
            info!("Query successful");
            Ok(result)
        }
        Err(e) => {
            error!("Query failed: {:?}", e);
            Err(e)
        }
    }
}
```

## 🚨 Alert Management

### Alertmanager Configuration
```yaml
# alertmanager.yml
global:
  smtp_smarthost: 'smtp.example.com:587'
  smtp_from: 'alerts@example.com'
  smtp_auth_username: 'alerts@example.com'
  smtp_auth_password: 'password'

route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'team'
  routes:
  - match:
      severity: critical
    receiver: 'team-critical'
  - match:
      severity: warning
    receiver: 'team-warning'

receivers:
- name: 'team'
  email_configs:
  - to: 'team@example.com'
    send_resolved: true
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/xxx/yyy/zzz'
    channel: '#alerts'
    send_resolved: true

- name: 'team-critical'
  email_configs:
  - to: 'oncall@example.com'
    send_resolved: true
  slack_configs:
  - api_url: 'https://hooks.slack.com/services/xxx/yyy/zzz'
    channel: '#critical-alerts'
    send_resolved: true

- name: 'team-warning'
  email_configs:
  - to: 'team@example.com'
    send_resolved: true
```

### Alert Response Procedures

#### Critical Alerts
1. **Vault Down**: Immediate investigation required
   - Check system resources (CPU, memory, disk)
   - Review system logs for errors
   - Attempt restart if safe
   - Escalate to on-call engineer

2. **Vault Sealed**: Requires immediate unseal
   - Gather unseal key holders
   - Perform unseal procedure
   - Verify cluster health
   - Review seal trigger cause

#### Warning Alerts
1. **High Latency**: Performance investigation
   - Check system resources
   - Review database performance
   - Analyze request patterns
   - Consider scaling if needed

2. **High Error Rate**: Application issues
   - Review error logs
   - Check dependencies (database, cache)
   - Analyze failing requests
   - Implement fixes or rollbacks

## 📊 Custom Metrics and Monitoring

### Application Metrics
```rust
// Custom metrics in Secreton
use prometheus::{Encoder, TextEncoder, register_counter, register_histogram};
use lazy_static::lazy_static;

lazy_static! {
    static ref REQUEST_COUNTER: prometheus::Counter = 
        register_counter!("secreton_requests_total", "Total number of requests")
            .expect("Can't create metrics");

    static ref REQUEST_DURATION: prometheus::Histogram = 
        register_histogram!("secreton_request_duration_seconds", 
                           "Request duration in seconds")
            .expect("Can't create metrics");
}

async fn handle_request(request: Request) -> Result<Response, Error> {
    let _timer = REQUEST_DURATION.start_timer();
    REQUEST_COUNTER.inc();

    // Process request
    let result = process_request(request).await;

    match result {
        Ok(response) => {
            // Record success metrics
            Ok(response)
        }
        Err(e) => {
            // Record error metrics
            REQUEST_ERRORS.inc();
            Err(e)
        }
    }
}
```

### Business Metrics
```bash
# Monitor business KPIs
curl https://vault.example.com/v1/sys/metrics | grep "business_"

# Example business metrics
vault_business_secrets_created_total{cluster="vault-cluster"} 15432
vault_business_tokens_issued_total{cluster="vault-cluster"} 8765
vault_business_transit_operations_total{cluster="vault-cluster"} 45678
```

## 🔧 Monitoring Best Practices

### 1. Alert Fatigue Prevention
- Set appropriate alert thresholds
- Use alert grouping and inhibition
- Implement alert escalation policies
- Regular alert review and tuning

### 2. Monitoring Coverage
- Monitor all system components
- Include business metrics
- Track user experience metrics
- Monitor security events

### 3. Data Retention
- Metrics: 30 days minimum
- Logs: 90 days minimum
- Traces: 7 days minimum
- Audit logs: 1 year minimum (compliance)

### 4. Performance Baselines
- Establish normal operating ranges
- Monitor for deviations
- Regular baseline updates
- Seasonal adjustment consideration

### 5. Incident Response
- Documented response procedures
- Escalation paths
- Communication templates
- Post-incident reviews

## 📚 Additional Resources

### Documentation Links
- [Deployment Guide](../docs/DEPLOYMENT_GUIDE.md)
- [Security Hardening](../docs/SECURITY_HARDENING.md)
- [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)
- [Performance Benchmarks](../docs/PERFORMANCE_BENCHMARKS.md)

### Tools and Integrations
- [Prometheus](https://prometheus.io/)
- [Grafana](https://grafana.com/)
- [Loki](https://grafana.com/oss/loki/)
- [Jaeger](https://www.jaegertracing.io/)
- [Alertmanager](https://prometheus.io/docs/alerting/latest/alertmanager/)

### Community Resources
- [Monitoring Best Practices](https://sre.google/sre-book/monitoring-distributed-systems/)
- [Prometheus Monitoring Mixins](https://monitoring.mixins.dev/)
- [Grafana Dashboards](https://grafana.com/grafana/dashboards/)

---

**Effective monitoring is crucial for maintaining the reliability and security of Secreton Enterprise Vault. This guide provides comprehensive monitoring strategies for production deployments.**
