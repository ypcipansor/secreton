# Brankas Production Deployment Guide

## Overview

Brankas is an enterprise-grade HashiCorp Vault-compatible transit engine built with Rust and RustCrypto. This guide covers production deployment, configuration, monitoring, and security considerations.

## Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Load Balancer │────│  Brankas API     │────│   Transit       │
│   (nginx/HAProxy)│    │   (HTTP/TLS)     │    │   Engine        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                              │                         │
                              ▼                         ▼
                    ┌──────────────────┐    ┌─────────────────┐
                    │   Audit Logging  │    │   Key Storage   │
                    │   (File/Syslog)  │    │   (Memory/HSM)  │
                    └──────────────────┘    └─────────────────┘
```

## Features

### Core Cryptographic Operations
- **AES-256-GCM**: NIST-approved authenticated encryption
- **ChaCha20-Poly1305**: Modern AEAD cipher for high performance
- **RSA**: Asymmetric encryption and signing (OAEP, PSS, PKCS1v15)
- **Ed25519**: Fast elliptic curve signatures
- **HMAC**: Message authentication (SHA-256, SHA-512)
- **Key Derivation**: PBKDF2, scrypt, Argon2id support

### API Features
- **Vault-Compatible**: Drop-in replacement for HashiCorp Vault transit engine
- **REST API**: Full HTTP API with OpenAPI/Swagger documentation
- **Batch Operations**: High-throughput bulk encryption/decryption
- **Key Management**: Create, rotate, delete, and export keys
- **Random Generation**: Cryptographically secure random data
- **Health Checks**: Monitoring and status endpoints

### Security Features
- **JWT Authentication**: Role-based access control (RBAC)
- **Rate Limiting**: DDoS protection and resource management
- **Audit Logging**: Comprehensive security event tracking
- **TLS Termination**: End-to-end encryption
- **Security Headers**: OWASP-compliant HTTP security
- **Input Validation**: Comprehensive request sanitization

### Production Features
- **High Performance**: Async Rust with Tokio for concurrent operations
- **Horizontal Scaling**: Stateless design for multi-instance deployment
- **Monitoring**: Prometheus metrics and health endpoints
- **Configuration**: Environment-based configuration management
- **Graceful Shutdown**: Clean resource cleanup on termination

## Quick Start

### Prerequisites

- Rust 1.70+ (stable)
- Linux/macOS/Windows
- 2GB+ RAM (4GB recommended)
- TLS certificates (for production)

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/brankas.git
cd brankas

# Build release binary
cargo build --release --bin api_server

# Run with default configuration
./target/release/api_server
```

### Docker Deployment

```dockerfile
FROM rust:1.70-alpine AS builder
WORKDIR /app
COPY . .
RUN cargo build --release --bin api_server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/target/release/api_server .
EXPOSE 8200
CMD ["./api_server"]
```

```bash
# Build and run Docker container
docker build -t brankas .
docker run -p 8200:8200 brankas
```

## Configuration

### Environment Variables

```bash
# Server Configuration
BRANKAS_HOST=0.0.0.0              # Bind address
BRANKAS_PORT=8200                 # HTTP port
BRANKAS_TLS_CERT_PATH=cert.pem    # TLS certificate
BRANKAS_TLS_KEY_PATH=key.pem      # TLS private key
BRANKAS_WORKERS=0                 # Worker threads (0 = auto)

# Security Configuration  
BRANKAS_JWT_SECRET=your-secret-key-256-bits-minimum
BRANKAS_JWT_EXPIRY=86400          # Token expiry (seconds)
BRANKAS_RATE_LIMIT_RPS=1000       # Requests per second limit
BRANKAS_RATE_LIMIT_BURST=2000     # Burst capacity

# Audit Configuration
BRANKAS_AUDIT_ENABLED=true        # Enable audit logging
BRANKAS_AUDIT_FILE=/var/log/brankas/audit.log
BRANKAS_AUDIT_SYSLOG=false        # Use syslog instead of file
BRANKAS_AUDIT_FORMAT=json         # json|text

# Storage Configuration (Future)
BRANKAS_STORAGE_TYPE=memory       # memory|file|postgres|vault
BRANKAS_STORAGE_PATH=/var/lib/brankas/keys
BRANKAS_STORAGE_ENCRYPT=true      # Encrypt keys at rest

# Monitoring Configuration
BRANKAS_METRICS_ENABLED=true      # Enable Prometheus metrics
BRANKAS_METRICS_PATH=/metrics     # Metrics endpoint path
BRANKAS_HEALTH_PATH=/health       # Health check endpoint
```

### Configuration File (config/production.toml)

```toml
[server]
host = "0.0.0.0"
port = 8200
workers = 0  # Auto-detect CPU cores
tls_cert_path = "/etc/brankas/tls/cert.pem"
tls_key_path = "/etc/brankas/tls/key.pem"

[security]
jwt_secret = "${BRANKAS_JWT_SECRET}"
jwt_expiry_seconds = 86400
rate_limit_requests_per_second = 1000
rate_limit_burst_capacity = 2000
cors_allow_origins = ["https://your-ui-domain.com"]

[audit]
enabled = true
log_file = "/var/log/brankas/audit.log"
use_syslog = false
format = "json"
log_level = "info"

[storage]
type = "memory"  # Development only
# For production:
# type = "postgres"
# connection_string = "postgresql://user:pass@localhost/brankas"
# encryption_key = "${BRANKAS_STORAGE_KEY}"

[monitoring]
metrics_enabled = true
metrics_path = "/metrics"
health_path = "/health"
status_path = "/v1/sys/status"
```

## API Endpoints

### Authentication

All endpoints require JWT authentication via `Authorization: Bearer <token>` header.

### Key Management

```bash
# Create key
POST /v1/transit/keys/{key_name}
{
  "key_type": "aes256-gcm",  # aes256-gcm, chacha20-poly1305, rsa-2048, rsa-4096, ed25519
  "exportable": false,       # Allow key export
  "usage": ["encrypt", "decrypt", "sign", "verify"]
}

# List keys
GET /v1/transit/keys

# Get key info
GET /v1/transit/keys/{key_name}

# Rotate key
POST /v1/transit/keys/{key_name}/rotate

# Delete key (if allowed)
DELETE /v1/transit/keys/{key_name}
```

### Encryption Operations

```bash
# Encrypt data
POST /v1/transit/encrypt/{key_name}
{
  "plaintext": "SGVsbG8gV29ybGQ=",  # Base64 encoded
  "encoding": "base64",             # base64|hex|utf8
  "associated_data": "context"      # Optional AAD for AEAD
}

# Decrypt data
POST /v1/transit/decrypt/{key_name}
{
  "ciphertext": "vault:v1:ABC123...",
  "encoding": "base64",
  "associated_data": "context"
}

# Batch encrypt
POST /v1/transit/encrypt
{
  "batch_input": [
    {"key_name": "key1", "plaintext": "data1"},
    {"key_name": "key2", "plaintext": "data2"}
  ]
}

# Batch decrypt
POST /v1/transit/decrypt
{
  "batch_input": [
    {"key_name": "key1", "ciphertext": "vault:v1:..."},
    {"key_name": "key2", "ciphertext": "vault:v1:..."}
  ]
}
```

### Signing Operations

```bash
# Sign data
POST /v1/transit/sign/{key_name}
{
  "input": "SGVsbG8gV29ybGQ=",  # Base64 encoded data to sign
  "signature_algorithm": "pss"  # pss, pkcs1v15 (RSA) or eddsa (Ed25519)
}

# Verify signature
POST /v1/transit/verify/{key_name}
{
  "input": "SGVsbG8gV29ybGQ=",
  "signature": "signature_data",
  "signature_algorithm": "pss"
}
```

### Utility Operations

```bash
# Generate random data
POST /v1/transit/random/{num_bytes}
{
  "encoding": "base64"  # base64|hex
}

# Hash data
POST /v1/transit/hash
{
  "input": "SGVsbG8gV29ybGQ=",
  "algorithm": "sha256",  # sha256, sha512, sha3-256, sha3-512
  "encoding": "base64"
}

# HMAC
POST /v1/transit/hmac/{key_name}
{
  "input": "SGVsbG8gV29ybGQ=",
  "algorithm": "sha256"
}
```

### System Operations

```bash
# Health check
GET /health
# Returns: {"status": "healthy", "timestamp": "...", "version": "..."}

# Version info
GET /version
# Returns: {"version": "1.0.0", "build_date": "...", "git_commit": "..."}

# Status (Vault-compatible)
GET /v1/sys/status
# Returns: {"type": "transit", "initialized": true, "sealed": false}

# Metrics (Prometheus format)
GET /metrics
# Returns: Prometheus-formatted metrics
```

## Production Deployment

### 1. TLS Configuration

Generate TLS certificates:

```bash
# Self-signed for testing
openssl req -x509 -newkey rsa:4096 -nodes \
  -keyout key.pem -out cert.pem -days 365 \
  -subj "/CN=brankas.local"

# Let's Encrypt for production
certbot certonly --nginx -d your-domain.com
```

### 2. Reverse Proxy (nginx)

```nginx
upstream brankas_backend {
    server 127.0.0.1:8200;
    server 127.0.0.1:8201;  # Multiple instances
    server 127.0.0.1:8202;
}

server {
    listen 443 ssl http2;
    server_name your-domain.com;
    
    ssl_certificate /etc/letsencrypt/live/your-domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your-domain.com/privkey.pem;
    
    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options DENY;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;
    limit_req zone=api burst=200 nodelay;
    
    location / {
        proxy_pass http://brankas_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
        
        # Buffering
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
```

### 3. Systemd Service

```ini
# /etc/systemd/system/brankas.service
[Unit]
Description=Brankas Transit Engine
After=network.target
Wants=network.target

[Service]
Type=simple
User=brankas
Group=brankas
WorkingDirectory=/opt/brankas
ExecStart=/opt/brankas/bin/api_server
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=brankas

# Security
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log/brankas /var/lib/brankas
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Environment
Environment=BRANKAS_CONFIG_PATH=/etc/brankas/production.toml
Environment=BRANKAS_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

```bash
# Install and start service
sudo systemctl enable brankas
sudo systemctl start brankas
sudo systemctl status brankas
```

### 4. High Availability Setup

For production environments requiring high availability:

```bash
# Multiple instances with different ports
BRANKAS_PORT=8200 ./api_server &
BRANKAS_PORT=8201 ./api_server &
BRANKAS_PORT=8202 ./api_server &
```

Use a load balancer (nginx, HAProxy, or cloud load balancer) to distribute traffic.

### 5. Monitoring and Alerting

#### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'brankas'
    static_configs:
      - targets: ['localhost:8200', 'localhost:8201', 'localhost:8202']
    metrics_path: '/metrics'
    scrape_interval: 15s
```

#### Grafana Dashboard

Key metrics to monitor:
- Request rate and latency
- Error rates
- Key usage statistics
- Memory and CPU utilization
- Authentication failures
- Rate limit hits

#### Alerting Rules

```yaml
# alerts.yml
groups:
  - name: brankas
    rules:
      - alert: BrankasDown
        expr: up{job="brankas"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Brankas instance is down"
          
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High error rate detected"
```

### 6. Log Management

```bash
# Logrotate configuration
# /etc/logrotate.d/brankas
/var/log/brankas/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 brankas brankas
    postrotate
        systemctl reload brankas
    endscript
}
```

## Security Considerations

### 1. Key Management
- Use Hardware Security Modules (HSMs) for production key storage
- Implement key rotation policies
- Secure key backup and recovery procedures
- Audit all key operations

### 2. Access Control
- Implement least-privilege access policies
- Use strong JWT secrets (256+ bits)
- Regular token rotation
- Multi-factor authentication for administrative access

### 3. Network Security
- Deploy behind TLS-terminating load balancer
- Use firewall rules to restrict access
- Implement network segmentation
- Regular security assessments

### 4. Audit and Compliance
- Enable comprehensive audit logging
- Regular log analysis and anomaly detection
- Compliance reporting (SOC 2, ISO 27001)
- Incident response procedures

## Performance Tuning

### 1. Server Configuration

```toml
# Optimize for high throughput
[server]
workers = 16  # Match CPU cores
max_connections = 10000
keep_alive = 300

[performance]
batch_size_limit = 1000  # Max batch operations
key_cache_size = 10000   # In-memory key cache
request_timeout = 30     # Request timeout (seconds)
```

### 2. Operating System

```bash
# Increase file descriptor limits
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# Optimize TCP settings
echo "net.core.somaxconn = 65536" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65536" >> /etc/sysctl.conf
sysctl -p
```

### 3. Resource Allocation

Recommended resources per instance:
- **CPU**: 4+ cores for production workloads
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: SSD for key storage and logs
- **Network**: 1Gbps minimum bandwidth

### 4. Benchmarking

Use included benchmarks to test performance:

```bash
# Run performance benchmarks
cargo bench

# Load testing with wrk
wrk -t12 -c400 -d30s http://localhost:8200/health
```

## Troubleshooting

### Common Issues

#### 1. TLS Certificate Problems
```bash
# Check certificate validity
openssl x509 -in cert.pem -text -noout

# Test TLS connection
openssl s_client -connect your-domain.com:443
```

#### 2. JWT Authentication Failures
```bash
# Verify JWT token
echo "TOKEN" | base64 -d | jq .

# Check server logs for authentication errors
journalctl -u brankas -f | grep auth
```

#### 3. High Memory Usage
```bash
# Monitor memory usage
systemctl status brankas
ps aux | grep api_server

# Adjust key cache size
export BRANKAS_KEY_CACHE_SIZE=5000
```

#### 4. Performance Issues
```bash
# Check system resources
htop
iotop

# Analyze request patterns
tail -f /var/log/brankas/audit.log | jq .

# Monitor network connections
netstat -ant | grep :8200
```

### Debug Mode

```bash
# Enable debug logging
export BRANKAS_LOG_LEVEL=debug
export RUST_LOG=brankas=debug

# Run with detailed tracing
cargo run --bin api_server
```

## Migration from HashiCorp Vault

Brankas provides Vault-compatible APIs for seamless migration:

1. **API Compatibility**: Drop-in replacement for transit engine endpoints
2. **Data Format**: Compatible ciphertext format (`vault:v1:...`)  
3. **Client Libraries**: Use existing Vault client libraries
4. **Configuration**: Similar configuration patterns

### Migration Steps

1. Deploy Brankas alongside existing Vault
2. Update client applications to use Brankas endpoints
3. Migrate keys using export/import functionality
4. Validate all operations work correctly
5. Decommission old Vault transit engine

## Support and Community

- **Documentation**: https://brankas.dev/docs
- **GitHub**: https://github.com/your-org/brankas
- **Issues**: https://github.com/your-org/brankas/issues
- **Discussions**: https://github.com/your-org/brankas/discussions
- **Security**: security@brankas.dev

## License

Brankas is licensed under the MIT License. See LICENSE file for details.

---

For additional support, please consult the documentation or reach out via GitHub issues.
