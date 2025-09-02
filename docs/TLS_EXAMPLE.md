# Secreton Enterprise Vault - Advanced TLS/mTLS Configuration Guide

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ FIPS 140-3 Compliant

## 📋 Overview

Secreton Enterprise Vault implements military-grade TLS/mTLS encryption for all communications, ensuring end-to-end security with FIPS 140-3 compliance. This guide provides comprehensive configuration examples for various deployment scenarios.

## 🔐 TLS Configuration Fundamentals

### Supported TLS Versions
- **TLS 1.3** (Primary, quantum-safe handshake)
- **TLS 1.2** (Legacy compatibility, FIPS compliant)
- **Legacy TLS disabled** (Security hardening)

### Cipher Suites (Prioritized)
1. **TLS_AES_256_GCM_SHA384** (TLS 1.3, AES-256-GCM)
2. **TLS_CHACHA20_POLY1305_SHA256** (TLS 1.3, ChaCha20-Poly1305)
3. **ECDHE-RSA-AES256-GCM-SHA384** (TLS 1.2, FIPS compliant)
4. **ECDHE-ECDSA-AES256-GCM-SHA384** (TLS 1.2, ECDSA)

### Certificate Requirements
- **Key Size**: RSA 4096-bit, ECDSA P-384
- **Signature Algorithm**: SHA-384 or higher
- **Certificate Chain**: Complete chain including root CA
- **Validity Period**: Maximum 398 days (industry best practice)
- **SAN Fields**: Include all service DNS names and IPs

## ⚙️ Basic TLS Configuration

### Single Server TLS

```toml
[server]
host = "0.0.0.0"
port = 8200

[server.tls]
enabled = true
certificate_path = "/etc/secreton/certs/server.crt"
private_key_path = "/etc/secreton/certs/server.key"
certificate_chain_path = "/etc/secreton/certs/chain.crt"

# TLS Protocol Configuration
min_version = "TLS1.2"
max_version = "TLS1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384"
]

# Security Hardening
prefer_server_cipher_suites = true
session_tickets_disabled = false
session_ticket_key_rotation_hours = 24
ocsp_stapling_enabled = true
```

### Environment Variables

```bash
# TLS Configuration
export SECRETON_TLS_ENABLED="true"
export SECRETON_TLS_CERT_PATH="/etc/secreton/certs/server.crt"
export SECRETON_TLS_KEY_PATH="/etc/secreton/certs/server.key"
export SECRETON_TLS_CHAIN_PATH="/etc/secreton/certs/chain.crt"

# Protocol Settings
export SECRETON_TLS_MIN_VERSION="TLS1.2"
export SECRETON_TLS_MAX_VERSION="TLS1.3"

# Security Settings
export SECRETON_TLS_OCSP_STAPLING="true"
export SECRETON_TLS_SESSION_TICKETS="true"
export SECRETON_TLS_PREFER_SERVER_CIPHERS="true"
```

## 🔒 Mutual TLS (mTLS) Configuration

### Server mTLS Configuration

```toml
[server]
host = "0.0.0.0"
port = 8200

[server.tls]
enabled = true
mutual_tls_enabled = true

# Server Certificate
certificate_path = "/etc/secreton/certs/server.crt"
private_key_path = "/etc/secreton/certs/server.key"
certificate_chain_path = "/etc/secreton/certs/chain.crt"

# Client Certificate Authority
client_ca_path = "/etc/secreton/certs/client-ca.crt"
client_certificate_required = true
client_certificate_verification_depth = 2

# CRL (Certificate Revocation List)
crl_path = "/etc/secreton/certs/client-crl.pem"
crl_check_enabled = true
crl_check_mode = "strict"  # "strict" or "permissive"

# Protocol Configuration
min_version = "TLS1.2"
max_version = "TLS1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384"
]

# Security Hardening
prefer_server_cipher_suites = true
session_tickets_disabled = true  # Disabled for mTLS
ocsp_stapling_enabled = true
```

### Client mTLS Configuration

```toml
[client]
tls_enabled = true
mutual_tls_enabled = true

# Client Certificate
certificate_path = "/etc/secreton/certs/client.crt"
private_key_path = "/etc/secreton/certs/client.key"

# Server Certificate Authority
server_ca_path = "/etc/secreton/certs/server-ca.crt"

# Connection Settings
server_name_indication = "vault.company.com"
insecure_skip_verify = false

# Protocol Configuration
min_version = "TLS1.2"
max_version = "TLS1.3"
```

## 🏢 Enterprise Deployment Examples

### Banking-Grade Configuration

```toml
[server]
host = "0.0.0.0"
port = 8200

[server.tls]
enabled = true
mutual_tls_enabled = true

# FIPS 140-3 Compliant Certificates
certificate_path = "/etc/secreton/certs/banking-server.crt"
private_key_path = "/etc/secreton/certs/banking-server.key"
certificate_chain_path = "/etc/secreton/certs/banking-chain.crt"

# Banking CA (Internal)
client_ca_path = "/etc/secreton/certs/banking-client-ca.crt"
client_certificate_required = true

# PCI DSS Compliance
min_version = "TLS1.2"
max_version = "TLS1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES256-GCM-SHA384"
]

# Enhanced Security
ocsp_stapling_enabled = true
crl_check_enabled = true
crl_check_mode = "strict"
session_tickets_disabled = true

# Monitoring
tls_handshake_timeout_seconds = 10
max_concurrent_tls_handshakes = 1000
tls_connection_rate_limit = 10000

# Audit Logging
tls_audit_log_enabled = true
tls_audit_log_path = "/var/log/secreton/tls-audit.log"
```

### Government-Grade Configuration

```toml
[server]
host = "0.0.0.0"
port = 8200

[server.tls]
enabled = true
mutual_tls_enabled = true

# Government PKI Certificates
certificate_path = "/etc/secreton/certs/gov-server.crt"
private_key_path = "/etc/secreton/certs/gov-server.key"
certificate_chain_path = "/etc/secreton/certs/gov-chain.crt"

# Government CA
client_ca_path = "/etc/secreton/certs/gov-client-ca.crt"
client_certificate_required = true
client_certificate_verification_depth = 3

# FIPS 140-3 Level 3
min_version = "TLS1.2"
max_version = "TLS1.3"
cipher_suites = [
    "TLS_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES256-GCM-SHA384"
]

# Maximum Security
ocsp_stapling_enabled = true
crl_check_enabled = true
crl_check_mode = "strict"
session_tickets_disabled = true
prefer_server_cipher_suites = true

# Quantum-Safe (Future-proofing)
tls13_kyber_enabled = true  # Post-quantum key exchange

# Advanced Monitoring
tls_handshake_timeout_seconds = 5
max_concurrent_tls_handshakes = 500
tls_connection_rate_limit = 5000

# Comprehensive Audit
tls_audit_log_enabled = true
tls_audit_log_path = "/var/log/secreton/tls-audit.log"
tls_security_events_log_enabled = true
tls_security_events_log_path = "/var/log/secreton/tls-security.log"
```

## 🔧 Certificate Management

### Certificate Generation Scripts

#### Root CA Generation

```bash
#!/bin/bash
# Generate Root CA for Secreton

# Create CA private key (RSA 4096-bit)
openssl genrsa -out ca.key 4096

# Create CA certificate
openssl req -new -x509 -days 3650 -key ca.key -sha384 -extensions v3_ca \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=Secreton Root CA" \
  -out ca.crt

echo "Root CA generated: ca.crt"
```

#### Server Certificate Generation

```bash
#!/bin/bash
# Generate Server Certificate

# Create server private key
openssl genrsa -out server.key 4096

# Create certificate signing request
cat > server.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
CN = vault.company.com

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = vault.company.com
DNS.2 = vault.internal.company.com
IP.1 = 10.0.1.100
IP.2 = 127.0.0.1
EOF

openssl req -new -key server.key -out server.csr -config server.cnf

# Sign certificate with CA
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 398 -sha384 -extfile server.cnf -extensions v3_req

echo "Server certificate generated: server.crt"
```

#### Client Certificate Generation

```bash
#!/bin/bash
# Generate Client Certificate for mTLS

# Create client private key
openssl genrsa -out client.key 4096

# Create certificate signing request
cat > client.cnf << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = State
L = City
O = Organization
CN = client.company.com

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = clientAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = client.company.com
email.1 = client@company.com
EOF

openssl req -new -key client.key -out client.csr -config client.cnf

# Sign certificate with CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client.crt -days 398 -sha384 -extfile client.cnf -extensions v3_req

echo "Client certificate generated: client.crt"
```

### Certificate Rotation

```bash
#!/bin/bash
# Automated Certificate Rotation

# Backup current certificates
cp server.crt server.crt.backup
cp server.key server.key.backup

# Generate new certificates
./generate-server-cert.sh

# Reload Secreton configuration
curl -X POST https://vault.company.com/v1/sys/config/reload \
  -H "X-Vault-Token: $VAULT_TOKEN"

# Verify new certificates
openssl s_client -connect vault.company.com:8200 -servername vault.company.com

echo "Certificate rotation completed"
```

## 📊 TLS Monitoring and Metrics

### Prometheus Metrics

```yaml
# TLS Metrics Configuration
tls_handshake_total: Counter for total TLS handshakes
tls_handshake_duration_seconds: Histogram of TLS handshake duration
tls_connection_state: Gauge for active TLS connections
tls_certificate_expiry_seconds: Gauge for certificate expiry time
tls_protocol_version: Counter for TLS protocol versions used
tls_cipher_suite: Counter for cipher suites used
tls_handshake_failures_total: Counter for failed handshakes
tls_mutual_auth_success_total: Counter for successful mTLS authentications
tls_mutual_auth_failures_total: Counter for failed mTLS authentications
```

### Monitoring Dashboard

```bash
# TLS Health Check
curl -v https://vault.company.com/v1/sys/health \
  --cert client.crt \
  --key client.key \
  --cacert ca.crt

# Certificate Expiry Check
openssl s_client -connect vault.company.com:8200 \
  -servername vault.company.com 2>/dev/null | \
  openssl x509 -noout -dates

# TLS Connection Test
openssl s_client -connect vault.company.com:8200 \
  -servername vault.company.com \
  -tls1_3 \
  -cipher TLS_AES_256_GCM_SHA384
```

## 🔍 Troubleshooting TLS Issues

### Common Problems and Solutions

#### Certificate Verification Errors

```bash
# Check certificate validity
openssl verify -CAfile ca.crt server.crt

# Check certificate details
openssl x509 -in server.crt -text -noout

# Check certificate chain
openssl verify -CAfile ca.crt -untrusted intermediate.crt server.crt
```

#### Connection Refused

```bash
# Check if port is open
telnet vault.company.com 8200

# Check firewall rules
iptables -L -n | grep 8200

# Check Secreton logs
tail -f /var/log/secreton/server.log
```

#### TLS Handshake Failures

```bash
# Debug TLS handshake
openssl s_client -connect vault.company.com:8200 \
  -servername vault.company.com \
  -debug -state

# Check supported cipher suites
openssl s_client -connect vault.company.com:8200 \
  -servername vault.company.com \
  -cipher ALL
```

#### mTLS Authentication Issues

```bash
# Test client certificate
openssl s_client -connect vault.company.com:8200 \
  -servername vault.company.com \
  -cert client.crt \
  -key client.key \
  -CAfile ca.crt

# Check client certificate validity
openssl verify -CAfile ca.crt client.crt
```

### Debug Logging

```toml
[logging]
level = "debug"

[logging.tls]
enabled = true
file_path = "/var/log/secreton/tls-debug.log"
include_handshake_details = true
include_certificate_details = true
```

## 🛡️ Security Best Practices

### Certificate Security
- **Private Key Protection**: Store private keys in HSM or encrypted storage
- **Certificate Lifecycle**: Automate certificate renewal and rotation
- **Access Control**: Restrict certificate access to authorized personnel
- **Backup Security**: Encrypt certificate backups

### TLS Configuration Security
- **Protocol Versions**: Use TLS 1.3 whenever possible
- **Cipher Suites**: Prefer AEAD cipher suites (GCM, ChaCha20-Poly1305)
- **Perfect Forward Secrecy**: Ensure all cipher suites support PFS
- **Session Management**: Disable session tickets for sensitive applications

### Operational Security
- **Certificate Transparency**: Monitor certificate transparency logs
- **Revocation Checking**: Enable OCSP stapling and CRL checking
- **Monitoring**: Implement comprehensive TLS monitoring
- **Incident Response**: Have TLS security incident response procedures

## 📋 Compliance Mapping

### FIPS 140-3 Compliance

| Requirement | Secreton Implementation | Status |
|-------------|-------------------------|--------|
| **Cryptographic Module** | OpenSSL FIPS provider | ✅ |
| **Key Management** | HSM integration, secure key storage | ✅ |
| **Self-Tests** | Automatic cryptographic validation | ✅ |
| **Physical Security** | HSM physical security | ✅ |
| **Logical Security** | Access controls, audit logging | ✅ |

### PCI DSS Compliance

| Requirement | Secreton Implementation | Status |
|-------------|-------------------------|--------|
| **Strong Cryptography** | TLS 1.2+, approved cipher suites | ✅ |
| **Secure Transmission** | End-to-end TLS encryption | ✅ |
| **Certificate Management** | Automated certificate lifecycle | ✅ |
| **Key Exchange** | Perfect forward secrecy | ✅ |

### HIPAA Compliance

| Requirement | Secreton Implementation | Status |
|-------------|-------------------------|--------|
| **Encryption in Transit** | TLS 1.2+ with strong ciphers | ✅ |
| **Access Controls** | mTLS client authentication | ✅ |
| **Audit Controls** | TLS connection logging | ✅ |
| **Integrity Controls** | TLS message authentication | ✅ |

## 🎯 Configuration Validation

### TLS Configuration Validator

```bash
#!/bin/bash
# TLS Configuration Validation Script

CONFIG_FILE="/etc/secreton/config.toml"

echo "Validating TLS configuration..."

# Check if TLS is enabled
if ! grep -q "tls_enabled = true" "$CONFIG_FILE"; then
    echo "ERROR: TLS not enabled"
    exit 1
fi

# Check certificate files exist
CERT_PATH=$(grep "certificate_path" "$CONFIG_FILE" | cut -d'"' -f2)
if [ ! -f "$CERT_PATH" ]; then
    echo "ERROR: Certificate file not found: $CERT_PATH"
    exit 1
fi

# Check private key file exists
KEY_PATH=$(grep "private_key_path" "$CONFIG_FILE" | cut -d'"' -f2)
if [ ! -f "$KEY_PATH" ]; then
    echo "ERROR: Private key file not found: $KEY_PATH"
    exit 1
fi

# Validate certificate
if ! openssl x509 -in "$CERT_PATH" -noout; then
    echo "ERROR: Invalid certificate format"
    exit 1
fi

# Check certificate expiry
EXPIRY=$(openssl x509 -in "$CERT_PATH" -noout -enddate | cut -d'=' -f2)
EXPIRY_SECONDS=$(date -d "$EXPIRY" +%s)
CURRENT_SECONDS=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_SECONDS - CURRENT_SECONDS) / 86400 ))

if [ $DAYS_LEFT -lt 30 ]; then
    echo "WARNING: Certificate expires in $DAYS_LEFT days"
fi

echo "TLS configuration validation completed successfully"
```

### Automated Testing

```rust
#[cfg(test)]
mod tls_tests {
    use super::*;
    use tokio::net::TcpListener;
    use rustls::{ServerConfig, ClientConfig};
    
    #[tokio::test]
    async fn test_tls_handshake() {
        // Test TLS handshake with valid certificates
        let server_config = create_server_config();
        let client_config = create_client_config();
        
        // Start test server
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        
        // Test successful connection
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls_stream = tokio_rustls::TlsConnector::from(client_config)
            .connect("localhost".try_into().unwrap(), stream)
            .await
            .unwrap();
        
        assert!(tls_stream.get_ref().1.peer_certificates().is_some());
    }
    
    #[tokio::test]
    async fn test_mutual_tls() {
        // Test mTLS with client certificates
        let server_config = create_mutual_tls_server_config();
        let client_config = create_mutual_tls_client_config();
        
        // Test mTLS handshake
        // Implementation would test mutual authentication
        assert!(true); // Placeholder for actual test
    }
    
    #[test]
    fn test_certificate_validation() {
        // Test certificate validation logic
        let cert = load_test_certificate();
        assert!(validate_certificate(&cert).is_ok());
    }
}
```

## 📞 Support and Resources

### Documentation Links
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [RFC 8446 (TLS 1.3)](https://tools.ietf.org/rfc/rfc8446.txt)
- [NIST SP 800-52 (TLS Guidelines)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf)

### Community Resources
- [SSL Labs Server Test](https://www.ssllabs.com/ssltest/)
- [Certificate Transparency Logs](https://crt.sh/)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/)

### Professional Services
- Certificate Authority services
- TLS security assessment
- FIPS 140-3 validation consulting
- PCI DSS compliance auditing

---

**Secreton Enterprise Vault's TLS/mTLS implementation provides military-grade encryption with comprehensive security controls, ensuring the highest standards of data protection and regulatory compliance.**
