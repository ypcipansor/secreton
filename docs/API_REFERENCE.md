# Secreton Enterprise Vault - Complete API Reference

**Version:** 2.1.1
**Last Updated:** August 28, 2025
**Status:** ✅ Production Ready

## 📋 Overview

The Secreton Enterprise Vault API provides RESTful endpoints for secure secret management, encryption services, and administrative operations. All API calls require authentication and are protected by quantum-safe TLS encryption.

## 🔐 Authentication

### Authentication Methods

#### 1. Token Authentication
```bash
# Set authentication token
export SECRETON_TOKEN="hvs.your-token-here"

# Or pass in header
curl -H "X-Vault-Token: hvs.your-token-here" \
  https://vault.example.com/v1/secret/my-secret
```

#### 2. TLS Certificate Authentication
```bash
# Use client certificate
curl --cert client.crt --key client.key \
  https://vault.example.com/v1/secret/my-secret
```

#### 3. Multi-Factor Authentication
```bash
# MFA with TOTP
curl -H "X-Vault-Token: hvs.token" \
  -H "X-Vault-MFA: TOTP:123456" \
  https://vault.example.com/v1/secret/my-secret
```

## 🔑 Transit Engine API

### Encrypt Data

**Endpoint:** `POST /v1/transit/encrypt/{key_name}`

**Request:**
```json
{
  "plaintext": "SGVsbG8gV29ybGQ=",  // Base64 encoded
  "context": "dXNlci1jb250ZXh0", // Optional: Base64 encoded context
  "key_version": 1,              // Optional: Specific key version
  "convergent_encryption": true  // Optional: Deterministic encryption
}
```

**Response:**
```json
{
  "data": {
    "ciphertext": "vault:v1:encrypted-data-here",
    "key_version": 1
  }
}
```

**Example:**
```bash
curl -X POST \
  -H "X-Vault-Token: hvs.token" \
  -d '{"plaintext": "SGVsbG8gV29ybGQ="}' \
  https://vault.example.com/v1/transit/encrypt/my-key
```

### Decrypt Data

**Endpoint:** `POST /v1/transit/decrypt/{key_name}`

**Request:**
```json
{
  "ciphertext": "vault:v1:encrypted-data-here",
  "context": "dXNlci1jb250ZXh0", // Must match encryption context
  "nonce": "bm9uY2UtdmFsdWU="     // Required for AEAD modes
}
```

**Response:**
```json
{
  "data": {
    "plaintext": "SGVsbG8gV29ybGQ=",
    "key_version": 1
  }
}
```

### Generate Data Key

**Endpoint:** `POST /v1/transit/datakey/plaintext/{key_name}`

**Request:**
```json
{
  "bits": 256,                    // Key size: 128, 256, 512
  "context": "YXBwLWNvbnRleHQ=", // Optional context
  "nonce": "bm9uY2UtdmFsdWU="     // Optional nonce
}
```

**Response:**
```json
{
  "data": {
    "ciphertext": "vault:v1:wrapped-key",
    "plaintext": "cGxhaW4tdGV4dC1rZXk="  // Base64 encoded plaintext key
  }
}
```

### Key Management

#### Create Key
**Endpoint:** `POST /v1/transit/keys/{key_name}`

**Request:**
```json
{
  "type": "aes256-gcm",           // Key type
  "derived": true,                // Enable key derivation
  "exportable": false,            // Allow key export
  "allow_plaintext_backup": false, // Allow plaintext backup
  "auto_rotate_period": 2592000    // Auto rotation in seconds (30 days)
}
```

#### Read Key
**Endpoint:** `GET /v1/transit/keys/{key_name}`

**Response:**
```json
{
  "data": {
    "name": "my-key",
    "type": "aes256-gcm",
    "deletion_allowed": true,
    "derived": true,
    "exportable": false,
    "allow_plaintext_backup": false,
    "keys": {
      "1": {
        "creation_time": "2025-08-28T10:00:00Z",
        "public_key": "public-key-if-asymmetric"
      }
    },
    "min_decryption_version": 1,
    "min_encryption_version": 1,
    "latest_version": 1,
    "auto_rotate_period": 2592000
  }
}
```

#### Rotate Key
**Endpoint:** `POST /v1/transit/keys/{key_name}/rotate`

**Request:**
```json
{
  "migration": false  // Set true for migration scenarios
}
```

#### Delete Key
**Endpoint:** `DELETE /v1/transit/keys/{key_name}`

## 🗄️ KV Secrets Engine API

### Write Secret

**Endpoint:** `POST /v1/secret/data/{path}`

**Request:**
```json
{
  "data": {
    "username": "admin",
    "password": "secure-password",
    "api_key": "sk-1234567890abcdef",
    "database_url": "postgresql://user:pass@host:5432/db"
  },
  "options": {
    "cas": 1,        // Check-and-set version
    "max_versions": 10
  }
}
```

**Response:**
```json
{
  "data": {
    "created_time": "2025-08-28T10:30:00Z",
    "deletion_time": "",
    "destroyed": false,
    "version": 2
  }
}
```

### Read Secret

**Endpoint:** `GET /v1/secret/data/{path}`

**Response:**
```json
{
  "data": {
    "data": {
      "username": "admin",
      "password": "secure-password",
      "api_key": "sk-1234567890abcdef",
      "database_url": "postgresql://user:pass@host:5432/db"
    },
    "metadata": {
      "created_time": "2025-08-28T10:30:00Z",
      "deletion_time": "",
      "destroyed": false,
      "version": 2,
      "max_versions": 10
    }
  }
}
```

### List Secrets

**Endpoint:** `LIST /v1/secret/metadata/{path}`

**Response:**
```json
{
  "data": {
    "keys": [
      "database/",
      "api-keys/",
      "certificates/"
    ]
  }
}
```

### Delete Secret

**Endpoint:** `DELETE /v1/secret/data/{path}`

**Soft Delete (Versioned):**
```bash
curl -X DELETE \
  -H "X-Vault-Token: hvs.token" \
  https://vault.example.com/v1/secret/data/my-secret
```

**Permanent Delete:**
```bash
curl -X DELETE \
  -H "X-Vault-Token: hvs.token" \
  https://vault.example.com/v1/secret/metadata/my-secret
```

## 🔐 Authentication Methods API

### TOTP Setup

**Endpoint:** `POST /v1/auth/totp/create`

**Request:**
```json
{
  "account_name": "admin@example.com",
  "issuer": "Secreton Vault",
  "generate": true,
  "exported": false,
  "period": 30,
  "algorithm": "SHA256",
  "digits": 6,
  "skew": 1,
  "qr_size": 200
}
```

**Response:**
```json
{
  "data": {
    "url": "otpauth://totp/Secreton%20Vault:admin%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Secreton%20Vault",
    "qr_code": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMgAAAD...",
    "secret": "JBSWY3DPEHPK3PXP",
    "algorithm": "SHA256",
    "digits": 6,
    "period": 30
  }
}
```

### TOTP Validation

**Endpoint:** `POST /v1/auth/totp/validate`

**Request:**
```json
{
  "code": "123456"
}
```

**Response:**
```json
{
  "data": {
    "valid": true,
    "drift": 0
  }
}
```

### WebAuthn Registration

**Endpoint:** `POST /v1/auth/webauthn/register`

**Request:**
```json
{
  "name": "admin-key",
  "user_id": "admin-user-id",
  "display_name": "Administrator Key",
  "attestation": "direct"
}
```

**Response:**
```json
{
  "data": {
    "creation_options": {
      "challenge": "random-challenge-bytes",
      "rp": {
        "name": "Secreton Vault",
        "id": "vault.example.com"
      },
      "user": {
        "id": "admin-user-id",
        "name": "admin@example.com",
        "displayName": "Administrator"
      },
      "pubKeyCredParams": [
        {
          "type": "public-key",
          "alg": -7
        }
      ],
      "authenticatorSelection": {
        "authenticatorAttachment": "cross-platform",
        "requireResidentKey": false,
        "userVerification": "preferred"
      }
    }
  }
}
```

## 📊 System Management API

### Health Check

**Endpoint:** `GET /v1/sys/health`

**Response:**
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "performance_standby": false,
  "replication_performance_mode": "disabled",
  "replication_dr_mode": "disabled",
  "server_time_utc": 1693219200,
  "version": "2.1.1",
  "cluster_name": "vault-cluster-01",
  "cluster_id": "cluster-id-here"
}
```

### Seal Status

**Endpoint:** `GET /v1/sys/seal-status`

**Response:**
```json
{
  "type": "shamir",
  "initialized": true,
  "sealed": false,
  "t": 3,
  "n": 5,
  "progress": 0,
  "nonce": "",
  "version": "2.1.1",
  "build_date": "2025-08-28T00:00:00Z",
  "migration": false,
  "cluster_name": "vault-cluster-01",
  "cluster_id": "cluster-id-here",
  "recovery_seal": false,
  "storage_type": "raft"
}
```

### Server Configuration

**Endpoint:** `GET /v1/sys/config`

**Response:**
```json
{
  "data": {
    "api_addr": "https://vault.example.com:8200",
    "cache_size": 16777216,
    "cluster_addr": "https://vault.example.com:8201",
    "cluster_cipher_suites": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,...",
    "cluster_name": "vault-cluster-01",
    "default_lease_ttl": 2764800,
    "default_max_request_duration": 90000000000,
    "detect_deadlocks": "aliveness",
    "disable_clustering": false,
    "disable_indexing": false,
    "disable_keep_alives": false,
    "disable_mlock": false,
    "disable_performance_standby": false,
    "disable_printable_check": false,
    "disable_sealwrap": false,
    "disable_sentinel": true,
    "enable_ui": true,
    "experiments": null,
    "log_format": "standard",
    "log_level": "info",
    "max_lease_ttl": 2764800,
    "pid_file": "",
    "plugin_directory": "",
    "raw_storage_endpoint": true,
    "ui_headers": null
  }
}
```

### Audit Logs

**Endpoint:** `GET /v1/sys/audit`

**Response:**
```json
{
  "data": {
    "audit-01/": {
      "type": "file",
      "description": "Primary audit log",
      "options": {
        "file_path": "/var/log/vault/audit.log",
        "format": "json",
        "hmac_accessor": true,
        "log_raw": false,
        "mode": "0600",
        "prefix": ""
      },
      "local": false,
      "seal_wrap": false
    }
  }
}
```

## 🔍 Monitoring and Metrics API

### Prometheus Metrics

**Endpoint:** `GET /v1/sys/metrics`

**Response:**
```json
{
  "data": {
    "Counters": {
      "vault.audit.log_request": {
        "Count": 150,
        "Rate": 0.5,
        "Sum": 150,
        "SumSquares": 150
      },
      "vault.core.handle_request": {
        "Count": 1000,
        "Rate": 3.33,
        "Sum": 1000,
        "SumSquares": 1000
      }
    },
    "Gauges": {
      "vault.core.leader": {
        "Value": 1
      },
      "vault.core.unsealed": {
        "Value": 1
      }
    },
    "Samples": {
      "vault.core.handle_request": [
        {
          "Count": 1000,
          "Rate": 3.33,
          "Sum": 1000,
          "SumSquares": 1000
        }
      ]
    }
  }
}
```

### Request Rate Limiting

**Endpoint:** `GET /v1/sys/rate-limit`

**Response:**
```json
{
  "data": {
    "enabled": true,
    "rate_limit": 1000,
    "burst_limit": 2000,
    "lease_count": 150,
    "lease_max": 1000
  }
}
```

## 🚨 Alerting API

### Create Alert Rule

**Endpoint:** `POST /v1/sys/alerts/rules`

**Request:**
```json
{
  "name": "high-cpu-alert",
  "type": "threshold",
  "metric": "cpu_usage_percent",
  "operator": "gt",
  "threshold": 80,
  "duration": "5m",
  "channels": ["email", "webhook"],
  "severity": "warning",
  "description": "CPU usage above 80% for 5 minutes"
}
```

### List Alert Rules

**Endpoint:** `GET /v1/sys/alerts/rules`

**Response:**
```json
{
  "data": {
    "rules": [
      {
        "id": "rule-001",
        "name": "high-cpu-alert",
        "type": "threshold",
        "enabled": true,
        "created_at": "2025-08-28T10:00:00Z"
      }
    ]
  }
}
```

### Get Alert History

**Endpoint:** `GET /v1/sys/alerts/history`

**Query Parameters:**
- `start_time`: ISO 8601 timestamp
- `end_time`: ISO 8601 timestamp
- `severity`: Filter by severity
- `limit`: Maximum number of results

**Response:**
```json
{
  "data": {
    "alerts": [
      {
        "id": "alert-001",
        "rule_id": "rule-001",
        "severity": "warning",
        "message": "CPU usage above 80%",
        "timestamp": "2025-08-28T10:30:00Z",
        "resolved": true,
        "resolved_at": "2025-08-28T10:35:00Z"
      }
    ]
  }
}
```

## 🔧 Administration API

### User Management

#### Create User
**Endpoint:** `POST /v1/auth/userpass/users/{username}`

**Request:**
```json
{
  "password": "secure-password",
  "policies": ["default", "admin"],
  "ttl": "24h",
  "max_ttl": "168h"
}
```

#### List Users
**Endpoint:** `GET /v1/auth/userpass/users`

**Response:**
```json
{
  "data": {
    "keys": ["admin", "developer", "auditor"]
  }
}
```

### Policy Management

#### Create Policy
**Endpoint:** `POST /v1/sys/policies/acl/{name}`

**Request:**
```json
{
  "policy": "path \"secret/*\" {\n  capabilities = [\"create\", \"read\", \"update\", \"delete\", \"list\"]\n}\n\npath \"transit/*\" {\n  capabilities = [\"create\", \"read\", \"update\"]\n}"
}
```

#### List Policies
**Endpoint:** `GET /v1/sys/policies/acl`

**Response:**
```json
{
  "data": {
    "policies": ["default", "admin", "developer", "auditor"]
  }
}
```

### Backup and Restore

#### Create Backup
**Endpoint:** `POST /v1/sys/storage/backup`

**Request:**
```json
{
  "force": false,
  "snapshot": {
    "name": "backup-2025-08-28",
    "retain": 30
  }
}
```

#### List Backups
**Endpoint:** `GET /v1/sys/storage/backup`

**Response:**
```json
{
  "data": {
    "backups": [
      {
        "name": "backup-2025-08-28",
        "created_at": "2025-08-28T10:00:00Z",
        "size": 1073741824,
        "status": "completed"
      }
    ]
  }
}
```

## 📋 Error Codes and Responses

### Common HTTP Status Codes

| Status Code | Description | Example |
|-------------|-------------|---------|
| `200` | Success | Operation completed successfully |
| `201` | Created | Resource created successfully |
| `204` | No Content | Operation completed, no content returned |
| `400` | Bad Request | Invalid request parameters |
| `401` | Unauthorized | Authentication required |
| `403` | Forbidden | Insufficient permissions |
| `404` | Not Found | Resource not found |
| `409` | Conflict | Resource already exists |
| `429` | Too Many Requests | Rate limit exceeded |
| `500` | Internal Server Error | Server error occurred |
| `503` | Service Unavailable | Service temporarily unavailable |

### Error Response Format

```json
{
  "errors": [
    "permission denied",
    "invalid path"
  ]
}
```

### Detailed Error Response

```json
{
  "error": {
    "code": "permission_denied",
    "message": "permission denied",
    "details": {
      "path": "/v1/secret/my-secret",
      "operation": "read",
      "user": "developer",
      "policies": ["default"]
    },
    "timestamp": "2025-08-28T10:30:00Z",
    "request_id": "req-12345678-90ab-cdef-1234-567890abcdef"
  }
}
```

## 🔄 Rate Limiting

### Rate Limit Headers

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1693219200
X-RateLimit-Retry-After: 60
```

### Rate Limit Response

```json
{
  "error": {
    "code": "rate_limit_exceeded",
    "message": "rate limit exceeded",
    "details": {
      "limit": 1000,
      "remaining": 0,
      "reset": 1693219200,
      "retry_after": 60
    }
  }
}
```

## 📊 API Versioning

### Version Headers

```http
Accept: application/vnd.vault.v1+json
X-Vault-API-Version: v1
```

### Version Compatibility

- **v1**: Current stable API version
- **Legacy Support**: Automatic compatibility layer for older clients
- **Deprecation Notice**: 6 months notice for breaking changes

## 🔒 Security Considerations

### API Security Best Practices

1. **Always use HTTPS**: All API calls must use TLS 1.3
2. **Token Security**: Never expose tokens in logs or client-side code
3. **Rate Limiting**: Implement appropriate rate limiting
4. **Input Validation**: Validate all input parameters
5. **Audit Logging**: Enable comprehensive audit logging
6. **Access Control**: Use principle of least privilege

### Security Headers

```http
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## 📚 Additional Resources

### SDKs and Libraries

- **Go SDK**: `github.com/hashicorp/vault/api` (compatible)
- **Python SDK**: `hvac` library (compatible)
- **Java SDK**: `spring-cloud-vault` (compatible)
- **JavaScript SDK**: Custom implementation available

### API Tools

- **Postman Collection**: Available in `/docs/api/postman_collection.json`
- **OpenAPI Specification**: Available in `/docs/api/openapi.yaml`
- **API Testing Scripts**: Available in `/scripts/api_test.sh`

### Documentation Links

- [Authentication Guide](../docs/AUTHENTICATION_GUIDE.md)
- [Configuration Guide](../docs/CONFIGURATION_GUIDE.md)
- [Security Hardening](../docs/SECURITY_HARDENING.md)
- [Troubleshooting Guide](../docs/TROUBLESHOOTING.md)

---

**This API reference provides comprehensive documentation for all Secreton Enterprise Vault endpoints. For the latest updates, please refer to the official documentation repository.**
