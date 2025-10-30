# Secreton API Reference

This document provides comprehensive API reference for Secreton.

## Authentication

All API requests require authentication via Bearer token in the `X-Vault-Token` header.

```bash
curl -H "X-Vault-Token: $VAULT_TOKEN" \
     https://vault.example.com/v1/secret/data/mysecret
```

## Endpoints

### System

#### Health Check
```http
GET /v1/sys/health
```

Response:
```json
{
  "initialized": true,
  "sealed": false,
  "standby": false,
  "version": "1.0.0"
}
```

#### Seal Status
```http
GET /v1/sys/seal-status
```

### Secrets

#### KV Secrets Engine

##### Store Secret
```http
POST /v1/secret/data/{path}
```

Request:
```json
{
  "data": {
    "key": "value"
  },
  "options": {
    "cas": 0
  }
}
```

##### Retrieve Secret
```http
GET /v1/secret/data/{path}
```

Response:
```json
{
  "data": {
    "data": {
      "key": "value"
    },
    "metadata": {
      "created_time": "2025-01-01T00:00:00Z",
      "version": 1
    }
  }
}
```

##### List Secrets
```http
LIST /v1/secret/metadata/{path}
```

#### PKI Secrets Engine

##### Generate Certificate
```http
POST /v1/pki/issue/{role}
```

Request:
```json
{
  "common_name": "example.com",
  "ttl": "24h"
}
```

Response:
```json
{
  "data": {
    "certificate": "-----BEGIN CERTIFICATE-----\n...",
    "private_key": "-----BEGIN PRIVATE KEY-----\n...",
    "serial_number": "12:34:56:78:90"
  }
}
```

#### Transit Secrets Engine

##### Encrypt Data
```http
POST /v1/transit/encrypt/{key}
```

Request:
```json
{
  "plaintext": "dGVzdCBkYXRh"  // base64 encoded
}
```

Response:
```json
{
  "data": {
    "ciphertext": "vault:v1:..."
  }
}
```

##### Decrypt Data
```http
POST /v1/transit/decrypt/{key}
```

Request:
```json
{
  "ciphertext": "vault:v1:..."
}
```

Response:
```json
{
  "data": {
    "plaintext": "dGVzdCBkYXRh"  // base64 encoded
  }
}
```

### Authentication

#### Token Authentication

##### Login
```http
POST /v1/auth/token/login
```

Request:
```json
{
  "token": "hvs.CAES..."
}
```

##### Renew Token
```http
POST /v1/auth/token/renew
```

Request:
```json
{
  "token": "hvs.CAES..."
}
```

#### UserPass Authentication

##### Login
```http
POST /v1/auth/userpass/login/{username}
```

Request:
```json
{
  "password": "userpassword"
}
```

### Policies

#### List Policies
```http
GET /v1/sys/policies/acl
```

#### Create Policy
```http
PUT /v1/sys/policies/acl/{name}
```

Request:
```json
{
  "policy": "path \"secret/*\" { capabilities = [\"read\"] }"
}
```

### Audit

#### List Audit Devices
```http
GET /v1/sys/audit
```

#### Enable Audit Device
```http
PUT /v1/sys/audit/{path}
```

Request:
```json
{
  "type": "file",
  "options": {
    "file_path": "/var/log/vault/audit.log"
  }
}
```

## Error Responses

All errors follow this format:

```json
{
  "errors": [
    "permission denied"
  ]
}
```

Common HTTP status codes:
- `200` - Success
- `400` - Bad Request
- `401` - Unauthorized
- `403` - Forbidden
- `404` - Not Found
- `500` - Internal Server Error

## Rate Limiting

API requests are rate limited. Check the `X-RateLimit-*` headers in responses:

```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## Pagination

List operations support pagination:

```http
GET /v1/secret/metadata/?list=true&limit=10&after=secret1
```

Response includes:
```json
{
  "data": {
    "keys": ["secret1", "secret2"],
    "next_page": "secret3"
  }
}
```

## SDK Examples

### Rust
```rust
use secreton_core::{Config, VaultClient};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::default();
    let client = VaultClient::new(config).await?;

    // Store secret
    client.kv_put("secret/app", serde_json::json!({
        "api_key": "secret123"
    })).await?;

    // Get secret
    let secret = client.kv_get("secret/app").await?;
    println!("{:?}", secret);

    Ok(())
}
```

### Go
```go
package main

import (
    "context"
    "log"
    "github.com/hashicorp/vault/api"  // Note: This is HashiCorp Vault SDK
)

func main() {
    config := api.DefaultConfig()
    client, err := api.NewClient(config)
    if err != nil {
        log.Fatal(err)
    }

    // For Secreton, use custom client implementation
    // Secreton API is compatible with Vault API
}
```

### Python
```python
import requests

class SecretonClient:
    def __init__(self, url, token):
        self.url = url
        self.token = token
        self.session = requests.Session()
        self.session.headers.update({
            'X-Vault-Token': token
        })

    def kv_get(self, path):
        response = self.session.get(f"{self.url}/v1/secret/data/{path}")
        return response.json()

# Usage
client = SecretonClient("https://vault.example.com", "your-token")
secret = client.kv_get("myapp/config")
print(secret)
```

## Webhooks

Secreton supports webhooks for certain events:

### Configuration
```http
PUT /v1/sys/webhooks/{name}
```

Request:
```json
{
  "url": "https://example.com/webhook",
  "events": ["secret.created", "secret.updated"],
  "headers": {
    "Authorization": "Bearer token"
  }
}
```

### Supported Events
- `secret.created` - New secret stored
- `secret.updated` - Secret modified
- `secret.deleted` - Secret removed
- `auth.login` - User authentication
- `policy.changed` - Policy modification

## Monitoring

### Metrics
```http
GET /v1/sys/metrics
```

Returns Prometheus-compatible metrics:

```
# HELP vault_identity_entity_active_count Current number of active entities
# TYPE vault_identity_entity_active_count gauge
vault_identity_entity_active_count 42

# HELP vault_secret_kv_count Total number of KV secrets
# TYPE vault_secret_kv_count gauge
vault_secret_kv_count 1337
```

### Health Checks
```http
GET /v1/sys/health
```

Response:
```json
{
  "status": "ok",
  "checks": {
    "storage": "ok",
    "crypto": "ok",
    "network": "ok"
  }
}
```

## Best Practices

### Security
1. Use HTTPS for all API calls
2. Rotate tokens regularly
3. Implement least privilege access
4. Monitor audit logs
5. Use short-lived credentials

### Performance
1. Use connection pooling
2. Implement caching where appropriate
3. Batch operations when possible
4. Monitor rate limits

### Reliability
1. Implement retry logic with exponential backoff
2. Handle rate limiting gracefully
3. Monitor health endpoints
4. Plan for failover scenarios

## Troubleshooting

### Common Issues

**401 Unauthorized**
- Check token validity
- Verify token permissions
- Ensure token hasn't expired

**403 Forbidden**
- Review policy permissions
- Check path capabilities
- Verify authentication method

**429 Too Many Requests**
- Implement rate limit handling
- Reduce request frequency
- Use batch operations

**500 Internal Server Error**
- Check server logs
- Verify configuration
- Contact administrators

### Debug Mode

Enable debug logging:

```bash
export RUST_LOG=secreton=debug
secreton server -config=config/debug.toml
```

### Support

For API issues:
1. Check this documentation
2. Review server logs
3. Create GitHub issue with:
   - API request/response
   - Server version
   - Configuration (redacted)
   - Error logs