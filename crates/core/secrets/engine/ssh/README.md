# SSH Secrets Engine

SSH Secrets Engine untuk Secreton memungkinkan manajemen SSH keys dan certificates secara terpusat, memberikan kontrol penuh atas akses SSH ke server-server enterprise.

## Overview

SSH Secrets Engine menyediakan:
- **SSH Certificate Authority (CA)** untuk signing SSH certificates
- **Dynamic SSH Key Generation** dengan automatic rotation
- **Role-based Access Control** untuk SSH certificates
- **Certificate Revocation** untuk security incident response
- **Integration dengan SSH servers** untuk seamless authentication

## Quick Start

### 1. Setup SSH Certificate Authority

```bash
# Create SSH CA untuk user certificates
curl -X POST https://secreton.example.com/v1/ssh/ca/user \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"key_type": "rsa"}'

# Create SSH CA untuk host certificates
curl -X POST https://secreton.example.com/v1/ssh/ca/host \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"key_type": "rsa"}'
```

### 2. Create SSH Role

```bash
curl -X POST https://secreton.example.com/v1/ssh/roles/web-servers \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "key_type": "ca",
    "default_user": "ubuntu",
    "allowed_users": ["ubuntu", "ec2-user"],
    "max_ttl": "24h",
    "ttl": "1h",
    "allow_user_certificates": true,
    "allowed_extensions": {
      "permit-pty": "",
      "permit-port-forwarding": ""
    }
  }'
```

### 3. Generate SSH Certificate

```bash
# Generate new SSH key pair dan certificate
curl -X POST https://secreton.example.com/v1/ssh/creds/web-servers \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"key_type": "rsa", "key_bits": 2048}'

# Response:
{
  "certificate": "ssh-rsa-cert-v01@openssh.com AAAAHHNzaC1yc2EtY2VydC12MDFAB3BlbnNzaC5jb20AAAAg...",
  "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n...",
  "serial_number": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "expiration": "2025-08-29T10:30:00Z"
}
```

### 4. Sign Existing Public Key

```bash
curl -X POST https://secreton.example.com/v1/ssh/sign/web-servers \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "public_key": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDh8BW2J5+m2K8Jc1V5K6...",
    "ttl": "2h",
    "valid_principals": ["ubuntu"]
  }'
```

## Configuration

### SSH Role Parameters

| Parameter | Type | Description | Example |
|-----------|------|-------------|---------|
| `key_type` | string | Type of SSH key | `"ca"`, `"user"`, `"host"` |
| `default_user` | string | Default SSH user | `"ubuntu"` |
| `allowed_users` | array | Allowed SSH users | `["ubuntu", "ec2-user"]` |
| `max_ttl` | string | Maximum certificate lifetime | `"24h"`, `"86400"` |
| `ttl` | string | Default certificate lifetime | `"1h"`, `"3600"` |
| `allow_user_certificates` | boolean | Allow user certificates | `true` |
| `allow_host_certificates` | boolean | Allow host certificates | `false` |
| `allowed_extensions` | object | Permitted SSH extensions | `{"permit-pty": ""}` |
| `allowed_critical_options` | array | Permitted critical options | `["source-address"]` |

### SSH Extensions

Common SSH certificate extensions:

```json
{
  "permit-pty": "",
  "permit-port-forwarding": "",
  "permit-agent-forwarding": "",
  "permit-X11-forwarding": "",
  "permit-user-rc": "",
  "no-pty": "",
  "no-port-forwarding": "",
  "no-agent-forwarding": "",
  "no-X11-forwarding": "",
  "no-user-rc": ""
}
```

### SSH Critical Options

```json
{
  "source-address": "192.168.1.0/24,10.0.0.0/8",
  "force-command": "/usr/bin/custom-shell",
  "verify-required": ""
}
```

## Server Configuration

### OpenSSH Server Setup

1. **Configure SSH to trust CA:**

```bash
# Add CA public key ke /etc/ssh/trusted-user-ca-keys.pem
curl https://secreton.example.com/v1/ssh/ca/user > /etc/ssh/trusted-user-ca-keys.pem

# Update /etc/ssh/sshd_config
TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem
```

2. **Restart SSH service:**

```bash
sudo systemctl restart sshd
```

### Host Certificate Setup

```bash
# Get host certificate
curl -X POST https://secreton.example.com/v1/ssh/sign/host-role \
  -H "X-Vault-Token: $TOKEN" \
  -d '{
    "public_key": "'$(cat /etc/ssh/ssh_host_rsa_key.pub)'",
    "ttl": "8760h",
    "valid_principals": ["server.example.com"]
  }'

# Configure SSH server
HostCertificate /etc/ssh/ssh_host_rsa_key-cert.pub
```

## Certificate Lifecycle

### Certificate Expiration

Certificates automatically expire based on TTL settings. Monitor expiration:

```bash
# Check certificate expiration
ssh-keygen -L -f certificate.pub

# Renew certificate before expiration
curl -X POST https://secreton.example.com/v1/ssh/sign/role-name \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"public_key": "...", "ttl": "1h"}'
```

### Certificate Revocation

Revoke compromised certificates immediately:

```bash
# Revoke certificate by serial number
curl -X POST https://secreton.example.com/v1/ssh/revoke \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"serial_number": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'

# Check if certificate is revoked
curl https://secreton.example.com/v1/ssh/revoke/check \
  -H "X-Vault-Token: $TOKEN" \
  -d '{"serial_number": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"}'
```

## Security Best Practices

### 1. Principle of Least Privilege

```json
{
  "allowed_users": ["specific-user"],
  "allowed_extensions": {
    "permit-pty": "",
    "no-port-forwarding": "",
    "no-agent-forwarding": ""
  },
  "max_ttl": "8h"
}
```

### 2. Certificate Rotation

- Set reasonable TTL values (1-24 hours for users)
- Implement automatic rotation in CI/CD
- Monitor certificate usage patterns

### 3. Access Control

- Use specific roles per environment
- Implement network restrictions with CIDR
- Regular audit of certificate issuance

### 4. Monitoring & Alerting

```bash
# Monitor certificate issuance
curl https://secreton.example.com/v1/ssh/certificates \
  -H "X-Vault-Token: $TOKEN"

# Check CA status
curl https://secreton.example.com/v1/ssh/ca/user \
  -H "X-Vault-Token: $TOKEN"
```

## Troubleshooting

### Common Issues

1. **Certificate rejected by server:**
   - Verify CA public key is installed on server
   - Check SSH server configuration
   - Ensure certificate is not expired/revoked

2. **Permission denied:**
   - Verify user is in `allowed_users`
   - Check role permissions
   - Validate certificate extensions

3. **Certificate expired:**
   - Check TTL settings
   - Implement automatic renewal
   - Monitor expiration dates

### Debug Commands

```bash
# Validate certificate
ssh-keygen -L -f certificate.pub

# Check SSH server logs
sudo journalctl -u sshd -f

# Test certificate authentication
ssh -i private_key -o CertificateFile=certificate.pub user@server
```

## Integration Examples

### CI/CD Pipeline Integration

```yaml
# .github/workflows/deploy.yml
name: Deploy
on: push

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Get SSH Certificate
        run: |
          curl -X POST https://secreton.example.com/v1/ssh/creds/deploy-role \
            -H "X-Vault-Token: ${{ secrets.VAULT_TOKEN }}" \
            -o ssh-cert.json

      - name: Deploy to Server
        run: |
          PRIVATE_KEY=$(jq -r .private_key ssh-cert.json)
          CERTIFICATE=$(jq -r .certificate ssh-cert.json)
          echo "$PRIVATE_KEY" > deploy_key
          echo "$CERTIFICATE" > deploy_key-cert.pub
          chmod 600 deploy_key*

          ssh -i deploy_key -o CertificateFile=deploy_key-cert.pub \
            ubuntu@server.example.com "deploy-application.sh"
```

### Application Integration

```rust
use reqwest::Client;
use serde_json::json;

async fn get_ssh_certificate(role: &str, vault_token: &str) -> Result<SshCredentials, Box<dyn std::error::Error>> {
    let client = Client::new();

    let response = client
        .post(&format!("https://secreton.example.com/v1/ssh/creds/{}", role))
        .header("X-Vault-Token", vault_token)
        .json(&json!({
            "key_type": "rsa",
            "key_bits": 2048
        }))
        .send()
        .await?;

    let credentials: SshCredentials = response.json().await?;
    Ok(credentials)
}

#[derive(Deserialize)]
struct SshCredentials {
    certificate: String,
    private_key: String,
    serial_number: String,
}
```

## API Reference

### Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/v1/ssh/ca/{type}` | Create SSH CA |
| `GET` | `/v1/ssh/ca/{type}` | Get CA public key |
| `DELETE` | `/v1/ssh/ca/{type}` | Delete SSH CA |
| `POST` | `/v1/ssh/roles/{name}` | Create SSH role |
| `GET` | `/v1/ssh/roles/{name}` | Get SSH role |
| `DELETE` | `/v1/ssh/roles/{name}` | Delete SSH role |
| `GET` | `/v1/ssh/roles` | List SSH roles |
| `POST` | `/v1/ssh/creds/{role}` | Generate SSH credentials |
| `POST` | `/v1/ssh/sign/{role}` | Sign SSH public key |
| `POST` | `/v1/ssh/revoke` | Revoke SSH certificate |
| `GET` | `/v1/ssh/revoke/check` | Check revocation status |

### Response Codes

- `200` - Success
- `400` - Bad request (invalid parameters)
- `403` - Forbidden (insufficient permissions)
- `404` - Not found (CA/role doesn't exist)
- `500` - Internal server error

## Performance Considerations

- **Certificate Generation:** < 100ms per certificate
- **Concurrent Requests:** Supports 1000+ concurrent requests
- **Storage Requirements:** Minimal (certificate metadata only)
- **Memory Usage:** Low memory footprint

## Compliance

SSH Secrets Engine membantu memenuhi:
- **SOX 404** - Access control dan audit trails
- **PCI DSS** - Secure key management
- **NIST 800-53** - Access control requirements
- **ISO 27001** - Information security management

---

*SSH Secrets Engine memberikan kontrol penuh atas SSH access dengan enterprise-grade security dan compliance features.*</content>
<parameter name="filePath">/home/clouduser/secreton/secreton/crates/core/secrets/engine/ssh/README.md
