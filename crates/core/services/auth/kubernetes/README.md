# Kubernetes Authentication Configuration Example

This document provides configuration examples for setting up Kubernetes authentication in Secreton.

## Overview

Kubernetes authentication allows service accounts in Kubernetes clusters to authenticate with Secreton using JWT tokens issued by the Kubernetes API server.

## Configuration

### Basic Configuration

```toml
[kubernetes]
# Kubernetes API server endpoint
kubernetes_host = "https://kubernetes.default.svc.cluster.local:443"

# Optional: Path to CA certificate for verifying Kubernetes API server
kubernetes_ca_cert = "/path/to/kubernetes-ca.crt"

# Optional: Service account token for API server authentication
service_account_token = "eyJhbGciOiJSUzI1NiIsImtpZCI6..."

# Disable local JWT validation (use TokenReview API only)
disable_local_ca_jwt = false

# Optional: JWT for TokenReview API authentication
token_reviewer_jwt = "eyJhbGciOiJSUzI1NiIsImtpZCI6..."

# Optional: Expected JWT issuer
issuer = "https://kubernetes.default.svc.cluster.local"

# Expected JWT audiences
audiences = ["https://kubernetes.default.svc.cluster.local"]

# Public keys for local JWT validation (PEM format)
pem_keys = [
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
]
```

### Role Configuration

```toml
[kubernetes.roles.default]
# Role name
name = "default"

# Bound service account names (empty allows any)
bound_service_account_names = []

# Bound service account namespaces (empty allows any)
bound_service_account_namespaces = []

# Optional: Expected JWT audience
audience = "https://kubernetes.default.svc.cluster.local"

# Source for alias name
alias_name_source = "serviceaccount_uid"

# Token configuration
token_ttl = 3600
token_max_ttl = 86400
token_policies = ["default"]
token_bound_cidrs = []
token_explicit_max_ttl = 86400
token_no_default_policy = false
token_num_uses = 0
token_period = 0
token_type = "service"
```

### Production Configuration Example

```toml
[kubernetes]
kubernetes_host = "https://10.96.0.1:443"
kubernetes_ca_cert = "/etc/kubernetes/ssl/ca.crt"
disable_local_ca_jwt = false
issuer = "https://kubernetes.default.svc.cluster.local"
audiences = ["https://kubernetes.default.svc.cluster.local"]

# Multiple public keys for key rotation
pem_keys = [
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----"
]

[kubernetes.roles.web-app]
name = "web-app"
bound_service_account_names = ["web-app-sa"]
bound_service_account_namespaces = ["production"]
token_policies = ["web-app-policy", "database-read"]
token_ttl = 1800
token_max_ttl = 3600

[kubernetes.roles.api-gateway]
name = "api-gateway"
bound_service_account_names = ["api-gateway-sa"]
bound_service_account_namespaces = ["production"]
token_policies = ["api-gateway-policy", "secret-read"]
token_ttl = 900
token_max_ttl = 1800
```

## Usage

### Authentication Request

```bash
# Authenticate using a Kubernetes service account token
curl -X POST https://secreton.example.com/v1/auth/kubernetes/login \
  -H "Content-Type: application/json" \
  -d '{
    "jwt": "eyJhbGciOiJSUzI1NiIsImtpZCI6..."
  }'
```

### Service Account Token Retrieval

To get a service account token in Kubernetes:

```bash
# Get the token from a pod's service account
kubectl exec -it my-pod -- cat /var/run/secrets/kubernetes.io/serviceaccount/token
```

Or create a dedicated service account:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: secreton-auth
  namespace: default
---
apiVersion: v1
kind: Secret
metadata:
  name: secreton-auth-token
  namespace: default
  annotations:
    kubernetes.io/service-account.name: secreton-auth
type: kubernetes.io/service-account-token
```

## Security Considerations

1. **Token Validation**: Always validate JWT tokens using either local public keys or the TokenReview API
2. **Role Binding**: Use specific service account and namespace bindings to limit access
3. **Token TTL**: Set appropriate token lifetimes based on your security requirements
4. **Network Security**: Ensure the Kubernetes API server is accessible only from trusted sources
5. **Certificate Validation**: Always validate the Kubernetes API server certificate

## Troubleshooting

### Common Issues

1. **TokenReview API Access**: Ensure the service account has permissions to access the TokenReview API
2. **JWT Validation**: Verify that the JWT issuer and audiences match the configuration
3. **Network Connectivity**: Check network connectivity to the Kubernetes API server
4. **Certificate Issues**: Validate CA certificates and ensure proper certificate chain

### Debug Commands

```bash
# Test TokenReview API access
kubectl auth can-i create tokenreviews --as=system:serviceaccount:default:secreton-auth

# Decode JWT token (without verification)
echo "eyJhbGciOiJSUzI1NiIsImtpZCI6..." | jq -R 'split(".") | .[0],.[1] | @base64d | fromjson'
```

## Integration Examples

### Application Integration

```rust
use secreton_core::services::auth::kubernetes::{KubernetesAuth, KubernetesConfig};

async fn authenticate_service_account() -> Result<(), Box<dyn std::error::Error>> {
    let config = KubernetesConfig {
        kubernetes_host: "https://kubernetes.default.svc.cluster.local:443".to_string(),
        kubernetes_ca_cert: None,
        service_account_token: None,
        disable_local_ca_jwt: false,
        token_reviewer_jwt: None,
        issuer: Some("https://kubernetes.default.svc.cluster.local".to_string()),
        audiences: vec!["https://kubernetes.default.svc.cluster.local".to_string()],
        pem_keys: vec![],
    };

    let auth = KubernetesAuth::new(config);

    // Read service account token from file
    let token = tokio::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token").await?;

    let auth_request = AuthRequest::Kubernetes { jwt: token };
    let response = auth.authenticate(&auth_request).await?;

    if response.authenticated {
        println!("Authentication successful!");
        println!("Policies: {:?}", response.policies);
    } else {
        println!("Authentication failed");
    }

    Ok(())
}
```
