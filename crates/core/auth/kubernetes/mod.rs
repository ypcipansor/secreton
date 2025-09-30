use crate::auth::traits::{AuthMethod, AuthResult};
use crate::error::CoreError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Kubernetes authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesAuthConfig {
    /// Kubernetes API server URL
    pub kubernetes_host: String,
    /// Kubernetes CA certificate
    pub kubernetes_ca_cert: Option<String>,
    /// Token reviewer JWT (for token review API)
    pub token_reviewer_jwt: Option<String>,
    /// Allowed namespaces
    pub allowed_namespaces: Vec<String>,
    /// Allowed service accounts
    pub allowed_service_accounts: Vec<String>,
    /// Token TTL in seconds
    pub ttl: i64,
}

impl Default for KubernetesAuthConfig {
    fn default() -> Self {
        Self {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            token_reviewer_jwt: None,
            allowed_namespaces: Vec::new(),
            allowed_service_accounts: Vec::new(),
            ttl: 3600,
        }
    }
}

/// Kubernetes service account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountInfo {
    pub name: String,
    pub namespace: String,
    pub uid: String,
}

/// Kubernetes authentication method
pub struct KubernetesAuth {
    config: KubernetesAuthConfig,
    client: reqwest::Client,
}

impl KubernetesAuth {
    /// Create new Kubernetes authentication method
    pub fn new(config: KubernetesAuthConfig) -> Result<Self, CoreError> {
        let mut client_builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30));

        // Add CA certificate if provided
        if let Some(ca_cert) = &config.kubernetes_ca_cert {
            let cert = reqwest::Certificate::from_pem(ca_cert.as_bytes())
                .map_err(|e| CoreError::configuration(format!("Invalid CA certificate: {}", e)))?;
            client_builder = client_builder.add_root_certificate(cert);
        }

        let client = client_builder.build()
            .map_err(|e| CoreError::configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Verify Kubernetes service account token using TokenReview API
    async fn verify_token(&self, token: &str) -> Result<ServiceAccountInfo, CoreError> {
        let url = format!("{}/apis/authentication.k8s.io/v1/tokenreviews", self.config.kubernetes_host);

        let review_request = serde_json::json!({
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {
                "token": token
            }
        });

        let mut request = self.client.post(&url).json(&review_request);

        // Add reviewer JWT if configured
        if let Some(reviewer_jwt) = &self.config.token_reviewer_jwt {
            request = request.bearer_auth(reviewer_jwt);
        }

        let response = request.send().await
            .map_err(|e| CoreError::authentication(format!("Failed to verify Kubernetes token: {}", e)))?;

        if !response.status().is_success() {
            return Err(CoreError::authentication("Invalid Kubernetes token"));
        }

        #[derive(Deserialize)]
        struct TokenReviewResponse {
            status: TokenReviewStatus,
        }

        #[derive(Deserialize)]
        struct TokenReviewStatus {
            authenticated: bool,
            user: Option<UserInfo>,
        }

        #[derive(Deserialize)]
        struct UserInfo {
            username: String,
            uid: String,
        }

        let review: TokenReviewResponse = response.json().await
            .map_err(|e| CoreError::authentication(format!("Failed to parse token review: {}", e)))?;

        if !review.status.authenticated {
            return Err(CoreError::authentication("Token not authenticated"));
        }

        let user = review.status.user
            .ok_or_else(|| CoreError::authentication("No user information in token"))?;

        // Parse service account from username (format: system:serviceaccount:namespace:name)
        let parts: Vec<&str> = user.username.split(':').collect();
        if parts.len() != 4 || parts[0] != "system" || parts[1] != "serviceaccount" {
            return Err(CoreError::authentication("Invalid service account format"));
        }

        Ok(ServiceAccountInfo {
            namespace: parts[2].to_string(),
            name: parts[3].to_string(),
            uid: user.uid,
        })
    }

    /// Check if service account is allowed
    fn is_allowed(&self, sa_info: &ServiceAccountInfo) -> bool {
        // Check namespace
        if !self.config.allowed_namespaces.is_empty() 
            && !self.config.allowed_namespaces.contains(&sa_info.namespace) {
            return false;
        }

        // Check service account
        if !self.config.allowed_service_accounts.is_empty() {
            let full_name = format!("{}/{}", sa_info.namespace, sa_info.name);
            if !self.config.allowed_service_accounts.contains(&full_name) 
                && !self.config.allowed_service_accounts.contains(&sa_info.name) {
                return false;
            }
        }

        true
    }
}

#[async_trait]
impl AuthMethod for KubernetesAuth {
    fn method_type(&self) -> &'static str {
        "kubernetes"
    }

    async fn authenticate(&self, credentials: HashMap<String, String>) -> Result<AuthResult, CoreError> {
        let token = credentials.get("jwt")
            .or_else(|| credentials.get("token"))
            .ok_or_else(|| CoreError::authentication("Kubernetes service account token required"))?;

        // Verify token
        let sa_info = self.verify_token(token).await?;

        // Check if allowed
        if !self.is_allowed(&sa_info) {
            return Err(CoreError::authentication("Service account not allowed"));
        }

        // Generate policies based on namespace and service account
        let policies = vec![
            format!("k8s-namespace-{}", sa_info.namespace),
            format!("k8s-sa-{}", sa_info.name),
        ];

        Ok(AuthResult {
            authenticated: true,
            user_id: sa_info.uid.clone(),
            username: format!("{}/{}", sa_info.namespace, sa_info.name),
            policies,
            metadata: HashMap::from([
                ("k8s_namespace".to_string(), sa_info.namespace),
                ("k8s_service_account".to_string(), sa_info.name),
                ("k8s_uid".to_string(), sa_info.uid),
            ]),
            ttl: self.config.ttl,
        })
    }

    async fn validate_token(&self, token: &str) -> Result<bool, CoreError> {
        self.verify_token(token).map(|_| true).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kubernetes_config_default() {
        let config = KubernetesAuthConfig::default();
        assert_eq!(config.kubernetes_host, "https://kubernetes.default.svc");
        assert_eq!(config.ttl, 3600);
    }

    #[test]
    fn test_kubernetes_auth_creation() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_is_allowed_no_restrictions() {
        let config = KubernetesAuthConfig::default();
        let auth = KubernetesAuth::new(config).unwrap();
        
        let sa_info = ServiceAccountInfo {
            name: "test-sa".to_string(),
            namespace: "default".to_string(),
            uid: "test-uid".to_string(),
        };
        
        assert!(auth.is_allowed(&sa_info));
    }

    #[test]
    fn test_is_allowed_with_namespace_restriction() {
        let mut config = KubernetesAuthConfig::default();
        config.allowed_namespaces = vec!["production".to_string()];
        let auth = KubernetesAuth::new(config).unwrap();
        
        let sa_info = ServiceAccountInfo {
            name: "test-sa".to_string(),
            namespace: "production".to_string(),
            uid: "test-uid".to_string(),
        };
        
        assert!(auth.is_allowed(&sa_info));
        
        let sa_info_denied = ServiceAccountInfo {
            name: "test-sa".to_string(),
            namespace: "development".to_string(),
            uid: "test-uid".to_string(),
        };
        
        assert!(!auth.is_allowed(&sa_info_denied));
    }
}
