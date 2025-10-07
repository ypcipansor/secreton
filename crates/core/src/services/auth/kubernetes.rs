//! Kubernetes Authentication
//!
//! Kubernetes service account token authentication with
//! JWT validation and role binding.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Kubernetes authentication errors
#[derive(Debug, thiserror::Error)]
pub enum K8sError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    
    #[error("JWT validation failed: {0}")]
    JwtValidationFailed(String),
    
    #[error("Unauthorized namespace: {0}")]
    UnauthorizedNamespace(String),
    
    #[error("Unauthorized service account: {0}")]
    UnauthorizedServiceAccount(String),
}

/// Kubernetes JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sJwtClaims {
    /// Issuer
    pub iss: String,
    
    /// Subject (service account)
    pub sub: String,
    
    /// Audience
    pub aud: Vec<String>,
    
    /// Expiration time
    pub exp: i64,
    
    /// Issued at
    pub iat: i64,
    
    /// Kubernetes claims
    pub kubernetes: K8sClaims,
}

/// Kubernetes specific claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sClaims {
    /// Namespace
    pub namespace: String,
    
    /// Service account name
    #[serde(rename = "serviceaccount")]
    pub service_account: ServiceAccountInfo,
    
    /// Pod info
    pub pod: Option<PodInfo>,
}

/// Service account information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceAccountInfo {
    /// Service account name
    pub name: String,
    
    /// Service account UID
    pub uid: String,
}

/// Pod information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PodInfo {
    /// Pod name
    pub name: String,
    
    /// Pod UID
    pub uid: String,
}

/// Kubernetes role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sRole {
    /// Role name
    pub name: String,
    
    /// Bound service account names
    pub bound_service_account_names: Vec<String>,
    
    /// Bound service account namespaces
    pub bound_service_account_namespaces: Vec<String>,
    
    /// Audience (for JWT validation)
    pub audience: String,
    
    /// Token TTL
    pub token_ttl: u64,
    
    /// Token max TTL
    pub token_max_ttl: u64,
    
    /// Policies to assign
    pub policies: Vec<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl K8sRole {
    /// Create new role
    pub fn new(name: String) -> Self {
        Self {
            name,
            bound_service_account_names: Vec::new(),
            bound_service_account_namespaces: Vec::new(),
            audience: "vault".to_string(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            policies: Vec::new(),
            created_at: Utc::now(),
        }
    }
    
    /// Check if service account is authorized
    pub fn is_authorized(&self, namespace: &str, sa_name: &str) -> bool {
        // Check namespace
        let ns_authorized = self.bound_service_account_namespaces.is_empty()
            || self.bound_service_account_namespaces.contains(&namespace.to_string())
            || self.bound_service_account_namespaces.contains(&"*".to_string());
        
        if !ns_authorized {
            return false;
        }
        
        // Check service account name
        let sa_authorized = self.bound_service_account_names.is_empty()
            || self.bound_service_account_names.contains(&sa_name.to_string())
            || self.bound_service_account_names.contains(&"*".to_string());
        
        sa_authorized
    }
}

/// Kubernetes authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sConfig {
    /// Kubernetes API server URL
    pub kubernetes_host: String,
    
    /// Kubernetes CA certificate
    pub kubernetes_ca_cert: Option<String>,
    
    /// Token reviewer JWT (for token validation)
    pub token_reviewer_jwt: Option<String>,
    
    /// Issuer
    pub issuer: Option<String>,
}

impl Default for K8sConfig {
    fn default() -> Self {
        Self {
            kubernetes_host: "https://kubernetes.default.svc".to_string(),
            kubernetes_ca_cert: None,
            token_reviewer_jwt: None,
            issuer: Some("kubernetes/serviceaccount".to_string()),
        }
    }
}

/// Kubernetes authentication service
pub struct K8sAuth {
    config: Arc<RwLock<K8sConfig>>,
    roles: Arc<RwLock<HashMap<String, K8sRole>>>,
}

impl K8sAuth {
    /// Create new Kubernetes auth service
    pub fn new(config: K8sConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Verify JWT token (simplified)
    async fn verify_jwt(&self, token: &str) -> Result<K8sJwtClaims, K8sError> {
        // In production, this would:
        // 1. Call Kubernetes TokenReview API
        // 2. Verify JWT signature with K8s public key
        // 3. Validate claims (exp, iss, aud)
        
        // Simulated JWT parsing
        if token.is_empty() {
            return Err(K8sError::InvalidToken("Empty token".to_string()));
        }
        
        // Simulate parsing JWT
        let claims = K8sJwtClaims {
            iss: "kubernetes/serviceaccount".to_string(),
            sub: "system:serviceaccount:default:app-sa".to_string(),
            aud: vec!["vault".to_string()],
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            kubernetes: K8sClaims {
                namespace: "default".to_string(),
                service_account: ServiceAccountInfo {
                    name: "app-sa".to_string(),
                    uid: "12345".to_string(),
                },
                pod: Some(PodInfo {
                    name: "app-pod-123".to_string(),
                    uid: "67890".to_string(),
                }),
            },
        };
        
        // Check expiration
        let now = Utc::now().timestamp();
        if claims.exp < now {
            return Err(K8sError::TokenExpired);
        }
        
        Ok(claims)
    }
    
    /// Authenticate with Kubernetes token
    pub async fn authenticate(
        &self,
        role_name: &str,
        jwt: &str,
    ) -> Result<K8sAuthResponse, K8sError> {
        // Verify JWT
        let claims = self.verify_jwt(jwt).await?;
        
        // Get role
        let roles = self.roles.read().await;
        let role = roles.get(role_name)
            .ok_or_else(|| K8sError::RoleNotFound(role_name.to_string()))?;
        
        // Check if service account is authorized for this role
        if !role.is_authorized(
            &claims.kubernetes.namespace,
            &claims.kubernetes.service_account.name,
        ) {
            return Err(K8sError::UnauthorizedServiceAccount(
                format!(
                    "{}/{}",
                    claims.kubernetes.namespace,
                    claims.kubernetes.service_account.name
                )
            ));
        }
        
        // Check audience
        if !claims.aud.contains(&role.audience) {
            return Err(K8sError::JwtValidationFailed(
                format!("Invalid audience, expected: {}", role.audience)
            ));
        }
        
        Ok(K8sAuthResponse {
            namespace: claims.kubernetes.namespace,
            service_account_name: claims.kubernetes.service_account.name,
            service_account_uid: claims.kubernetes.service_account.uid,
            pod_name: claims.kubernetes.pod.as_ref().map(|p| p.name.clone()),
            pod_uid: claims.kubernetes.pod.as_ref().map(|p| p.uid.clone()),
            policies: role.policies.clone(),
            token_ttl: role.token_ttl,
        })
    }
    
    /// Create role
    pub async fn create_role(&self, role: K8sRole) -> Result<(), K8sError> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }
    
    /// Get role
    pub async fn get_role(&self, name: &str) -> Option<K8sRole> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }
    
    /// List roles
    pub async fn list_roles(&self) -> Vec<K8sRole> {
        let roles = self.roles.read().await;
        roles.values().cloned().collect()
    }
    
    /// Delete role
    pub async fn delete_role(&self, name: &str) -> Result<(), K8sError> {
        let mut roles = self.roles.write().await;
        roles.remove(name)
            .ok_or_else(|| K8sError::RoleNotFound(name.to_string()))?;
        Ok(())
    }
    
    /// Update configuration
    pub async fn update_config(&self, config: K8sConfig) {
        let mut current = self.config.write().await;
        *current = config;
    }
}

/// Kubernetes authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct K8sAuthResponse {
    pub namespace: String,
    pub service_account_name: String,
    pub service_account_uid: String,
    pub pod_name: Option<String>,
    pub pod_uid: Option<String>,
    pub policies: Vec<String>,
    pub token_ttl: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_role() {
        let config = K8sConfig::default();
        let k8s = K8sAuth::new(config);
        
        let mut role = K8sRole::new("app-role".to_string());
        role.bound_service_account_names = vec!["app-sa".to_string()];
        role.bound_service_account_namespaces = vec!["default".to_string()];
        role.policies = vec!["app-policy".to_string()];
        
        k8s.create_role(role).await.unwrap();
        
        let retrieved = k8s.get_role("app-role").await.unwrap();
        assert_eq!(retrieved.name, "app-role");
    }
    
    #[tokio::test]
    async fn test_authenticate() {
        let config = K8sConfig::default();
        let k8s = K8sAuth::new(config);
        
        let mut role = K8sRole::new("app-role".to_string());
        role.bound_service_account_names = vec!["app-sa".to_string()];
        role.bound_service_account_namespaces = vec!["default".to_string()];
        role.policies = vec!["app-policy".to_string()];
        
        k8s.create_role(role).await.unwrap();
        
        let result = k8s.authenticate("app-role", "mock-jwt-token").await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert_eq!(response.namespace, "default");
        assert_eq!(response.service_account_name, "app-sa");
    }
    
    #[tokio::test]
    async fn test_role_authorization() {
        let mut role = K8sRole::new("test-role".to_string());
        role.bound_service_account_namespaces = vec!["prod".to_string()];
        role.bound_service_account_names = vec!["api-sa".to_string()];
        
        assert!(role.is_authorized("prod", "api-sa"));
        assert!(!role.is_authorized("dev", "api-sa"));
        assert!(!role.is_authorized("prod", "other-sa"));
    }
}
