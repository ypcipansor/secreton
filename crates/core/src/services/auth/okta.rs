//! Okta Authentication
//!
//! Okta SSO integration using OAuth2/OIDC for user authentication.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Okta authentication errors
#[derive(Debug, thiserror::Error)]
pub enum OktaError {
    #[error("Organization not found: {0}")]
    OrgNotFound(String),
    
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Token verification failed: {0}")]
    TokenVerificationFailed(String),
    
    #[error("API error: {0}")]
    ApiError(String),
}

/// Okta configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Organization name
    pub organization: String,
    
    /// Okta domain (e.g., "dev-12345678.okta.com")
    pub okta_domain: String,
    
    /// Client ID for OAuth2
    pub client_id: String,
    
    /// Client secret for OAuth2 (encrypted)
    pub client_secret: String,
    
    /// Redirect URI
    pub redirect_uri: String,
    
    /// Allowed groups (empty = all)
    pub allowed_groups: Vec<String>,
    
    /// Token TTL
    pub token_ttl: u64,
    
    /// Token max TTL
    pub token_max_ttl: u64,
    
    /// Policies to assign
    pub policies: Vec<String>,
    
    /// API token for Okta API (encrypted)
    pub api_token: Option<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl OktaConfig {
    /// Create new Okta config
    pub fn new(organization: String, okta_domain: String) -> Self {
        Self {
            organization,
            okta_domain,
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            allowed_groups: Vec::new(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            policies: Vec::new(),
            api_token: None,
            created_at: Utc::now(),
        }
    }
}

/// Okta authentication request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaAuthRequest {
    /// Authorization code from Okta
    pub code: String,
    
    /// State parameter for CSRF protection
    pub state: String,
}

/// Okta authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaAuthResponse {
    /// User email
    pub email: String,
    
    /// User ID
    pub user_id: String,
    
    /// Display name
    pub display_name: String,
    
    /// Groups
    pub groups: Vec<String>,
    
    /// Policies assigned
    pub policies: Vec<String>,
    
    /// Token (created)
    pub token: String,
    
    /// Token TTL
    pub ttl: u64,
    
    /// Authenticated at
    pub authenticated_at: DateTime<Utc>,
}

/// Okta authentication service
pub struct OktaAuthService {
    configs: Arc<RwLock<HashMap<String, OktaConfig>>>,
}

impl OktaAuthService {
    /// Create new Okta auth service
    pub fn new() -> Self {
        Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Configure Okta organization
    pub async fn configure(&self, config: OktaConfig) -> Result<(), OktaError> {
        // Validate configuration
        if config.okta_domain.is_empty() {
            return Err(OktaError::InvalidConfig("Okta domain is required".to_string()));
        }
        
        if config.client_id.is_empty() {
            return Err(OktaError::InvalidConfig("Client ID is required".to_string()));
        }
        
        let mut configs = self.configs.write().await;
        configs.insert(config.organization.clone(), config);
        
        Ok(())
    }
    
    /// Get authorization URL for OAuth2 flow
    pub async fn get_auth_url(
        &self,
        organization: &str,
        state: &str,
    ) -> Result<String, OktaError> {
        let configs = self.configs.read().await;
        let config = configs
            .get(organization)
            .ok_or_else(|| OktaError::OrgNotFound(organization.to_string()))?;
        
        // Build OAuth2 authorization URL
        let auth_url = format!(
            "https://{}/oauth2/v1/authorize?client_id={}&response_type=code&scope=openid%20profile%20email%20groups&redirect_uri={}&state={}",
            config.okta_domain,
            config.client_id,
            urlencoding::encode(&config.redirect_uri),
            state
        );
        
        Ok(auth_url)
    }
    
    /// Authenticate user with authorization code
    pub async fn authenticate(
        &self,
        organization: &str,
        request: OktaAuthRequest,
    ) -> Result<OktaAuthResponse, OktaError> {
        let configs = self.configs.read().await;
        let config = configs
            .get(organization)
            .ok_or_else(|| OktaError::OrgNotFound(organization.to_string()))?
            .clone();
        drop(configs);
        
        // Exchange authorization code for tokens
        // In production, this would make real HTTP requests to Okta
        // For now, we simulate the response
        
        // TODO: Implement actual OAuth2 token exchange
        // 1. POST to https://{okta_domain}/oauth2/v1/token
        // 2. Verify ID token signature
        // 3. Extract user claims
        // 4. Fetch user groups
        // 5. Check group membership against allowed_groups
        
        // Simulated response for now
        let user_email = format!("user@{}", config.organization);
        let user_id = "okta-user-123";
        let display_name = "Test User";
        let groups = vec!["Everyone".to_string()];
        
        // Check group membership
        if !config.allowed_groups.is_empty() {
            let has_allowed_group = groups
                .iter()
                .any(|g| config.allowed_groups.contains(g));
            
            if !has_allowed_group {
                return Err(OktaError::AuthenticationFailed(
                    "User not in allowed groups".to_string(),
                ));
            }
        }
        
        // Generate token
        let token = format!("hvs.okta.{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
        
        Ok(OktaAuthResponse {
            email: user_email,
            user_id: user_id.to_string(),
            display_name: display_name.to_string(),
            groups,
            policies: config.policies.clone(),
            token,
            ttl: config.token_ttl,
            authenticated_at: Utc::now(),
        })
    }
    
    /// Verify Okta token
    pub async fn verify_token(
        &self,
        organization: &str,
        token: &str,
    ) -> Result<bool, OktaError> {
        let configs = self.configs.read().await;
        let _config = configs
            .get(organization)
            .ok_or_else(|| OktaError::OrgNotFound(organization.to_string()))?;
        
        // TODO: Implement actual token verification
        // 1. Introspect token with Okta
        // 2. Verify signature and expiration
        
        Ok(token.starts_with("hvs.okta."))
    }
}

impl Default for OktaAuthService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_okta_configuration() {
        let service = OktaAuthService::new();
        let config = OktaConfig::new(
            "test-org".to_string(),
            "dev-12345678.okta.com".to_string(),
        );
        
        service.configure(config).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_get_auth_url() {
        let service = OktaAuthService::new();
        let mut config = OktaConfig::new(
            "test-org".to_string(),
            "dev-12345678.okta.com".to_string(),
        );
        config.client_id = "test-client-id".to_string();
        config.redirect_uri = "https://vault.example.com/callback".to_string();
        
        service.configure(config).await.unwrap();
        
        let auth_url = service
            .get_auth_url("test-org", "random-state-123")
            .await
            .unwrap();
        
        assert!(auth_url.contains("dev-12345678.okta.com"));
        assert!(auth_url.contains("client_id=test-client-id"));
        assert!(auth_url.contains("state=random-state-123"));
    }
}
