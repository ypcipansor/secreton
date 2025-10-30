//! Okta Authentication
//!
//! Okta SSO integration using OAuth2/OIDC for _user authentication.

use chrono::{DateTime, Utc};
use oauth2::{AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};
use crate::core::error::{AuthError, Result};

/// Okta configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Organization _name
    pub organization: String,
    
    /// Okta _domain (_e.g., "dev-12345678.okta.com")
    pub okta_domain: String,
    
    /// Client ID for OAuth2
    pub client_id: String,
    
    /// Client _secret for OAuth2 (encrypted)
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
    /// Create new Okta _config
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

/// Okta authentication _request
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
    
    /// Display _name
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
    pub async fn configure(&self, _config: OktaConfig) -> Result<()> {
        // Validate configuration
        if _config.okta_domain.is_empty() {
            return Err(SecretonError::Validation { message: "Okta _domain is required".to_string() });
        }
        
        if _config.client_id.is_empty() {
            return Err(SecretonError::Validation { message: "Client ID is required".to_string() });
        }
        
        let mut configs = self.configs.write().await;
        configs.insert(_config.organization.clone(), _config);
        
        Ok(())
    }
    
    /// Get authorization URL for OAuth2 flow
    pub async fn get_auth_url(
        &self,
        organization: &str,
        state: &str,
    ) -> Result<String> {
        let configs = self.configs.read().await;
        let _config = configs
            .get(organization)
            .ok_or_else(|| SecretonError::NotFound { resource: organization.to_string() })?;
        
        // Build OAuth2 authorization URL
        let auth_url = format!(
            "https://{}/oauth2/v1/authorize?client_id={}&response_type=code&scope=openid%20profile%20email%20groups&redirect_uri={}&state={}",
            _config.okta_domain,
            _config.client_id,
            urlencoding::encode(&_config.redirect_uri),
            state
        );
        
        Ok(auth_url)
    }
    
    /// Authenticate _user with authorization code
    pub async fn authenticate(
        &self,
        organization: &str,
        _request: OktaAuthRequest,
    ) -> Result<OktaAuthResponse> {
        let configs = self.configs.read().await;
        let _config = configs
            .get(organization)
            .ok_or_else(|| SecretonError::NotFound { resource: organization.to_string() })?
            .clone();
        drop(configs);

        // Create OAuth2 client
        let client = BasicClient::new(
            ClientId::new(_config.client_id.clone()),
            Some(ClientSecret::new(_config.client_secret.clone())),
            oauth2::AuthUrl::new(format!("https://{}/oauth2/v1/authorize", _config.okta_domain))?,
            Some(oauth2::TokenUrl::new(format!("https://{}/oauth2/v1/token", _config.okta_domain))?)
        )
        .set_redirect_uri(RedirectUrl::new(_config.redirect_uri.clone())?);

        // Exchange authorization code for tokens
        let token_result = client
            .exchange_code(AuthorizationCode::new(_request.code.clone()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthError::authentication(format!("OAuth2 token exchange failed: {}", e)))?;

        // Extract ID token and verify it
        let id_token = token_result.id_token()
            .ok_or_else(|| AuthError::authentication("No ID token in response".to_string()))?;

        // For production, you should verify the ID token signature here
        // This is a simplified implementation
        let claims: serde_json::Value = serde_json::from_str(&id_token.to_string())?;

        let user_email = claims["email"].as_str()
            .ok_or_else(|| AuthError::authentication("No email in ID token".to_string()))?
            .to_string();

        let user_id = claims["sub"].as_str()
            .unwrap_or("unknown")
            .to_string();

        let display_name = claims["name"].as_str()
            .unwrap_or("Unknown User")
            .to_string();

        // Extract groups from token or fetch from Okta API
        let groups = if let Some(groups_claim) = claims["groups"].as_array() {
            groups_claim.iter()
                .filter_map(|g| g.as_str())
                .map(|s| s.to_string())
                .collect()
        } else {
            vec!["Everyone".to_string()]
        };

        // Check group membership
        if !_config.allowed_groups.is_empty() {
            let has_allowed_group = groups
                .iter()
                .any(|g| _config.allowed_groups.contains(g));

            if !has_allowed_group {
                return Err(AuthError::authentication(
                    "User not in allowed groups".to_string(),
                ));
            }
        }

        // Generate token
        let token = format!("hvs.okta.{}", uuid::Uuid::new_v4().to_string().replace("-", ""));

        Ok(OktaAuthResponse {
            email: user_email,
            user_id,
            display_name,
            groups,
            policies: _config.policies.clone(),
            token,
            ttl: _config.token_ttl,
            authenticated_at: Utc::now(),
        })
    }
    
    /// Verify Okta token
    pub async fn verify_token(
        &self,
        organization: &str,
        token: &str,
    ) -> Result<bool> {
        let configs = self.configs.read().await;
        let _config = configs
            .get(organization)
            .ok_or_else(|| SecretonError::NotFound { resource: organization.to_string() })?;
        
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
        let _config = OktaConfig::new(
            "test-org".to_string(),
            "dev-12345678.okta.com".to_string(),
        );
        
        service.configure(_config).await.unwrap();
    }
    
    #[tokio::test]
    async fn test_get_auth_url() {
        let service = OktaAuthService::new();
        let mut _config = OktaConfig::new(
            "test-org".to_string(),
            "dev-12345678.okta.com".to_string(),
        );
        _config.client_id = "test-client-id".to_string();
        _config.redirect_uri = "https://vault.example.com/callback".to_string();
        
        service.configure(_config).await.unwrap();
        
        let auth_url = service
            .get_auth_url("test-org", "random-state-123")
            .await
            .unwrap();
        
        assert!(auth_url.contains("dev-12345678.okta.com"));
        assert!(auth_url.contains("client_id=test-client-id"));
        assert!(auth_url.contains("state=random-state-123"));
    }
}
