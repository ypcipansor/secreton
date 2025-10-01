//! Okta authentication method for Secreton
//!
//! This module provides Okta-based authentication using OAuth 2.0/OpenID Connect.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};
use reqwest::Client as HttpClient;
use chrono::{DateTime, Utc, Duration};

use super::{AuthEngine, AuthError, AuthConfig, AuthResult, AuthRequest, AuthResponse};
use super::traits::{AuthMethod, AuthProvider};

/// Okta authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaConfig {
    /// Enable Okta authentication
    pub enabled: bool,
    /// Okta domain (e.g., "dev-123456.okta.com")
    pub domain: String,
    /// Client ID for OAuth application
    pub client_id: String,
    /// Client secret for OAuth application
    pub client_secret: String,
    /// Authorization server ID (optional)
    pub server_id: Option<String>,
    /// Base URL for Okta API
    pub base_url: Option<String>,
    /// Token verification configuration
    pub token_config: OktaTokenConfig,
    /// Group claim mapping
    pub group_claim: Option<String>,
    /// User claim mapping
    pub username_claim: Option<String>,
    /// Policy claim mapping
    pub policy_claim: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OktaTokenConfig {
    /// JWKS endpoint for token verification
    pub jwks_endpoint: Option<String>,
    /// Token issuer for verification
    pub issuer: Option<String>,
    /// Audience for token verification
    pub audience: Option<String>,
    /// Clock skew tolerance in seconds
    pub clock_skew_seconds: u64,
}

/// Okta authentication engine
pub struct OktaAuth {
    config: OktaConfig,
    http_client: HttpClient,
}

/// Okta token response
#[derive(Debug, Deserialize)]
struct OktaTokenResponse {
    access_token: String,
    token_type: String,
    expires_in: Option<u64>,
    scope: Option<String>,
    id_token: Option<String>,
}

/// Okta user info response
#[derive(Debug, Deserialize)]
struct OktaUserInfo {
    sub: String,
    name: Option<String>,
    preferred_username: Option<String>,
    email: Option<String>,
    groups: Option<Vec<String>>,
}

/// Okta JWT claims
#[derive(Debug, Deserialize)]
struct OktaJwtClaims {
    sub: String,
    aud: String,
    iss: String,
    iat: u64,
    exp: u64,
    groups: Option<Vec<String>>,
    preferred_username: Option<String>,
    email: Option<String>,
}

impl OktaAuth {
    /// Create a new Okta authentication engine
    pub fn new(config: OktaConfig) -> Self {
        Self {
            config,
            http_client: HttpClient::new(),
        }
    }

    /// Get Okta authorization URL
    pub fn get_authorization_url(&self, state: &str, redirect_uri: &str) -> String {
        let base_url = self.config.base_url.as_deref()
            .unwrap_or(&format!("https://{}/oauth2", self.config.domain));

        let server_id = self.config.server_id.as_deref().unwrap_or("default");

        format!(
            "{}/{}/v1/authorize?client_id={}&response_type=code&scope=openid%20profile&redirect_uri={}&state={}",
            base_url, server_id, self.config.client_id, redirect_uri, state
        )
    }

    /// Exchange authorization code for tokens
    async fn exchange_code_for_tokens(&self, code: &str, redirect_uri: &str) -> Result<OktaTokenResponse, AuthError> {
        let base_url = self.config.base_url.as_deref()
            .unwrap_or(&format!("https://{}/oauth2", self.config.domain));

        let server_id = self.config.server_id.as_deref().unwrap_or("default");

        let token_url = format!("{}/{}/v1/token", base_url, server_id);

        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("client_id", &self.config.client_id);
        params.insert("client_secret", &self.config.client_secret);
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);

        let response = self.http_client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthError::InternalError(format!("Token exchange failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::InternalError(format!(
                "Token exchange failed with status {}: {}", status, error_text
            )));
        }

        let token_response = response.json::<OktaTokenResponse>()
            .await
            .map_err(|e| AuthError::InternalError(format!("Failed to parse token response: {}", e)))?;

        Ok(token_response)
    }

    /// Get user info from Okta
    async fn get_user_info(&self, access_token: &str) -> Result<OktaUserInfo, AuthError> {
        let base_url = self.config.base_url.as_deref()
            .unwrap_or(&format!("https://{}/oauth2", self.config.domain));

        let server_id = self.config.server_id.as_deref().unwrap_or("default");
        let userinfo_url = format!("{}/{}/v1/userinfo", base_url, server_id);

        let response = self.http_client
            .get(&userinfo_url)
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await
            .map_err(|e| AuthError::InternalError(format!("User info request failed: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(AuthError::InternalError(format!(
                "User info request failed with status {}: {}", status, error_text
            )));
        }

        let user_info = response.json::<OktaUserInfo>()
            .await
            .map_err(|e| AuthError::InternalError(format!("Failed to parse user info: {}", e)))?;

        Ok(user_info)
    }

    /// Validate and parse JWT token
    async fn validate_jwt_token(&self, token: &str) -> Result<OktaJwtClaims, AuthError> {
        // In a real implementation, this would:
        // 1. Fetch JWKS from Okta
        // 2. Verify JWT signature
        // 3. Validate claims (iss, aud, exp, etc.)
        // 4. Return parsed claims

        // For now, return a mock successful validation
        // This would need proper JWT verification in production

        warn!("JWT token validation is not fully implemented - using mock validation");

        // Mock implementation for demonstration
        Ok(OktaJwtClaims {
            sub: "mock_user_id".to_string(),
            aud: self.config.token_config.audience.clone().unwrap_or_default(),
            iss: self.config.token_config.issuer.clone().unwrap_or_default(),
            iat: chrono::Utc::now().timestamp() as u64,
            exp: (chrono::Utc::now() + Duration::hours(1)).timestamp() as u64,
            groups: Some(vec!["default".to_string()]),
            preferred_username: Some("mock_user".to_string()),
            email: Some("mock@example.com".to_string()),
        })
    }
}

#[async_trait]
impl AuthEngine for OktaAuth {
    async fn authenticate(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        // Handle different authentication flows
        if let Some(code) = request.get_string("code") {
            // OAuth authorization code flow
            let redirect_uri = request.get_string("redirect_uri")
                .unwrap_or_else(|| "http://localhost:3000/callback".to_string());

            let token_response = self.exchange_code_for_tokens(&code, &redirect_uri).await?;
            let user_info = self.get_user_info(&token_response.access_token).await?;

            // Extract policies from groups
            let policies = user_info.groups.unwrap_or_default()
                .into_iter()
                .map(|group| format!("okta_group_{}", group))
                .collect();

            // Use configured claim mappings or defaults
            let username = self.config.username_claim.as_deref()
                .and_then(|claim| request.get_string(claim))
                .unwrap_or_else(|| user_info.preferred_username.unwrap_or_else(|| user_info.sub.clone()));

            let response = AuthResponse {
                authenticated: true,
                token: Some(format!("okta_token_{}", user_info.sub)),
                policies,
                metadata: {
                    let mut metadata = HashMap::new();
                    metadata.insert("username".to_string(), username);
                    metadata.insert("auth_method".to_string(), "okta".to_string());
                    metadata.insert("provider".to_string(), "okta".to_string());
                    metadata.insert("user_id".to_string(), user_info.sub);
                    if let Some(email) = user_info.email {
                        metadata.insert("email".to_string(), email);
                    }
                    metadata
                },
                ttl: token_response.expires_in,
            };

            Ok(response)
        } else if let Some(token) = request.get_string("token") {
            // JWT token validation flow
            let claims = self.validate_jwt_token(&token).await?;

            // Extract policies from groups
            let policies = claims.groups.unwrap_or_default()
                .into_iter()
                .map(|group| format!("okta_group_{}", group))
                .collect();

            let username = self.config.username_claim.as_deref()
                .and_then(|claim| request.get_string(claim))
                .unwrap_or_else(|| claims.preferred_username.unwrap_or_else(|| claims.sub.clone()));

            let response = AuthResponse {
                authenticated: true,
                token: Some(format!("okta_token_{}", claims.sub)),
                policies,
                metadata: {
                    let mut metadata = HashMap::new();
                    metadata.insert("username".to_string(), username);
                    metadata.insert("auth_method".to_string(), "okta".to_string());
                    metadata.insert("provider".to_string(), "okta".to_string());
                    metadata.insert("user_id".to_string(), claims.sub);
                    if let Some(email) = claims.email {
                        metadata.insert("email".to_string(), email);
                    }
                    metadata
                },
                ttl: Some(claims.exp - claims.iat),
            };

            Ok(response)
        } else {
            Err(AuthError::InvalidRequest("Either 'code' or 'token' must be provided".to_string()))
        }
    }

    async fn validate_credentials(&self, _username: &str, _password: &str) -> Result<bool, AuthError> {
        // Okta doesn't use username/password validation directly
        // This would typically be handled through OAuth flows
        Err(AuthError::UnsupportedOperation("Okta auth does not support direct credential validation".to_string()))
    }

/// Okta authentication provider
pub struct OktaAuthProvider;

impl OktaAuthProvider {
    /// Create a new Okta authentication provider
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AuthProvider for OktaAuthProvider {
    async fn authenticate(&self, request: AuthRequest) -> Result<AuthResponse, AuthError> {
        let method = OktaAuthMethod::new();
        method.authenticate(request).await
    }

    fn name(&self) -> &str {
        "okta"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthRequest, AuthResponse};
    use std::collections::HashMap;

    #[test]
    fn test_okta_config_default() {
        let config = OktaConfig::default();
        assert!(config.enabled);
        assert_eq!(config.domain, "your-okta-domain.okta.com");
        assert_eq!(config.client_id, "your-client-id");
        assert_eq!(config.client_secret, "your-client-secret");
        assert!(config.group_claim.is_some());
        assert!(config.username_claim.is_some());
        assert!(config.policy_claim.is_some());
    }

    #[test]
    fn test_okta_token_config_default() {
        let config = OktaTokenConfig::default();
        assert_eq!(config.clock_skew_seconds, 300);
    }

    #[test]
    fn test_get_authorization_url() {
        let config = OktaConfig::default();
        let auth = OktaAuth::new(config);

        let url = auth.get_authorization_url("test_state", "http://localhost:3000/callback");
        assert!(url.contains("authorize"));
        assert!(url.contains("client_id=your-client-id"));
        assert!(url.contains("redirect_uri=http://localhost:3000/callback"));
        assert!(url.contains("state=test_state"));
    }

    #[test]
    fn test_okta_auth_method() {
        let method = OktaAuthMethod::new();
        assert_eq!(method.name(), "okta");
        assert!(method.supported_request_types().contains(&"oauth"));
        assert!(method.supported_request_types().contains(&"jwt"));
    }

    #[test]
    fn test_okta_auth_provider() {
        let provider = OktaAuthProvider::new();
        assert_eq!(provider.name(), "okta");
    }

    #[test]
    fn test_invalid_request() {
        let config = OktaConfig::default();
        let auth = OktaAuth::new(config);

        // Create request without code or token
        let request_data = HashMap::new();
        let request = AuthRequest::new(request_data);

        // Should return error for missing code/token
        let result = tokio_test::block_on(auth.authenticate(request));
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::InvalidRequest(msg) => {
                assert!(msg.contains("code") || msg.contains("token"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[test]
    fn test_okta_auth_method_authenticate() {
        let method = OktaAuthMethod::new();

        // Create request with code
        let mut request_data = HashMap::new();
        request_data.insert("code".to_string(), "test_code".to_string());
        request_data.insert("redirect_uri".to_string(), "http://localhost:3000/callback".to_string());

        let request = AuthRequest::new(request_data);

        // Test authentication (will fail due to network/missing config, but shouldn't panic)
        let result = tokio_test::block_on(method.authenticate(request));
        assert!(result.is_err()); // Should fail gracefully due to invalid config
    }

    #[test]
    fn test_okta_auth_provider_authenticate() {
        let provider = OktaAuthProvider::new();

        // Create request with token
        let mut request_data = HashMap::new();
        request_data.insert("token".to_string(), "test_token".to_string());

        let request = AuthRequest::new(request_data);

        // Test authentication (will fail due to network/missing config, but shouldn't panic)
        let result = tokio_test::block_on(provider.authenticate(request));
        assert!(result.is_err()); // Should fail gracefully
    }
}

impl Default for OktaConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            domain: "your-okta-domain.okta.com".to_string(),
            client_id: "your-client-id".to_string(),
            client_secret: "your-client-secret".to_string(),
            server_id: None,
            base_url: None,
            token_config: OktaTokenConfig::default(),
            group_claim: Some("groups".to_string()),
            username_claim: Some("preferred_username".to_string()),
            policy_claim: Some("policies".to_string()),
        }
    }
}

impl Default for OktaTokenConfig {
    fn default() -> Self {
        Self {
            jwks_endpoint: None,
            issuer: None,
            audience: None,
            clock_skew_seconds: 300,
        }
    }

    fn name(&self) -> &str {
        "okta"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AuthRequest, AuthResponse};
    use std::collections::HashMap;

    #[test]
    fn test_okta_config_default() {
        let config = OktaConfig::default();
        assert!(config.enabled);
        assert_eq!(config.domain, "your-okta-domain.okta.com");
        assert_eq!(config.client_id, "your-client-id");
        assert_eq!(config.client_secret, "your-client-secret");
        assert!(config.group_claim.is_some());
        assert!(config.username_claim.is_some());
        assert!(config.policy_claim.is_some());
    }

    #[test]
    fn test_okta_token_config_default() {
        let config = OktaTokenConfig::default();
        assert_eq!(config.clock_skew_seconds, 300);
    }

    #[test]
    fn test_get_authorization_url() {
        let config = OktaConfig::default();
        let auth = OktaAuth::new(config);

        let url = auth.get_authorization_url("test_state", "http://localhost:3000/callback");
        assert!(url.contains("authorize"));
        assert!(url.contains("client_id=your-client-id"));
        assert!(url.contains("redirect_uri=http://localhost:3000/callback"));
        assert!(url.contains("state=test_state"));
    }

    #[test]
    fn test_okta_auth_method() {
        let method = OktaAuthMethod::new();
        assert_eq!(method.name(), "okta");
        assert!(method.supported_request_types().contains(&"oauth"));
        assert!(method.supported_request_types().contains(&"jwt"));
    }

    #[test]
    fn test_okta_auth_provider() {
        let provider = OktaAuthProvider::new();
        assert_eq!(provider.name(), "okta");
    }

    #[test]
    fn test_invalid_request() {
        let config = OktaConfig::default();
        let auth = OktaAuth::new(config);

        // Create request without code or token
        let request_data = HashMap::new();
        let request = AuthRequest::new(request_data);

        // Should return error for missing code/token
        let result = tokio_test::block_on(auth.authenticate(request));
        assert!(result.is_err());

        match result.unwrap_err() {
            AuthError::InvalidRequest(msg) => {
                assert!(msg.contains("code") || msg.contains("token"));
            }
            _ => panic!("Expected InvalidRequest error"),
        }
    }

    #[test]
    fn test_okta_auth_method_authenticate() {
        let method = OktaAuthMethod::new();

        // Create request with code
        let mut request_data = HashMap::new();
        request_data.insert("code".to_string(), "test_code".to_string());
        request_data.insert("redirect_uri".to_string(), "http://localhost:3000/callback".to_string());

        let request = AuthRequest::new(request_data);

        // Test authentication (will fail due to network/missing config, but shouldn't panic)
        let result = tokio_test::block_on(method.authenticate(request));
        assert!(result.is_err()); // Should fail gracefully due to invalid config
    }

    #[test]
    fn test_okta_auth_provider_authenticate() {
        let provider = OktaAuthProvider::new();

        // Create request with token
        let mut request_data = HashMap::new();
        request_data.insert("token".to_string(), "test_token".to_string());

        let request = AuthRequest::new(request_data);

        // Test authentication (will fail due to network/missing config, but shouldn't panic)
        let result = tokio_test::block_on(provider.authenticate(request));
        assert!(result.is_err()); // Should fail gracefully
    }
}
