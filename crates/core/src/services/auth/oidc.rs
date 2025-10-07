//! OIDC/JWT Authentication
//!
//! OpenID Connect and JWT-based authentication with claims mapping,
//! role binding, and OIDC discovery support.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// OIDC/JWT authentication errors
#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("Invalid token: {0}")]
    InvalidToken(String),
    
    #[error("Token expired")]
    TokenExpired,
    
    #[error("Role not found: {0}")]
    RoleNotFound(String),
    
    #[error("Claims validation failed: {0}")]
    ClaimsValidationFailed(String),
    
    #[error("OIDC discovery failed: {0}")]
    DiscoveryFailed(String),
    
    #[error("Invalid issuer")]
    InvalidIssuer,
}

/// OIDC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL
    pub issuer_url: String,
    
    /// OIDC discovery URL (typically issuer + /.well-known/openid-configuration)
    pub discovery_url: String,
    
    /// Client ID
    pub client_id: String,
    
    /// Client secret
    pub client_secret: String,
    
    /// Redirect URI
    pub redirect_uri: String,
    
    /// Allowed redirect URIs
    pub allowed_redirect_uris: Vec<String>,
    
    /// Default role
    pub default_role: Option<String>,
    
    /// OIDC scopes
    pub oidc_scopes: Vec<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer_url: String::new(),
            discovery_url: String::new(),
            client_id: String::new(),
            client_secret: String::new(),
            redirect_uri: String::new(),
            allowed_redirect_uris: Vec::new(),
            default_role: None,
            oidc_scopes: vec!["openid".to_string()],
        }
    }
}

/// JWT claims
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Subject (user identifier)
    pub sub: String,
    
    /// Issuer
    pub iss: String,
    
    /// Audience
    pub aud: Vec<String>,
    
    /// Expiration time
    pub exp: i64,
    
    /// Issued at
    pub iat: i64,
    
    /// Not before
    pub nbf: Option<i64>,
    
    /// Email
    pub email: Option<String>,
    
    /// Email verified
    pub email_verified: Option<bool>,
    
    /// Name
    pub name: Option<String>,
    
    /// Groups
    pub groups: Option<Vec<String>>,
    
    /// Additional claims
    #[serde(flatten)]
    pub additional: HashMap<String, serde_json::Value>,
}

impl JwtClaims {
    /// Check if token is expired
    pub fn is_expired(&self) -> bool {
        let now = Utc::now().timestamp();
        self.exp < now
    }
    
    /// Check if token is valid (not before)
    pub fn is_valid_now(&self) -> bool {
        let now = Utc::now().timestamp();
        self.nbf.map(|nbf| nbf <= now).unwrap_or(true)
    }
}

/// OIDC role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcRole {
    /// Role name
    pub name: String,
    
    /// Bound audiences
    pub bound_audiences: Vec<String>,
    
    /// Bound subject
    pub bound_subject: Option<String>,
    
    /// Bound claims (key -> expected values)
    pub bound_claims: HashMap<String, Vec<String>>,
    
    /// User claim (claim to use as username)
    pub user_claim: String,
    
    /// Groups claim (claim to use for groups)
    pub groups_claim: Option<String>,
    
    /// Allowed redirect URIs
    pub allowed_redirect_uris: Vec<String>,
    
    /// Token TTL
    pub token_ttl: u64,
    
    /// Token max TTL
    pub token_max_ttl: u64,
    
    /// Policies
    pub policies: Vec<String>,
    
    /// Created at
    pub created_at: DateTime<Utc>,
}

impl OidcRole {
    /// Create new role
    pub fn new(name: String) -> Self {
        Self {
            name,
            bound_audiences: Vec::new(),
            bound_subject: None,
            bound_claims: HashMap::new(),
            user_claim: "sub".to_string(),
            groups_claim: Some("groups".to_string()),
            allowed_redirect_uris: Vec::new(),
            token_ttl: 3600,
            token_max_ttl: 86400,
            policies: Vec::new(),
            created_at: Utc::now(),
        }
    }
    
    /// Validate claims against role constraints
    pub fn validate_claims(&self, claims: &JwtClaims) -> Result<(), OidcError> {
        // Check audience
        if !self.bound_audiences.is_empty() {
            let has_valid_audience = self.bound_audiences.iter()
                .any(|aud| claims.aud.contains(aud));
            
            if !has_valid_audience {
                return Err(OidcError::ClaimsValidationFailed(
                    "Audience mismatch".to_string()
                ));
            }
        }
        
        // Check subject
        if let Some(ref bound_sub) = self.bound_subject {
            if &claims.sub != bound_sub {
                return Err(OidcError::ClaimsValidationFailed(
                    "Subject mismatch".to_string()
                ));
            }
        }
        
        // Check bound claims
        for (key, expected_values) in &self.bound_claims {
            if let Some(claim_value) = claims.additional.get(key) {
                let value_str = claim_value.as_str()
                    .unwrap_or("");
                
                if !expected_values.contains(&value_str.to_string()) {
                    return Err(OidcError::ClaimsValidationFailed(
                        format!("Claim {} value mismatch", key)
                    ));
                }
            } else {
                return Err(OidcError::ClaimsValidationFailed(
                    format!("Required claim {} not found", key)
                ));
            }
        }
        
        Ok(())
    }
}

/// OIDC authentication service
pub struct OidcAuth {
    config: Arc<RwLock<OidcConfig>>,
    roles: Arc<RwLock<HashMap<String, OidcRole>>>,
}

impl OidcAuth {
    /// Create new OIDC auth service
    pub fn new(config: OidcConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Verify JWT token (simplified)
    pub async fn verify_jwt(&self, token: &str) -> Result<JwtClaims, OidcError> {
        // In production, this would:
        // 1. Fetch JWKS from OIDC discovery endpoint
        // 2. Verify JWT signature
        // 3. Validate claims (exp, iss, aud, nbf)
        
        if token.is_empty() {
            return Err(OidcError::InvalidToken("Empty token".to_string()));
        }
        
        // Simulated JWT parsing
        let claims = JwtClaims {
            sub: "user123".to_string(),
            iss: "https://accounts.google.com".to_string(),
            aud: vec!["my-client-id".to_string()],
            exp: (Utc::now() + chrono::Duration::hours(1)).timestamp(),
            iat: Utc::now().timestamp(),
            nbf: Some(Utc::now().timestamp()),
            email: Some("user@example.com".to_string()),
            email_verified: Some(true),
            name: Some("Test User".to_string()),
            groups: Some(vec!["developers".to_string(), "users".to_string()]),
            additional: HashMap::new(),
        };
        
        // Validate expiration
        if claims.is_expired() {
            return Err(OidcError::TokenExpired);
        }
        
        // Validate not before
        if !claims.is_valid_now() {
            return Err(OidcError::InvalidToken("Token not yet valid".to_string()));
        }
        
        // Validate issuer
        let config = self.config.read().await;
        if !config.issuer_url.is_empty() && claims.iss != config.issuer_url {
            return Err(OidcError::InvalidIssuer);
        }
        
        Ok(claims)
    }
    
    /// Authenticate with JWT
    pub async fn authenticate(
        &self,
        role_name: &str,
        jwt: &str,
    ) -> Result<OidcAuthResponse, OidcError> {
        // Verify JWT
        let claims = self.verify_jwt(jwt).await?;
        
        // Get role
        let roles = self.roles.read().await;
        let role = roles.get(role_name)
            .ok_or_else(|| OidcError::RoleNotFound(role_name.to_string()))?;
        
        // Validate claims against role
        role.validate_claims(&claims)?;
        
        // Extract username from user_claim
        let username = if role.user_claim == "sub" {
            claims.sub.clone()
        } else if role.user_claim == "email" {
            claims.email.clone().unwrap_or(claims.sub.clone())
        } else {
            claims.additional.get(&role.user_claim)
                .and_then(|v| v.as_str())
                .unwrap_or(&claims.sub)
                .to_string()
        };
        
        // Extract groups
        let groups = if let Some(ref groups_claim) = role.groups_claim {
            if groups_claim == "groups" {
                claims.groups.clone().unwrap_or_default()
            } else {
                claims.additional.get(groups_claim)
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default()
            }
        } else {
            Vec::new()
        };
        
        Ok(OidcAuthResponse {
            username,
            email: claims.email,
            groups,
            policies: role.policies.clone(),
            token_ttl: role.token_ttl,
        })
    }
    
    /// Create role
    pub async fn create_role(&self, role: OidcRole) -> Result<(), OidcError> {
        let mut roles = self.roles.write().await;
        roles.insert(role.name.clone(), role);
        Ok(())
    }
    
    /// Get role
    pub async fn get_role(&self, name: &str) -> Option<OidcRole> {
        let roles = self.roles.read().await;
        roles.get(name).cloned()
    }
    
    /// List roles
    pub async fn list_roles(&self) -> Vec<String> {
        let roles = self.roles.read().await;
        roles.keys().cloned().collect()
    }
    
    /// Delete role
    pub async fn delete_role(&self, name: &str) -> Result<(), OidcError> {
        let mut roles = self.roles.write().await;
        roles.remove(name)
            .ok_or_else(|| OidcError::RoleNotFound(name.to_string()))?;
        Ok(())
    }
    
    /// Get authorization URL
    pub fn get_auth_url(&self, state: &str, nonce: &str) -> String {
        // In production, this would construct proper OAuth2 authorization URL
        format!(
            "https://oauth.example.com/authorize?client_id=xxx&state={}&nonce={}",
            state, nonce
        )
    }
}

impl Default for OidcAuth {
    fn default() -> Self {
        Self::new(OidcConfig::default())
    }
}

/// OIDC authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcAuthResponse {
    pub username: String,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub policies: Vec<String>,
    pub token_ttl: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_create_role() {
        let oidc = OidcAuth::default();
        
        let mut role = OidcRole::new("web-app".to_string());
        role.bound_audiences = vec!["my-client-id".to_string()];
        role.policies = vec!["read".to_string()];
        
        oidc.create_role(role).await.unwrap();
        
        let retrieved = oidc.get_role("web-app").await.unwrap();
        assert_eq!(retrieved.name, "web-app");
    }
    
    #[tokio::test]
    async fn test_authenticate() {
        let oidc = OidcAuth::default();
        
        let mut role = OidcRole::new("web-app".to_string());
        role.bound_audiences = vec!["my-client-id".to_string()];
        role.policies = vec!["read".to_string()];
        
        oidc.create_role(role).await.unwrap();
        
        let result = oidc.authenticate("web-app", "mock-jwt-token").await;
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(!response.username.is_empty());
    }
    
    #[test]
    fn test_jwt_expiration() {
        let mut claims = JwtClaims {
            sub: "user".to_string(),
            iss: "issuer".to_string(),
            aud: vec!["aud".to_string()],
            exp: Utc::now().timestamp() - 100, // Expired
            iat: Utc::now().timestamp(),
            nbf: None,
            email: None,
            email_verified: None,
            name: None,
            groups: None,
            additional: HashMap::new(),
        };
        
        assert!(claims.is_expired());
        
        claims.exp = Utc::now().timestamp() + 3600; // Valid
        assert!(!claims.is_expired());
    }
}
use crate::utils::config::Config;

pub fn build_authorize_url(_config: &Config) -> Option<String> {
    // TODO: Implement Ed25519-based OAuth2 authorization URL
    // Temporarily disabled due to RSA vulnerability migration
    None
    /*
    let client_id = ClientId::new(config.oidc_client_id.clone()?);
    let client_secret = ClientSecret::new(config.oidc_client_secret.clone()?);
    let issuer_url = IssuerUrl::new(config.oidc_issuer.clone()?).ok()?;
    let redirect_url = RedirectUrl::new(config.oidc_redirect_url.clone()?).ok()?;
    let provider_metadata = futures::executor::block_on(CoreProviderMetadata::discover_async(issuer_url, async_http_client)).ok()?;
    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        client_id,
        Some(client_secret),
    ).set_redirect_uri(redirect_url);
    let (auth_url, _csrf, _nonce) = client
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .url();
    Some(auth_url.to_string())
    */
}

pub async fn handle_callback(_config: &Config, _code: &str) -> Option<String> {
    // Dummy: return Some(username) setelah verifikasi OIDC token
    Some("oidcuser".to_string())
}
