//! OIDC authentication method

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use oauth2::basic::BasicClient;
use oauth2::reqwest::async_http_client;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use serde::{Deserialize, Serialize};
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// OIDC authentication method
pub struct OidcAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    oidc_config: Option<OidcClientConfig>,
    client: Option<BasicClient>,
}

impl OidcAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            oidc_config: None,
            client: None,
        }
    }

    /// Set OIDC configuration
    pub fn set_oidc_config(&mut self, config: OidcClientConfig) {
        // Build OAuth2 client first before moving config
        let client = BasicClient::new(
            ClientId::new(config.client_id.clone()),
            Some(ClientSecret::new(config.client_secret.clone())),
            AuthUrl::new(config.auth_url.clone()).expect("Invalid auth URL"),
            Some(TokenUrl::new(config.token_url.clone()).expect("Invalid token URL")),
        )
        .set_redirect_uri(RedirectUrl::new(config.redirect_url.clone()).expect("Invalid redirect URL"));

        self.client = Some(client);
        self.oidc_config = Some(config);
    }

    /// Start OIDC authentication flow
    pub async fn start_auth(&self) -> AuthMethodResult<OidcAuthUrl> {
        let client = self.client.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("OIDC client not configured".to_string()))?;

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate authorization URL
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scope(Scope::new("openid".to_string()))
            .add_scope(Scope::new("profile".to_string()))
            .add_scope(Scope::new("email".to_string()))
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(OidcAuthUrl {
            url: auth_url.to_string(),
            state: csrf_token.secret().to_string(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        })
    }

    /// Complete OIDC authentication
    pub async fn complete_auth(&self, code: &str, state: &str, stored_state: &str, pkce_verifier: &str) -> AuthMethodResult<AuthResult> {
        let client = self.client.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("OIDC client not configured".to_string()))?;

        // Verify state
        if state != stored_state {
            return Err(AuthMethodError::InvalidCredentials("OIDC state mismatch".to_string()));
        }

        // Exchange code for token
        let _token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(async_http_client)
            .await
            .map_err(|e| AuthMethodError::OidcError(format!("Token exchange failed: {}", e)))?;

        // Get user info from userinfo endpoint
        // TODO: Parse ID token claims when oauth2 crate supports it
        let claims_str = "{}"; // Placeholder
        let claims: OidcClaims = serde_json::from_str(claims_str)
            .map_err(|e| AuthMethodError::OidcError(format!("Failed to parse claims: {}", e)))?;

        let user_info = UserInfo {
            id: Uuid::new_v4(),
            username: claims.preferred_username.unwrap_or_else(|| claims.sub.to_string()),
            email: claims.email,
            display_name: claims.name,
            groups: claims.groups.unwrap_or_default(),
            metadata: HashMap::new(),
            created_at: Utc::now(),
            last_login: Some(Utc::now()),
        };

        Ok(AuthResult {
            authenticated: true,
            user_info: Some(user_info),
            token: None,
            mfa_required: false,
            policies: vec![],
            lease_duration: None,
            renewable: Some(true),
            metadata: HashMap::new(),
            accessor: None,
            mfa_methods: vec![],
        })
    }
}

#[async_trait]
impl AuthMethodImpl for OidcAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Oidc
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse OIDC configuration from config
        if let (Some(client_id), Some(client_secret), Some(auth_url), Some(token_url), Some(redirect_url)) = (
            config.config.get("client_id").and_then(|v| v.as_str()),
            config.config.get("client_secret").and_then(|v| v.as_str()),
            config.config.get("auth_url").and_then(|v| v.as_str()),
            config.config.get("token_url").and_then(|v| v.as_str()),
            config.config.get("redirect_url").and_then(|v| v.as_str()),
        ) {
            let oidc_config = OidcClientConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                auth_url: auth_url.to_string(),
                token_url: token_url.to_string(),
                redirect_url: redirect_url.to_string(),
                scopes: config.config.get("scopes")
                    .and_then(|v| v.as_str())
                    .unwrap_or("openid profile email")
                    .to_string(),
            };
            self.set_oidc_config(oidc_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, _credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        // OIDC authentication requires a multi-step flow
        // This method should not be called directly for OIDC
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(AuthMethodError::MethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// OIDC client configuration (for OAuth2 setup)
#[derive(Clone, Debug)]
pub struct OidcClientConfig {
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub redirect_url: String,
    pub scopes: String,
}

/// OIDC authorization URL response
#[derive(Clone, Debug)]
pub struct OidcAuthUrl {
    pub url: String,
    pub state: String,
    pub pkce_verifier: String,
}

/// OIDC ID token claims
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OidcClaims {
    pub sub: String,
    pub preferred_username: Option<String>,
    pub email: Option<String>,
    pub groups: Option<Vec<String>>,
    pub name: Option<String>,
}