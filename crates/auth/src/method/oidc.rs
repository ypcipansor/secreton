//! OIDC authentication method

use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::Utc;
use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};
use oauth2::{AuthorizationCode, CsrfToken, PkceCodeChallenge, PkceCodeVerifier, Scope};
use reqwest::Client;
use secreton_domain::SecretonError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Type alias for OIDC client with auth and token endpoints set
type OidcClient = oauth2::Client<
    oauth2::StandardErrorResponse<oauth2::basic::BasicErrorResponseType>,
    oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
    oauth2::StandardTokenIntrospectionResponse<
        oauth2::EmptyExtraTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    oauth2::StandardRevocableToken,
    oauth2::StandardErrorResponse<oauth2::RevocationErrorResponseType>,
    oauth2::EndpointSet,    // HasAuthUrl
    oauth2::EndpointNotSet, // HasDeviceAuthUrl
    oauth2::EndpointNotSet, // HasIntrospectionUrl
    oauth2::EndpointNotSet, // HasRevocationUrl
    oauth2::EndpointSet,    // HasTokenUrl
>;

/// OIDC authentication method
pub struct OidcAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    oidc_config: Option<OidcClientConfig>,
    client: Option<OidcClient>,
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

    /// Set OIDC configuration.
    ///
    /// Returns an error rather than panicking on a malformed URL. These three values come
    /// from operator configuration, so a typo in `auth_url` used to take the process down
    /// on startup — the one moment an operator has the least information to diagnose it.
    pub fn set_oidc_config(&mut self, config: OidcClientConfig) -> AuthMethodResult<()> {
        let invalid = |field: &str, e: url::ParseError| SecretonError::Configuration {
            message: format!("OIDC {field} is not a valid URL: {e}"),
        };

        let auth_uri = AuthUrl::new(config.auth_url.clone()).map_err(|e| invalid("auth_url", e))?;
        let token_uri =
            TokenUrl::new(config.token_url.clone()).map_err(|e| invalid("token_url", e))?;
        let redirect_uri = RedirectUrl::new(config.redirect_url.clone())
            .map_err(|e| invalid("redirect_url", e))?;

        self.client = Some(
            BasicClient::new(ClientId::new(config.client_id.clone()))
                .set_client_secret(ClientSecret::new(config.client_secret.clone()))
                .set_auth_uri(auth_uri)
                .set_token_uri(token_uri)
                .set_redirect_uri(redirect_uri),
        );
        self.oidc_config = Some(config);
        Ok(())
    }

    /// Start OIDC authentication flow
    pub async fn start_auth(&self) -> AuthMethodResult<OidcAuthUrl> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| SecretonError::Configuration {
                message: "OIDC client not configured".to_string(),
            })?;

        // Generate PKCE challenge
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        // Generate authorization URL
        let (auth_url, csrf_token) = client
            .authorize_url(CsrfToken::new_random)
            .add_scopes(vec![
                Scope::new("openid".to_string()),
                Scope::new("profile".to_string()),
                Scope::new("email".to_string()),
            ])
            .set_pkce_challenge(pkce_challenge)
            .url();

        Ok(OidcAuthUrl {
            url: auth_url.to_string(),
            state: csrf_token.secret().to_string(),
            pkce_verifier: pkce_verifier.secret().to_string(),
        })
    }

    /// Complete OIDC authentication
    pub async fn complete_auth(
        &self,
        code: &str,
        state: &str,
        stored_state: &str,
        pkce_verifier: &str,
    ) -> AuthMethodResult<AuthResult> {
        let client = self
            .client
            .as_ref()
            .ok_or_else(|| SecretonError::Configuration {
                message: "OIDC client not configured".to_string(),
            })?;

        // Verify state
        if state != stored_state {
            return Err(SecretonError::InvalidCredentials);
        }

        // Exchange code for token
        let _token_result = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(PkceCodeVerifier::new(pkce_verifier.to_string()))
            .request_async(&Client::new())
            .await
            .map_err(|e| SecretonError::Authentication {
                message: format!("OIDC token exchange failed: {e}"),
            })?;

        // Token exchange successful - create user from OIDC provider
        // In production, you would call the userinfo endpoint with the access token
        let user_info = UserInfo {
            id: Some(Uuid::new_v4().to_string()),
            username: format!("oidc_user_{}", Uuid::new_v4()),
            email: None,
            display_name: None,
            metadata: {
                let mut m = HashMap::new();
                m.insert("auth_method".to_string(), "oidc".to_string());
                m
            },
            last_login: Some(Utc::now()),
            roles: vec![],
            permissions: vec![],
        };

        Ok(AuthResult {
            success: true,
            user_info: Some(user_info),
            mfa_required: false,
            policies: vec![],
            metadata: HashMap::new(),
            token: Some(format!("oidc_token_{}", Uuid::new_v4())),
            refresh_token: None,
        })
    }
}

impl Default for OidcAuthMethod {
    fn default() -> Self {
        Self::new()
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
        if let (
            Some(client_id),
            Some(client_secret),
            Some(auth_url),
            Some(token_url),
            Some(redirect_url),
        ) = (
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
                scopes: config
                    .config
                    .get("scopes")
                    .and_then(|v| v.as_str())
                    .unwrap_or("openid profile email")
                    .to_string(),
            };
            // Propagated: a malformed URL in the auth-method configuration must fail
            // initialisation, not be discarded so the method appears enabled with no
            // client behind it.
            self.set_oidc_config(oidc_config)?;
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, _credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        // OIDC authentication requires a multi-step flow
        // This method should not be called directly for OIDC
        Err(SecretonError::AuthMethodNotSupported)
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(SecretonError::AuthMethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(SecretonError::AuthMethodNotSupported)
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
