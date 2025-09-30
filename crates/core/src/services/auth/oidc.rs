// Temporarily disabled OIDC due to RSA vulnerability
// Will be replaced with Ed25519-based OAuth2 implementation

use crate::error::{CoreError, SecretonResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OidcClaims {
    pub sub: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub exp: i64,
    pub iat: i64,
}

// Placeholder implementation - will be replaced with Ed25519-based auth
#[allow(dead_code)]
pub struct OidcService {
    config: OidcConfig,
}

impl OidcService {
    pub fn new(config: OidcConfig) -> Self {
        Self { config }
    }

    pub async fn verify_token(&self, _token: &str) -> SecretonResult<OidcClaims> {
        // TODO: Implement Ed25519-based token verification
        Err(CoreError::Authentication {
            message: "OIDC temporarily disabled for security migration".into(),
        }
        .into())
    }

    pub fn get_auth_url(&self, _state: &str, _nonce: &str) -> SecretonResult<String> {
        // TODO: Implement Ed25519-based OAuth2 flow
        Err(CoreError::Authentication {
            message: "OIDC temporarily disabled for security migration".into(),
        }
        .into())
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
