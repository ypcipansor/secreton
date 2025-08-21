use openidconnect::{ClientId, ClientSecret, IssuerUrl, RedirectUrl, AuthenticationFlow, AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, Scope, TokenResponse, reqwest::async_http_client, core::{CoreProviderMetadata, CoreClient, CoreAuthenticationFlow}};
use crate::utils::config::Config;

pub fn build_authorize_url(config: &Config) -> Option<String> {
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
}

pub async fn handle_callback(_config: &Config, _code: &str) -> Option<String> {
    // Dummy: return Some(username) setelah verifikasi OIDC token
    Some("oidcuser".to_string())
} 