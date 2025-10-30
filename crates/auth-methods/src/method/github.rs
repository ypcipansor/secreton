//! GitHub authentication method

use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// GitHub authentication method
pub struct GithubAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    github_config: Option<GithubConfig>,
    http_client: Client,
}

impl GithubAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            github_config: None,
            http_client: Client::new(),
        }
    }

    /// Set GitHub configuration
    pub fn set_github_config(&mut self, config: GithubConfig) {
        self.github_config = Some(config);
    }
}

#[async_trait]
impl AuthMethodImpl for GithubAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Github
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse GitHub configuration from config
        if let (Some(client_id), Some(client_secret)) = (
            config.config.get("client_id"),
            config.config.get("client_secret"),
        ) {
            let github_config = GithubConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_url: config.config.get("redirect_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "http://localhost:8080/auth/github/callback".to_string()),
                allowed_organizations: config.config.get("allowed_organizations")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                allowed_teams: config.config.get("allowed_teams")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
            };
            self.set_github_config(github_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, _credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        // GitHub authentication requires OAuth flow
        // This method should not be called directly for GitHub
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

/// GitHub configuration
#[derive(Clone, Debug)]
pub struct GithubConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub allowed_organizations: Vec<String>,
    pub allowed_teams: Vec<String>,
}

/// GitHub OAuth token response
#[derive(Clone, Debug, Deserialize)]
pub struct GithubTokenResponse {
    pub access_token: Option<String>,
    pub token_type: Option<String>,
    pub scope: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GitHub user information
#[derive(Clone, Debug, Deserialize)]
pub struct GithubUser {
    pub id: u64,
    pub login: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub company: Option<String>,
    pub location: Option<String>,
}

/// GitHub organization
#[derive(Clone, Debug, Deserialize)]
pub struct GithubOrg {
    pub id: u64,
    pub login: String,
    pub url: String,
    pub avatar_url: Option<String>,
}

/// GitHub team
#[derive(Clone, Debug, Deserialize)]
pub struct GithubTeam {
    pub id: u64,
    pub name: String,
    pub slug: String,
    pub description: Option<String>,
    pub privacy: String,
    pub url: String,
}