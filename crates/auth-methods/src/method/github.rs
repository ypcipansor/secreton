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

    /// Exchange code for access token
    async fn exchange_code(&self, code: &str) -> AuthMethodResult<String> {
        let config = self.github_config.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("GitHub config not set".to_string()))?;

        let params = [
            ("client_id", &config.client_id),
            ("client_secret", &config.client_secret),
            ("code", &code.to_string()),
        ];

        let response = self.http_client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Token exchange failed: {}", e)))?;

        let token_response: GithubTokenResponse = response
            .json()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Failed to parse token response: {}", e)))?;

        if let Some(error) = token_response.error {
            return Err(AuthMethodError::GithubError(format!("OAuth error: {}", error)));
        }

        token_response.access_token
            .ok_or(AuthMethodError::GithubError("No access token received".to_string()))
    }

    /// Get user information from GitHub API
    async fn get_user_info(&self, access_token: &str) -> AuthMethodResult<GithubUser> {
        let response = self.http_client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton")
            .send()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("User info request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::GithubError(format!("GitHub API error: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Failed to parse user response: {}", e)))
    }

    /// Get user organizations
    async fn get_user_orgs(&self, access_token: &str) -> AuthMethodResult<Vec<GithubOrg>> {
        let response = self.http_client
            .get("https://api.github.com/user/orgs")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton")
            .send()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Orgs request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::GithubError(format!("GitHub API error: {}", response.status())));
        }

        response
            .json()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Failed to parse orgs response: {}", e)))
    }

    /// Get user teams for an organization
    async fn get_user_teams(&self, access_token: &str, org: &str) -> AuthMethodResult<Vec<GithubTeam>> {
        let url = format!("https://api.github.com/orgs/{}/teams", org);
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton")
            .send()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Teams request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AuthMethodError::GithubError(format!("GitHub API error: {}", response.status())));
        }

        let teams: Vec<GithubTeam> = response
            .json()
            .await
            .map_err(|e| AuthMethodError::GithubError(format!("Failed to parse teams response: {}", e)))?;

        // Filter teams where user is a member
        let mut user_teams = Vec::new();
        for team in teams {
            let membership_url = format!("https://api.github.com/orgs/{}/teams/{}/memberships/{}", org, team.slug, team.slug);
            let membership_response = self.http_client
                .get(&membership_url)
                .header("Authorization", format!("Bearer {}", access_token))
                .header("User-Agent", "Secreton")
                .send()
                .await;

            if let Ok(resp) = membership_response {
                if resp.status().is_success() {
                    user_teams.push(team);
                }
            }
        }

        Ok(user_teams)
    }

    /// Validate organization membership
    fn validate_org_membership(&self, user_orgs: &[GithubOrg], allowed_orgs: &[String]) -> bool {
        if allowed_orgs.is_empty() {
            return true; // No org restrictions
        }

        user_orgs.iter().any(|org| allowed_orgs.contains(&org.login))
    }

    /// Validate team membership
    fn validate_team_membership(&self, user_teams: &[GithubTeam], allowed_teams: &[String]) -> bool {
        if allowed_teams.is_empty() {
            return true; // No team restrictions
        }

        user_teams.iter().any(|team| allowed_teams.contains(&team.slug))
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