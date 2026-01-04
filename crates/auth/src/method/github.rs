//! GitHub authentication method

use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::Utc;
use reqwest::Client;
use secreton_errors::SecretonError;
use serde::Deserialize;
use std::collections::HashMap;

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

    pub fn set_github_config(&mut self, config: GithubConfig) {
        self.github_config = Some(config);
    }

    /// Generate GitHub OAuth authorization URL
    pub fn get_authorization_url(&self, state: &str) -> AuthMethodResult<String> {
        if let Some(config) = &self.github_config {
            let url = format!(
                "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=user:email&state={}",
                config.client_id,
                urlencoding::encode(&config.redirect_url),
                urlencoding::encode(state)
            );
            Ok(url)
        } else {
            Err(SecretonError::Configuration {
                message: "GitHub authentication is not configured".to_string(),
            })
        }
    }

    /// Exchange authorization code for access token
    pub async fn exchange_code_for_token(
        &self,
        code: &str,
        state: &str,
    ) -> AuthMethodResult<GithubTokenResponse> {
        if let Some(config) = &self.github_config {
            let params = [
                ("client_id", config.client_id.as_str()),
                ("client_secret", config.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", config.redirect_url.as_str()),
                ("state", state),
            ];

            let response = self
                .http_client
                .post("https://github.com/login/oauth/access_token")
                .header("Accept", "application/json")
                .form(&params)
                .send()
                .await
                .map_err(|err| SecretonError::Network {
                    message: format!("Failed to exchange GitHub code for token: {err}"),
                })?;

            if !response.status().is_success() {
                return Err(SecretonError::Authentication {
                    message: format!(
                        "GitHub token exchange failed with status {}",
                        response.status()
                    ),
                });
            }

            let token_response: GithubTokenResponse =
                response.json().await.map_err(|err| SecretonError::Parse {
                    message: format!("Failed to parse GitHub token response: {err}"),
                })?;

            if let Some(error) = token_response.error.as_ref() {
                return Err(SecretonError::Authentication {
                    message: format!(
                        "GitHub token exchange returned error: {}",
                        token_response.error_description.as_ref().unwrap_or(error)
                    ),
                });
            }

            Ok(token_response)
        } else {
            Err(SecretonError::Configuration {
                message: "GitHub authentication is not configured".to_string(),
            })
        }
    }

    /// Get user information from GitHub API
    pub async fn get_user_info(&self, access_token: &str) -> AuthMethodResult<GithubUser> {
        let response = self
            .http_client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton-Auth")
            .send()
            .await
            .map_err(|err| SecretonError::Network {
                message: format!("Failed to request GitHub user info: {err}"),
            })?;

        let user_info: GithubUser = response.json().await.map_err(|err| SecretonError::Parse {
            message: format!("Failed to parse GitHub user info response: {err}"),
        })?;

        Ok(user_info)
    }

    /// Validate user against allowed organizations/teams
    pub async fn validate_user_access(
        &self,
        _user_info: &GithubUser,
        access_token: &str,
    ) -> AuthMethodResult<bool> {
        if let Some(config) = &self.github_config {
            // Check organizations if specified
            if !config.allowed_organizations.is_empty() {
                let user_orgs = self.get_user_organizations(access_token).await?;
                let has_access = user_orgs
                    .iter()
                    .any(|org| config.allowed_organizations.contains(&org.login));
                if !has_access {
                    return Ok(false);
                }
            }

            // Check teams if specified
            if !config.allowed_teams.is_empty() {
                let user_teams = self.get_user_teams(access_token).await?;
                let has_access = user_teams.iter().any(|team| {
                    config
                        .allowed_teams
                        .contains(&format!("{}:{}", team.organization.login, team.name))
                });
                if !has_access {
                    return Ok(false);
                }
            }

            Ok(true)
        } else {
            Err(SecretonError::Configuration {
                message: "GitHub authentication is not configured".to_string(),
            })
        }
    }

    /// Get user organizations
    async fn get_user_organizations(&self, access_token: &str) -> AuthMethodResult<Vec<GithubOrg>> {
        let response = self
            .http_client
            .get("https://api.github.com/user/orgs")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton-Auth")
            .send()
            .await
            .map_err(|err| SecretonError::Network {
                message: format!("Failed to request GitHub organizations: {err}"),
            })?;

        let orgs: Vec<GithubOrg> = response.json().await.map_err(|err| SecretonError::Parse {
            message: format!("Failed to parse GitHub organizations response: {err}"),
        })?;

        Ok(orgs)
    }

    /// Get user teams
    async fn get_user_teams(&self, access_token: &str) -> AuthMethodResult<Vec<GithubTeam>> {
        let response = self
            .http_client
            .get("https://api.github.com/user/teams")
            .header("Authorization", format!("Bearer {}", access_token))
            .header("User-Agent", "Secreton-Auth")
            .send()
            .await
            .map_err(|err| SecretonError::Network {
                message: format!("Failed to request GitHub teams: {err}"),
            })?;

        let teams: Vec<GithubTeam> = response.json().await.map_err(|err| SecretonError::Parse {
            message: format!("Failed to parse GitHub teams response: {err}"),
        })?;

        Ok(teams)
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
            config.config.get("client_id").and_then(|v| v.as_str()),
            config.config.get("client_secret").and_then(|v| v.as_str()),
        ) {
            let github_config = GithubConfig {
                client_id: client_id.to_string(),
                client_secret: client_secret.to_string(),
                redirect_url: config
                    .config
                    .get("redirect_url")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "http://localhost:8080/auth/github/callback".to_string()),
                allowed_organizations: config
                    .config
                    .get("allowed_organizations")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
                allowed_teams: config
                    .config
                    .get("allowed_teams")
                    .and_then(|v| v.as_str())
                    .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
                    .unwrap_or_default(),
            };
            self.set_github_config(github_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        match credentials {
            AuthCredentials::OAuth2 { code, state } => {
                let token_response = self.exchange_code_for_token(code, state).await?;

                let access_token =
                    token_response
                        .access_token
                        .ok_or_else(|| SecretonError::Authentication {
                            message: "GitHub token response did not include an access token"
                                .to_string(),
                        })?;

                let user_info = self.get_user_info(&access_token).await?;

                let has_access = self.validate_user_access(&user_info, &access_token).await?;

                if !has_access {
                    return Err(SecretonError::Authorization {
                        message: "GitHub user is not in an allowed organization or team"
                            .to_string(),
                    });
                }

                let mut user_metadata = HashMap::new();
                if let Some(avatar) = &user_info.avatar_url {
                    user_metadata.insert("avatar_url".to_string(), avatar.clone());
                }
                if let Some(company) = &user_info.company {
                    user_metadata.insert("company".to_string(), company.clone());
                }
                if let Some(location) = &user_info.location {
                    user_metadata.insert("location".to_string(), location.clone());
                }

                let user = UserInfo {
                    id: Some(user_info.id.to_string()),
                    username: user_info.login.clone(),
                    email: user_info.email.clone(),
                    display_name: user_info.name.clone(),
                    roles: vec![], // GitHub roles need mapping
                    permissions: vec![],
                    metadata: user_metadata,
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    success: true,
                    user_info: Some(user),
                    token: Some(access_token),
                    policies: Vec::new(),
                    metadata: HashMap::new(),
                    mfa_required: false,
                })
            }
            _ => Err(SecretonError::InvalidCredentials),
        }
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
    pub organization: GithubOrg,
}
