use crate::auth::traits::{AuthMethod, AuthResult};
use crate::error::CoreError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// GitHub authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAuthConfig {
    /// GitHub organization name
    pub organization: String,
    /// Base URL for GitHub API (for GitHub Enterprise)
    pub base_url: String,
    /// Allowed teams (optional)
    pub allowed_teams: Vec<String>,
    /// Token TTL in seconds
    pub ttl: i64,
}

impl Default for GitHubAuthConfig {
    fn default() -> Self {
        Self {
            organization: String::new(),
            base_url: "https://api.github.com".to_string(),
            allowed_teams: Vec::new(),
            ttl: 3600,
        }
    }
}

/// GitHub user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUser {
    pub login: String,
    pub id: u64,
    pub name: Option<String>,
    pub email: Option<String>,
    pub teams: Vec<String>,
}

/// GitHub authentication method
pub struct GitHubAuth {
    config: GitHubAuthConfig,
    client: reqwest::Client,
}

impl GitHubAuth {
    /// Create new GitHub authentication method
    pub fn new(config: GitHubAuthConfig) -> Result<Self, CoreError> {
        let client = reqwest::Client::builder()
            .user_agent("Secreton-Vault/1.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CoreError::configuration(format!("Failed to create HTTP client: {}", e)))?;

        Ok(Self { config, client })
    }

    /// Verify GitHub personal access token
    async fn verify_token(&self, token: &str) -> Result<GitHubUser, CoreError> {
        let url = format!("{}/user", self.config.base_url);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::authentication(format!("Failed to verify GitHub token: {}", e)))?;

        if !response.status().is_success() {
            return Err(CoreError::authentication("Invalid GitHub token"));
        }

        #[derive(Deserialize)]
        struct GitHubUserResponse {
            login: String,
            id: u64,
            name: Option<String>,
            email: Option<String>,
        }

        let user_data: GitHubUserResponse = response.json().await
            .map_err(|e| CoreError::authentication(format!("Failed to parse GitHub response: {}", e)))?;

        // Get user's teams
        let teams = self.get_user_teams(&user_data.login, token).await?;

        Ok(GitHubUser {
            login: user_data.login,
            id: user_data.id,
            name: user_data.name,
            email: user_data.email,
            teams,
        })
    }

    /// Get user's teams in the organization
    async fn get_user_teams(&self, username: &str, token: &str) -> Result<Vec<String>, CoreError> {
        let url = format!("{}/orgs/{}/teams", self.config.base_url, self.config.organization);
        
        let response = self.client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::authentication(format!("Failed to get teams: {}", e)))?;

        if !response.status().is_success() {
            return Ok(Vec::new());
        }

        #[derive(Deserialize)]
        struct Team {
            name: String,
        }

        let teams: Vec<Team> = response.json().await.unwrap_or_default();
        Ok(teams.into_iter().map(|t| t.name).collect())
    }

    /// Check if user is in allowed teams
    fn is_team_allowed(&self, user_teams: &[String]) -> bool {
        if self.config.allowed_teams.is_empty() {
            return true; // No team restrictions
        }

        user_teams.iter().any(|team| self.config.allowed_teams.contains(team))
    }
}

#[async_trait]
impl AuthMethod for GitHubAuth {
    fn method_type(&self) -> &'static str {
        "github"
    }

    async fn authenticate(&self, credentials: HashMap<String, String>) -> Result<AuthResult, CoreError> {
        let token = credentials.get("token")
            .ok_or_else(|| CoreError::authentication("GitHub token required"))?;

        // Verify token and get user info
        let user = self.verify_token(token).await?;

        // Check team membership if configured
        if !self.is_team_allowed(&user.teams) {
            return Err(CoreError::authentication("User is not in allowed teams"));
        }

        // Generate policies based on teams
        let policies = user.teams.iter()
            .map(|team| format!("github-{}", team.to_lowercase()))
            .collect();

        Ok(AuthResult {
            authenticated: true,
            user_id: user.login.clone(),
            username: user.login,
            policies,
            metadata: HashMap::from([
                ("github_id".to_string(), user.id.to_string()),
                ("github_name".to_string(), user.name.unwrap_or_default()),
                ("github_email".to_string(), user.email.unwrap_or_default()),
                ("github_teams".to_string(), user.teams.join(",")),
            ]),
            ttl: self.config.ttl,
        })
    }

    async fn validate_token(&self, _token: &str) -> Result<bool, CoreError> {
        // GitHub tokens are validated during authentication
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_config_default() {
        let config = GitHubAuthConfig::default();
        assert_eq!(config.base_url, "https://api.github.com");
        assert_eq!(config.ttl, 3600);
    }

    #[test]
    fn test_github_auth_creation() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config);
        assert!(auth.is_ok());
    }

    #[test]
    fn test_team_allowed_no_restrictions() {
        let config = GitHubAuthConfig::default();
        let auth = GitHubAuth::new(config).unwrap();
        assert!(auth.is_team_allowed(&["any-team".to_string()]));
    }

    #[test]
    fn test_team_allowed_with_restrictions() {
        let mut config = GitHubAuthConfig::default();
        config.allowed_teams = vec!["team1".to_string(), "team2".to_string()];
        let auth = GitHubAuth::new(config).unwrap();
        
        assert!(auth.is_team_allowed(&["team1".to_string()]));
        assert!(!auth.is_team_allowed(&["team3".to_string()]));
    }
}
