//! GitHub Authentication Method
//!
//! OAuth-based authentication using GitHub personal access tokens with
//! organization and team-based access control.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// GitHub auth errors
#[derive(Debug, thiserror::Error)]
pub enum GitHubAuthError {
    #[error("Invalid token")]
    InvalidToken,
    
    #[error("User not in organization: {0}")]
    NotInOrganization(String),
    
    #[error("No team membership found")]
    NoTeamMembership,
    
    #[error("Team not found: {0}")]
    TeamNotFound(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("API error: {0}")]
    ApiError(String),
}

/// GitHub configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub organization name
    pub organization: String,
    
    /// Base URL for GitHub API (for GitHub Enterprise)
    pub base_url: String,
    
    /// Allowed teams (empty means all teams in org)
    pub allowed_teams: Vec<String>,
    
    /// TTL for generated tokens
    pub ttl: u64,
    
    /// Max TTL
    pub max_ttl: u64,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            organization: String::new(),
            base_url: "https://api.github.com".to_string(),
            allowed_teams: Vec::new(),
            ttl: 3600,
            max_ttl: 86400,
        }
    }
}

/// GitHub team configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubTeam {
    /// Team name or slug
    pub name: String,
    
    /// Policies to attach
    pub policies: Vec<String>,
    
    /// Token TTL override
    pub ttl: Option<u64>,
}

/// GitHub user info (from API)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUser {
    /// Username
    pub login: String,
    
    /// User ID
    pub id: u64,
    
    /// Email
    pub email: Option<String>,
    
    /// Name
    pub name: Option<String>,
}

/// GitHub organization membership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubOrgMembership {
    /// Organization name
    pub organization: String,
    
    /// State (active, pending)
    pub state: String,
    
    /// Role (member, admin)
    pub role: String,
}

/// GitHub team membership
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubTeamMembership {
    /// Team name
    pub team_name: String,
    
    /// Team slug
    pub team_slug: String,
    
    /// Role in team
    pub role: String,
}

/// Authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubAuthResult {
    /// Authenticated user
    pub user: GitHubUser,
    
    /// Organization membership
    pub org_membership: GitHubOrgMembership,
    
    /// Team memberships
    pub team_memberships: Vec<GitHubTeamMembership>,
    
    /// Policies to attach
    pub policies: Vec<String>,
    
    /// Token TTL
    pub ttl: u64,
}

/// GitHub authentication service
pub struct GitHubAuth {
    config: Arc<RwLock<GitHubConfig>>,
    teams: Arc<RwLock<HashMap<String, GitHubTeam>>>,
}

impl GitHubAuth {
    /// Create new GitHub auth service
    pub fn new(config: GitHubConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            teams: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Configure GitHub authentication
    pub async fn configure(&self, config: GitHubConfig) -> Result<(), GitHubAuthError> {
        let mut current = self.config.write().await;
        *current = config;
        Ok(())
    }
    
    /// Create team mapping
    pub async fn create_team(&self, team: GitHubTeam) -> Result<(), GitHubAuthError> {
        let mut teams = self.teams.write().await;
        teams.insert(team.name.clone(), team);
        Ok(())
    }
    
    /// Get team configuration
    pub async fn get_team(&self, name: &str) -> Option<GitHubTeam> {
        let teams = self.teams.read().await;
        teams.get(name).cloned()
    }
    
    /// Authenticate with GitHub token
    pub async fn authenticate(&self, token: &str) -> Result<GitHubAuthResult, GitHubAuthError> {
        if token.is_empty() {
            return Err(GitHubAuthError::InvalidToken);
        }
        
        // Simulate GitHub API calls (production would use actual GitHub API)
        let user = self.get_user_info(token).await?;
        let org_membership = self.verify_org_membership(token, &user).await?;
        let team_memberships = self.get_team_memberships(token, &user).await?;
        
        // Check allowed teams
        let config = self.config.read().await;
        if !config.allowed_teams.is_empty() {
            let has_allowed_team = team_memberships.iter()
                .any(|tm| config.allowed_teams.contains(&tm.team_slug));
            
            if !has_allowed_team {
                return Err(GitHubAuthError::NoTeamMembership);
            }
        }
        
        // Collect policies from team configurations
        let teams_map = self.teams.read().await;
        let mut policies = Vec::new();
        let mut ttl = config.ttl;
        
        for team_membership in &team_memberships {
            if let Some(team_config) = teams_map.get(&team_membership.team_slug) {
                policies.extend(team_config.policies.clone());
                if let Some(team_ttl) = team_config.ttl {
                    ttl = ttl.max(team_ttl);
                }
            }
        }
        
        // Deduplicate policies
        policies.sort();
        policies.dedup();
        
        Ok(GitHubAuthResult {
            user,
            org_membership,
            team_memberships,
            policies,
            ttl,
        })
    }
    
    /// Get user info from GitHub API (simulated)
    async fn get_user_info(&self, _token: &str) -> Result<GitHubUser, GitHubAuthError> {
        // In production, this would call: GET https://api.github.com/user
        Ok(GitHubUser {
            login: "testuser".to_string(),
            id: 12345,
            email: Some("testuser@example.com".to_string()),
            name: Some("Test User".to_string()),
        })
    }
    
    /// Verify organization membership (simulated)
    async fn verify_org_membership(
        &self,
        _token: &str,
        _user: &GitHubUser,
    ) -> Result<GitHubOrgMembership, GitHubAuthError> {
        let config = self.config.read().await;
        
        // In production: GET https://api.github.com/user/memberships/orgs/{org}
        Ok(GitHubOrgMembership {
            organization: config.organization.clone(),
            state: "active".to_string(),
            role: "member".to_string(),
        })
    }
    
    /// Get team memberships (simulated)
    async fn get_team_memberships(
        &self,
        _token: &str,
        _user: &GitHubUser,
    ) -> Result<Vec<GitHubTeamMembership>, GitHubAuthError> {
        // In production: GET https://api.github.com/user/teams
        Ok(vec![
            GitHubTeamMembership {
                team_name: "Developers".to_string(),
                team_slug: "developers".to_string(),
                role: "member".to_string(),
            },
        ])
    }
    
    /// List configured teams
    pub async fn list_teams(&self) -> Vec<String> {
        let teams = self.teams.read().await;
        teams.keys().cloned().collect()
    }
    
    /// Delete team configuration
    pub async fn delete_team(&self, name: &str) -> Result<(), GitHubAuthError> {
        let mut teams = self.teams.write().await;
        teams.remove(name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_github_auth_success() {
        let config = GitHubConfig {
            organization: "test-org".to_string(),
            base_url: "https://api.github.com".to_string(),
            allowed_teams: vec!["developers".to_string()],
            ttl: 3600,
            max_ttl: 86400,
        };
        
        let auth = GitHubAuth::new(config);
        
        let result = auth.authenticate("valid-token").await.unwrap();
        assert_eq!(result.user.login, "testuser");
        assert_eq!(result.org_membership.organization, "test-org");
        assert!(!result.team_memberships.is_empty());
    }
    
    #[tokio::test]
    async fn test_team_policy_mapping() {
        let config = GitHubConfig::default();
        let auth = GitHubAuth::new(config);
        
        let team = GitHubTeam {
            name: "developers".to_string(),
            policies: vec!["dev-policy".to_string(), "read-policy".to_string()],
            ttl: Some(7200),
        };
        
        auth.create_team(team).await.unwrap();
        
        let result = auth.authenticate("valid-token").await.unwrap();
        assert!(result.policies.contains(&"dev-policy".to_string()));
        assert!(result.policies.contains(&"read-policy".to_string()));
        assert_eq!(result.ttl, 7200);
    }
    
    #[tokio::test]
    async fn test_invalid_token() {
        let config = GitHubConfig::default();
        let auth = GitHubAuth::new(config);
        
        let result = auth.authenticate("").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), GitHubAuthError::InvalidToken));
    }
    
    #[tokio::test]
    async fn test_team_management() {
        let config = GitHubConfig::default();
        let auth = GitHubAuth::new(config);
        
        let team = GitHubTeam {
            name: "admins".to_string(),
            policies: vec!["admin".to_string()],
            ttl: None,
        };
        
        auth.create_team(team.clone()).await.unwrap();
        
        let retrieved = auth.get_team("admins").await.unwrap();
        assert_eq!(retrieved.name, "admins");
        
        let teams = auth.list_teams().await;
        assert!(teams.contains(&"admins".to_string()));
        
        auth.delete_team("admins").await.unwrap();
        assert!(auth.get_team("admins").await.is_none());
    }
}
