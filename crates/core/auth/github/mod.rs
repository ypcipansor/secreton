// GitHub Authentication Module
// Enterprise-grade authentication using GitHub OAuth and Personal Access Tokens
//
// Features:
// - GitHub.com and GitHub Enterprise support
// - Personal Access Token authentication
// - OAuth 2.0 flow support
// - Organization membership verification
// - Team-based policy assignment
// - High-performance caching
// - Enterprise audit logging

mod config;

pub use config::{GitHubConfig, CacheSettings};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use reqwest::Client;

use super::traits::{AuthMethod, AuthResult, Credentials, TokenInfo};
use crate::storage::{StorageEngine, StorageEntry};
use crate::audit::{AuditLogger, AuditLog, AuditStatus};
use crate::error::CoreError;

/// GitHub authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubCredentials {
    /// GitHub Personal Access Token or OAuth token
    pub token: String,
}

impl Credentials for GitHubCredentials {
    fn credential_type(&self) -> &str {
        "github"
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// GitHub user information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubUser {
    pub login: String,
    pub id: u64,
    pub name: Option<String>,
    pub email: Option<String>,
    pub avatar_url: Option<String>,
    pub teams: Vec<String>,
    pub org_member: bool,
}

/// Cached user information
#[derive(Debug, Clone)]
struct CachedUser {
    user: GitHubUser,
    cached_at: DateTime<Utc>,
}

/// GitHub authentication implementation
pub struct GitHubAuth {
    config: GitHubConfig,
    storage: Arc<dyn StorageEngine>,
    audit_logger: Arc<AuditLogger>,
    http_client: Client,
    user_cache: Arc<RwLock<HashMap<String, CachedUser>>>,
}

impl GitHubAuth {
    /// Create new GitHub authentication instance
    pub fn new(
        config: GitHubConfig,
        storage: Arc<dyn StorageEngine>,
        audit_logger: Arc<AuditLogger>,
    ) -> Result<Self, CoreError> {
        // Validate configuration
        config.validate()
            .map_err(|e| CoreError::Configuration(format!("Invalid GitHub config: {}", e)))?;
        
        // Create HTTP client with appropriate settings
        let http_client = Client::builder()
            .user_agent("Secreton-Vault/2.0")
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| CoreError::Configuration(format!("Failed to create HTTP client: {}", e)))?;
        
        Ok(Self {
            config,
            storage,
            audit_logger,
            http_client,
            user_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
    
    /// Verify GitHub token and get user information
    async fn verify_token(&self, token: &str) -> Result<GitHubUser, CoreError> {
        // Check cache first if enabled
        if self.config.cache_settings.enabled {
            if let Some(cached) = self.get_cached_user(token).await {
                return Ok(cached.user);
            }
        }
        
        // Get user info from GitHub API
        let user_info = self.get_user_info(token).await?;
        
        // Verify organization membership if required
        if self.config.verify_org_membership {
            let is_member = self.verify_org_membership(&user_info.login, token).await?;
            if !is_member {
                return Err(CoreError::AuthenticationFailed(
                    format!("User {} is not a member of organization {}", 
                            user_info.login, self.config.organization)
                ));
            }
        }
        
        // Get user's teams
        let teams = self.get_user_teams(&user_info.login, token).await?;
        
        let github_user = GitHubUser {
            login: user_info.login,
            id: user_info.id,
            name: user_info.name,
            email: user_info.email,
            avatar_url: user_info.avatar_url,
            teams,
            org_member: true,
        };
        
        // Cache the result
        if self.config.cache_settings.enabled {
            self.cache_user(token, github_user.clone()).await;
        }
        
        Ok(github_user)
    }
    
    /// Get user information from GitHub API
    async fn get_user_info(&self, token: &str) -> Result<GitHubUserResponse, CoreError> {
        let url = format!("{}/user", self.config.base_url);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::Network(format!("Failed to call GitHub API: {}", e)))?;
        
        if !response.status().is_success() {
            return Err(CoreError::AuthenticationFailed(
                format!("GitHub API returned status: {}", response.status())
            ));
        }
        
        response.json().await
            .map_err(|e| CoreError::Serialization(format!("Failed to parse GitHub response: {}", e)))
    }
    
    /// Verify user is a member of the organization
    async fn verify_org_membership(&self, username: &str, token: &str) -> Result<bool, CoreError> {
        let url = format!("{}/orgs/{}/members/{}", 
                         self.config.base_url, 
                         self.config.organization,
                         username);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::Network(format!("Failed to verify org membership: {}", e)))?;
        
        Ok(response.status().is_success())
    }
    
    /// Get user's teams in the organization
    async fn get_user_teams(&self, username: &str, token: &str) -> Result<Vec<String>, CoreError> {
        let url = format!("{}/orgs/{}/teams", 
                         self.config.base_url,
                         self.config.organization);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::Network(format!("Failed to get teams: {}", e)))?;
        
        if !response.status().is_success() {
            return Ok(Vec::new());
        }
        
        let teams: Vec<TeamResponse> = response.json().await.unwrap_or_default();
        
        // Filter teams where user is a member
        let mut user_teams = Vec::new();
        for team in teams {
            if self.is_team_member(&team.slug, username, token).await? {
                user_teams.push(team.slug);
            }
        }
        
        Ok(user_teams)
    }
    
    /// Check if user is a member of a specific team
    async fn is_team_member(&self, team_slug: &str, username: &str, token: &str) -> Result<bool, CoreError> {
        let url = format!("{}/orgs/{}/teams/{}/memberships/{}", 
                         self.config.base_url,
                         self.config.organization,
                         team_slug,
                         username);
        
        let response = self.http_client
            .get(&url)
            .header("Authorization", format!("token {}", token))
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .map_err(|e| CoreError::Network(format!("Failed to check team membership: {}", e)))?;
        
        Ok(response.status().is_success())
    }
    
    /// Check if user's teams are allowed
    fn validate_team_membership(&self, user_teams: &[String]) -> Result<(), CoreError> {
        // Check required team if configured
        if let Some(required_team) = &self.config.required_team {
            if !user_teams.contains(required_team) {
                return Err(CoreError::AuthenticationFailed(
                    format!("User must be in team: {}", required_team)
                ));
            }
        }
        
        // Check allowed teams if configured
        if !self.config.allowed_teams.is_empty() {
            let has_allowed_team = user_teams.iter()
                .any(|team| self.config.allowed_teams.contains(team));
            
            if !has_allowed_team {
                return Err(CoreError::AuthenticationFailed(
                    "User is not in any allowed teams".to_string()
                ));
            }
        }
        
        Ok(())
    }
    
    /// Generate policies based on user's teams
    fn generate_policies(&self, user_teams: &[String]) -> Vec<String> {
        let mut policies = self.config.default_policies.clone();
        
        // Add team-specific policies
        for team in user_teams {
            if let Some(team_policies) = self.config.team_policies.get(team) {
                policies.extend(team_policies.clone());
            } else {
                // Default team policy
                policies.push(format!("github-team-{}", team));
            }
        }
        
        policies.sort();
        policies.dedup();
        policies
    }
    
    /// Get cached user if available and not expired
    async fn get_cached_user(&self, token: &str) -> Option<CachedUser> {
        let cache = self.user_cache.read().await;
        if let Some(cached) = cache.get(token) {
            let age = Utc::now() - cached.cached_at;
            if age < Duration::seconds(self.config.cache_settings.user_cache_ttl as i64) {
                return Some(cached.clone());
            }
        }
        None
    }
    
    /// Cache user information
    async fn cache_user(&self, token: &str, user: GitHubUser) {
        let mut cache = self.user_cache.write().await;
        cache.insert(token.to_string(), CachedUser {
            user,
            cached_at: Utc::now(),
        });
        
        // Clean up old cache entries (simple cleanup)
        if cache.len() > 1000 {
            let cutoff = Utc::now() - Duration::seconds(self.config.cache_settings.user_cache_ttl as i64);
            cache.retain(|_, v| v.cached_at > cutoff);
        }
    }
    
    /// Log authentication attempt
    async fn log_auth_attempt(&self, username: &str, success: bool, reason: Option<&str>) {
        let status = if success {
            AuditStatus::Success
        } else {
            AuditStatus::Failure
        };
        
        let mut metadata = HashMap::new();
        metadata.insert("auth_method".to_string(), "github".to_string());
        metadata.insert("username".to_string(), username.to_string());
        metadata.insert("organization".to_string(), self.config.organization.clone());
        
        if let Some(reason) = reason {
            metadata.insert("failure_reason".to_string(), reason.to_string());
        }
        
        let log = AuditLog {
            timestamp: Utc::now(),
            action: "github_authentication".to_string(),
            actor: username.to_string(),
            resource: format!("auth/github/{}", username),
            status,
            metadata,
        };
        
        if let Err(e) = self.audit_logger.log(log).await {
            eprintln!("Failed to log audit event: {}", e);
        }
    }
}

#[async_trait]
impl AuthMethod for GitHubAuth {
    fn method_type(&self) -> &'static str {
        "github"
    }
    
    async fn authenticate(
        &self,
        credentials: Box<dyn Credentials>,
    ) -> Result<AuthResult, CoreError> {
        // Downcast credentials
        let github_creds = credentials.as_any()
            .downcast_ref::<GitHubCredentials>()
            .ok_or_else(|| CoreError::InvalidCredentials("Invalid credential type for GitHub auth".to_string()))?;
        
        // Verify token and get user info
        let user = match self.verify_token(&github_creds.token).await {
            Ok(user) => user,
            Err(e) => {
                self.log_auth_attempt("unknown", false, Some(&e.to_string())).await;
                return Err(e);
            }
        };
        
        // Validate team membership
        if let Err(e) = self.validate_team_membership(&user.teams) {
            self.log_auth_attempt(&user.login, false, Some(&e.to_string())).await;
            return Err(e);
        }
        
        // Generate policies
        let policies = self.generate_policies(&user.teams);
        
        // Create metadata
        let mut metadata = HashMap::new();
        metadata.insert("github_id".to_string(), user.id.to_string());
        metadata.insert("github_login".to_string(), user.login.clone());
        if let Some(name) = &user.name {
            metadata.insert("github_name".to_string(), name.clone());
        }
        if let Some(email) = &user.email {
            metadata.insert("github_email".to_string(), email.clone());
        }
        metadata.insert("github_teams".to_string(), user.teams.join(","));
        metadata.insert("github_org".to_string(), self.config.organization.clone());
        
        // Log successful authentication
        self.log_auth_attempt(&user.login, true, None).await;
        
        Ok(AuthResult {
            user_id: user.login.clone(),
            username: user.login,
            policies,
            metadata,
            ttl: self.config.ttl as i64,
        })
    }
    
    async fn renew(&self, _token_info: &TokenInfo) -> Result<TokenInfo, CoreError> {
        Err(CoreError::Unsupported("GitHub tokens cannot be renewed through Vault".to_string()))
    }
    
    async fn revoke(&self, _token: &str) -> Result<(), CoreError> {
        // GitHub tokens are revoked through GitHub, not through Vault
        Ok(())
    }
}

// GitHub API response structures
#[derive(Debug, Deserialize)]
struct GitHubUserResponse {
    login: String,
    id: u64,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TeamResponse {
    name: String,
    slug: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::in_memory::InMemoryStorage;
    
    #[test]
    fn test_github_auth_creation() {
        let config = GitHubConfig::github_com("test-org");
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = Arc::new(AuditLogger::new(storage.clone()));
        
        let auth = GitHubAuth::new(config, storage, audit_logger);
        assert!(auth.is_ok());
    }
    
    #[test]
    fn test_method_type() {
        let config = GitHubConfig::github_com("test-org");
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = Arc::new(AuditLogger::new(storage.clone()));
        
        let auth = GitHubAuth::new(config, storage, audit_logger).unwrap();
        assert_eq!(auth.method_type(), "github");
    }
    
    #[test]
    fn test_policy_generation() {
        let mut config = GitHubConfig::github_com("test-org");
        config.default_policies = vec!["default".to_string()];
        config.team_policies.insert(
            "devops".to_string(),
            vec!["admin".to_string(), "deploy".to_string()]
        );
        
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = Arc::new(AuditLogger::new(storage.clone()));
        let auth = GitHubAuth::new(config, storage, audit_logger).unwrap();
        
        let teams = vec!["devops".to_string(), "backend".to_string()];
        let policies = auth.generate_policies(&teams);
        
        assert!(policies.contains(&"default".to_string()));
        assert!(policies.contains(&"admin".to_string()));
        assert!(policies.contains(&"deploy".to_string()));
        assert!(policies.contains(&"github-team-backend".to_string()));
    }
    
    #[test]
    fn test_team_validation_with_required_team() {
        let mut config = GitHubConfig::github_com("test-org");
        config.required_team = Some("devops".to_string());
        
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = Arc::new(AuditLogger::new(storage.clone()));
        let auth = GitHubAuth::new(config, storage, audit_logger).unwrap();
        
        // Should pass with required team
        let teams = vec!["devops".to_string(), "backend".to_string()];
        assert!(auth.validate_team_membership(&teams).is_ok());
        
        // Should fail without required team
        let teams = vec!["backend".to_string()];
        assert!(auth.validate_team_membership(&teams).is_err());
    }
    
    #[test]
    fn test_team_validation_with_allowed_teams() {
        let mut config = GitHubConfig::github_com("test-org");
        config.allowed_teams = vec!["devops".to_string(), "backend".to_string()];
        
        let storage = Arc::new(InMemoryStorage::new());
        let audit_logger = Arc::new(AuditLogger::new(storage.clone()));
        let auth = GitHubAuth::new(config, storage, audit_logger).unwrap();
        
        // Should pass with allowed team
        let teams = vec!["devops".to_string()];
        assert!(auth.validate_team_membership(&teams).is_ok());
        
        // Should fail with disallowed team
        let teams = vec!["frontend".to_string()];
        assert!(auth.validate_team_membership(&teams).is_err());
    }
}
