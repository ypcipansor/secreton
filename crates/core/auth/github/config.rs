// GitHub Authentication Configuration
// Enterprise-grade GitHub OAuth and Personal Access Token authentication

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use url::Url;
use anyhow::{Result, anyhow};

/// GitHub authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitHubConfig {
    /// GitHub organization name (required)
    pub organization: String,
    
    /// Base URL for GitHub API (for GitHub Enterprise)
    pub base_url: Url,
    
    /// GitHub OAuth App Client ID (for OAuth flow)
    pub client_id: Option<String>,
    
    /// GitHub OAuth App Client Secret (for OAuth flow)
    pub client_secret: Option<String>,
    
    /// Allowed teams (empty = allow all org members)
    pub allowed_teams: Vec<String>,
    
    /// Required team (user must be in this team)
    pub required_team: Option<String>,
    
    /// Token TTL in seconds
    pub ttl: u64,
    
    /// Maximum token TTL in seconds
    pub max_ttl: u64,
    
    /// Team to policy mapping
    pub team_policies: HashMap<String, Vec<String>>,
    
    /// Default policies for all authenticated users
    pub default_policies: Vec<String>,
    
    /// Verify organization membership
    pub verify_org_membership: bool,
    
    /// Cache settings
    pub cache_settings: CacheSettings,
}

/// Cache configuration for GitHub API calls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    /// User info cache TTL in seconds
    pub user_cache_ttl: u64,
    
    /// Team membership cache TTL in seconds
    pub team_cache_ttl: u64,
    
    /// Organization membership cache TTL in seconds
    pub org_cache_ttl: u64,
    
    /// Enable caching
    pub enabled: bool,
}

impl Default for GitHubConfig {
    fn default() -> Self {
        Self {
            organization: String::new(),
            base_url: Url::parse("https://api.github.com").unwrap(),
            client_id: None,
            client_secret: None,
            allowed_teams: Vec::new(),
            required_team: None,
            ttl: 3600,      // 1 hour
            max_ttl: 86400, // 24 hours
            team_policies: HashMap::new(),
            default_policies: vec!["default".to_string()],
            verify_org_membership: true,
            cache_settings: CacheSettings::default(),
        }
    }
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            user_cache_ttl: 300,  // 5 minutes
            team_cache_ttl: 600,  // 10 minutes
            org_cache_ttl: 600,   // 10 minutes
            enabled: true,
        }
    }
}

impl GitHubConfig {
    /// Create configuration for GitHub.com
    pub fn github_com(organization: &str) -> Self {
        let mut config = Self::default();
        config.organization = organization.to_string();
        config
    }
    
    /// Create configuration for GitHub Enterprise
    pub fn github_enterprise(organization: &str, base_url: &str) -> Result<Self> {
        let mut config = Self::default();
        config.organization = organization.to_string();
        config.base_url = Url::parse(base_url)
            .map_err(|e| anyhow!("Invalid base URL: {}", e))?;
        Ok(config)
    }
    
    /// Set OAuth application credentials
    pub fn with_oauth(mut self, client_id: &str, client_secret: &str) -> Self {
        self.client_id = Some(client_id.to_string());
        self.client_secret = Some(client_secret.to_string());
        self
    }
    
    /// Set allowed teams
    pub fn with_teams(mut self, teams: Vec<String>) -> Self {
        self.allowed_teams = teams;
        self
    }
    
    /// Set required team
    pub fn with_required_team(mut self, team: String) -> Self {
        self.required_team = Some(team);
        self
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if self.organization.is_empty() {
            return Err(anyhow!("Organization name is required"));
        }
        
        if self.ttl == 0 {
            return Err(anyhow!("TTL must be greater than 0"));
        }
        
        if self.max_ttl < self.ttl {
            return Err(anyhow!("Max TTL must be greater than or equal to TTL"));
        }
        
        // If OAuth is configured, both client_id and client_secret must be set
        if self.client_id.is_some() != self.client_secret.is_some() {
            return Err(anyhow!("Both client_id and client_secret must be set for OAuth"));
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_github_com_config() {
        let config = GitHubConfig::github_com("my-org");
        assert_eq!(config.organization, "my-org");
        assert_eq!(config.base_url.as_str(), "https://api.github.com/");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_github_enterprise_config() {
        let config = GitHubConfig::github_enterprise("my-org", "https://github.example.com/api/v3").unwrap();
        assert_eq!(config.organization, "my-org");
        assert!(config.base_url.as_str().contains("github.example.com"));
    }

    #[test]
    fn test_config_with_oauth() {
        let config = GitHubConfig::github_com("my-org")
            .with_oauth("client123", "secret456");
        assert_eq!(config.client_id, Some("client123".to_string()));
        assert_eq!(config.client_secret, Some("secret456".to_string()));
    }

    #[test]
    fn test_config_validation() {
        let mut config = GitHubConfig::default();
        
        // Should fail with empty organization
        assert!(config.validate().is_err());
        
        config.organization = "test-org".to_string();
        
        // Should pass
        assert!(config.validate().is_ok());
        
        // Should fail with invalid TTL
        config.max_ttl = 100;
        config.ttl = 200;
        assert!(config.validate().is_err());
    }
}
