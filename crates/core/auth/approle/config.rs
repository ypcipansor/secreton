//! AppRole Configuration
//! 
//! Configuration structures for AppRole authentication method

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRoleConfig {
    /// Default token TTL in seconds
    pub default_token_ttl: u64,
    
    /// Maximum token TTL in seconds
    pub max_token_ttl: u64,
    
    /// Default secret ID TTL in seconds
    pub default_secret_id_ttl: u64,
    
    /// Maximum number of secret IDs per role
    pub max_secret_ids_per_role: u32,
    
    /// Whether to bind secret IDs by default
    pub bind_secret_id_default: bool,
    
    /// Enable local secret IDs
    pub local_secret_ids: bool,
}

impl Default for AppRoleConfig {
    fn default() -> Self {
        Self {
            default_token_ttl: 3600,      // 1 hour
            max_token_ttl: 86400,         // 24 hours
            default_secret_id_ttl: 86400, // 24 hours
            max_secret_ids_per_role: 1000,
            bind_secret_id_default: true,
            local_secret_ids: false,
        }
    }
}

impl AppRoleConfig {
    /// Create a new AppRole configuration
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set default token TTL
    pub fn with_default_token_ttl(mut self, ttl: u64) -> Self {
        self.default_token_ttl = ttl;
        self
    }
    
    /// Set maximum token TTL
    pub fn with_max_token_ttl(mut self, ttl: u64) -> Self {
        self.max_token_ttl = ttl;
        self
    }
    
    /// Set default secret ID TTL
    pub fn with_default_secret_id_ttl(mut self, ttl: u64) -> Self {
        self.default_secret_id_ttl = ttl;
        self
    }
    
    /// Set maximum secret IDs per role
    pub fn with_max_secret_ids_per_role(mut self, max: u32) -> Self {
        self.max_secret_ids_per_role = max;
        self
    }
    
    /// Enable or disable secret ID binding by default
    pub fn with_bind_secret_id_default(mut self, bind: bool) -> Self {
        self.bind_secret_id_default = bind;
        self
    }
    
    /// Enable or disable local secret IDs
    pub fn with_local_secret_ids(mut self, local: bool) -> Self {
        self.local_secret_ids = local;
        self
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.default_token_ttl > self.max_token_ttl {
            return Err("Default token TTL cannot be greater than max token TTL".to_string());
        }
        
        if self.max_secret_ids_per_role == 0 {
            return Err("Max secret IDs per role must be greater than 0".to_string());
        }
        
        if self.default_secret_id_ttl == 0 {
            return Err("Default secret ID TTL must be greater than 0".to_string());
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AppRoleConfig::default();
        assert_eq!(config.default_token_ttl, 3600);
        assert_eq!(config.max_token_ttl, 86400);
        assert_eq!(config.default_secret_id_ttl, 86400);
        assert_eq!(config.max_secret_ids_per_role, 1000);
        assert!(config.bind_secret_id_default);
        assert!(!config.local_secret_ids);
    }

    #[test]
    fn test_config_builder() {
        let config = AppRoleConfig::new()
            .with_default_token_ttl(1800)
            .with_max_token_ttl(7200)
            .with_max_secret_ids_per_role(500)
            .with_bind_secret_id_default(false);
            
        assert_eq!(config.default_token_ttl, 1800);
        assert_eq!(config.max_token_ttl, 7200);
        assert_eq!(config.max_secret_ids_per_role, 500);
        assert!(!config.bind_secret_id_default);
    }

    #[test]
    fn test_config_validation() {
        let valid_config = AppRoleConfig::default();
        assert!(valid_config.validate().is_ok());
        
        let invalid_config = AppRoleConfig {
            default_token_ttl: 7200,
            max_token_ttl: 3600, // Less than default
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());
        
        let zero_secret_ids = AppRoleConfig {
            max_secret_ids_per_role: 0,
            ..Default::default()
        };
        assert!(zero_secret_ids.validate().is_err());
    }
}
