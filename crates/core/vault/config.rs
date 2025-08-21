use serde::Deserialize;
use std::env;
use thiserror::Error;

#[derive(Debug, Deserialize, Clone)]
pub struct VaultConfig {
    pub address: String,
    pub token: String,
    pub mount_path: String,
    pub key_name: String,
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Missing environment variable: {0}")]
    MissingEnv(String),
}

impl VaultConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Ok(Self {
            address: env::var("VAULT_ADDR").map_err(|_| ConfigError::MissingEnv("VAULT_ADDR".to_string()))?,
            token: env::var("VAULT_TOKEN").map_err(|_| ConfigError::MissingEnv("VAULT_TOKEN".to_string()))?,
            mount_path: env::var("VAULT_MOUNT_PATH").unwrap_or_else(|_| "transit".to_string()),
            key_name: env::var("VAULT_KEY_NAME").unwrap_or_else(|_| "vault-adhyaksa".to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_config_from_env() {
        env::set_var("VAULT_ADDR", "http://localhost:8200");
        env::set_var("VAULT_TOKEN", "test-token");
        
        let config = VaultConfig::from_env().unwrap();
        assert_eq!(config.address, "http://localhost:8200");
        assert_eq!(config.token, "test-token");
        assert_eq!(config.mount_path, "transit");
        assert_eq!(config.key_name, "vault-adhyaksa");
        
        // Test with custom mount path and key name
        env::set_var("VAULT_MOUNT_PATH", "custom-transit");
        env::set_var("VAULT_KEY_NAME", "custom-key");
        
        let config = VaultConfig::from_env().unwrap();
        assert_eq!(config.mount_path, "custom-transit");
        assert_eq!(config.key_name, "custom-key");
        
        // Clean up
        env::remove_var("VAULT_ADDR");
        env::remove_var("VAULT_TOKEN");
        env::remove_var("VAULT_MOUNT_PATH");
        env::remove_var("VAULT_KEY_NAME");
    }
    
    #[test]
    fn test_missing_required_env() {
        env::remove_var("VAULT_ADDR");
        env::set_var("VAULT_TOKEN", "test-token");
        
        let result = VaultConfig::from_env();
        assert!(matches!(result, Err(ConfigError::MissingEnv(_))));
        
        env::set_var("VAULT_ADDR", "http://localhost:8200");
        env::remove_var("VAULT_TOKEN");
        
        let result = VaultConfig::from_env();
        assert!(matches!(result, Err(ConfigError::MissingEnv(_))));
        
        // Clean up
        env::remove_var("VAULT_ADDR");
        env::remove_var("VAULT_TOKEN");
    }
}
