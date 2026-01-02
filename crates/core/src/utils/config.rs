use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub jwt_secret: String,
    pub refresh_secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub database_url: String,
    pub backend: Option<String>,
    pub jwt_secret: String,
    pub jwt_refresh_secret: String,
    pub encryption_key: String,
    pub server_host: String,
    pub server_port: u16,
    pub log_level: String,
    pub is_leader: bool,
    pub dynamic_db_url: Option<String>,
    pub aws_access_key: Option<String>,
    pub aws_secret_key: Option<String>,
    pub aws_region: Option<String>,
    pub ldap_url: Option<String>,
    pub ldap_base_dn: Option<String>,
    pub oidc_client_id: Option<String>,
    pub oidc_client_secret: Option<String>,
    pub oidc_issuer: Option<String>,
    pub oidc_redirect_url: Option<String>,
    pub node_id: Option<String>,
    pub peers: Option<Vec<String>>,
    pub replication_mode: Option<String>, // "dr", "performance", "none"
    pub replication_peers: Option<Vec<String>>, // list url/addr cluster peer
    pub auto_unseal_enabled: Option<bool>,
    pub auto_unseal_provider: Option<String>, // "kms", "hsm", "cloud"
    pub auto_unseal_key_id: Option<String>,
    pub audit_devices: Option<Vec<String>>,
    // Nested structures for compatibility
    pub auth: AuthConfig,
    pub server: ServerConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self::from_env()
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    // Removed default method to avoid conflict with Default trait

    pub fn from_env() -> Self {
        let jwt_secret = std::env::var("VAULT_JWT_SECRET")
            .unwrap_or_else(|_| "your-super-secret-jwt-key-change-this-in-production".to_string());
        let jwt_refresh_secret = std::env::var("VAULT_JWT_REFRESH_SECRET").unwrap_or_else(|_| {
            "your-super-secret-refresh-key-change-this-in-production".to_string()
        });
        let server_host = std::env::var("VAULT_HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
        let server_port: u16 = std::env::var("VAULT_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .unwrap_or(8080);
        let log_level = std::env::var("VAULT_LOG_LEVEL").unwrap_or_else(|_| "info".to_string());

        Self {
            database_url: std::env::var("VAULT_DATABASE_URL")
                .unwrap_or_else(|_| "sqlite:secreton.db".to_string()),
            jwt_secret: jwt_secret.clone(),
            jwt_refresh_secret: jwt_refresh_secret.clone(),
            encryption_key: std::env::var("VAULT_ENCRYPTION_KEY")
                .unwrap_or_else(|_| "your-32-byte-encryption-key-here".to_string()),
            server_host: server_host.clone(),
            server_port,
            log_level: log_level.clone(),
            backend: None,
            is_leader: false,
            dynamic_db_url: None,
            aws_access_key: None,
            aws_secret_key: None,
            aws_region: None,
            ldap_url: None,
            ldap_base_dn: None,
            oidc_client_id: None,
            oidc_client_secret: None,
            oidc_issuer: None,
            oidc_redirect_url: None,
            node_id: None,
            peers: None,
            replication_mode: None,
            replication_peers: None,
            auto_unseal_enabled: None,
            auto_unseal_provider: None,
            auto_unseal_key_id: None,
            audit_devices: None,
            auth: AuthConfig {
                jwt_secret,
                refresh_secret: jwt_refresh_secret,
            },
            server: ServerConfig {
                host: server_host,
                port: server_port,
                log_level,
            },
        }
    }
}
