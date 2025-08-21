use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub log_level: String,
    pub storage_path: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    #[serde(default = "default_token_ttl")]
    pub token_ttl: i64,  // in seconds
    
    #[serde(default = "default_refresh_token_ttl")]
    pub refresh_token_ttl: i64,  // in seconds
    
    #[serde(default = "default_jwt_secret")]
    pub jwt_secret: String,
    
    #[serde(default = "default_refresh_secret")]
    pub refresh_secret: String,
    
    #[serde(default = "default_password_reset_ttl")]
    pub password_reset_ttl: i64,  // in seconds
    
    #[serde(default = "default_mfa_enabled")]
    pub mfa_enabled: bool,
}

// Default configuration values
fn default_token_ttl() -> i64 { 3600 }  // 1 hour
fn default_refresh_token_ttl() -> i64 { 2_592_000 }  // 30 days
fn default_password_reset_ttl() -> i64 { 3600 }  // 1 hour
fn default_mfa_enabled() -> bool { true }

fn default_jwt_secret() -> String {
    // In production, this should be overridden via environment variables
    "default-jwt-secret-please-change-in-production".to_string()
}

fn default_refresh_secret() -> String {
    // In production, this should be overridden via environment variables
    "default-refresh-secret-please-change-in-production".to_string()
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub auth: AuthConfig,
}

impl Config {
    pub fn from_file<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let config = config::Config::builder()
            .add_source(config::File::from(path.as_ref()))
            .add_source(config::Environment::with_prefix("BRANKAS").separator("__"))
            .build()?;

        config.try_deserialize().map_err(Into::into)
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let config = config::Config::builder()
            .add_source(config::Environment::with_prefix("BRANKAS").separator("__"))
            .build()?;

        config.try_deserialize().map_err(Into::into)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "127.0.0.1".to_string(),
                port: 8080,
                log_level: "info".to_string(),
                storage_path: "./data".to_string(),
            },
            database: DatabaseConfig {
                url: "sqlite:./data/brankas.db".to_string(),
                max_connections: 5,
            },
            auth: AuthConfig {
                token_ttl: default_token_ttl(),
                refresh_token_ttl: default_refresh_token_ttl(),
                jwt_secret: default_jwt_secret(),
                refresh_secret: default_refresh_secret(),
                password_reset_ttl: default_password_reset_ttl(),
                mfa_enabled: default_mfa_enabled(),
            },
        }
    }
}
