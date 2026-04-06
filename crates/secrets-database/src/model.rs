//! Database models and data structures

use serde::{Deserialize, Serialize};

/// Database type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    MongoDB,
    Redis,
}

/// Database role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub sql: String,
    /// Maximum allowed TTL in seconds.  Defaults to 86400 (24 h) when omitted
    /// in JSON, preserving backward compatibility with older API clients that
    /// used `Option<u64>`.
    #[serde(default = "default_max_ttl")]
    pub max_ttl: u64,
    /// Default lease TTL in seconds.  Defaults to 3600 (1 h) when omitted.
    #[serde(default = "default_ttl")]
    pub default_ttl: u64,
}

fn default_max_ttl() -> u64 {
    86400
}

fn default_ttl() -> u64 {
    3600
}

/// Database secret engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub connection_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database_name: Option<String>,
    pub max_open_connections: Option<u32>,
    pub max_idle_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
    #[serde(default = "default_verify_connection")]
    #[serde(default = "default_verify_connection")]
    pub verify_connection: bool,
}

fn default_verify_connection() -> bool {
    true
}
}

fn default_verify_connection() -> bool {
    true
}
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            connection_url: String::new(),
            username: None,
            password: None,
            database_name: None,
            max_open_connections: Some(10),
            max_idle_connections: Some(5),
            connection_timeout: Some(30),
            verify_connection: true,
        }
    }
}
