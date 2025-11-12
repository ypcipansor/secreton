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
    pub max_ttl: u64,
    pub default_ttl: u64,
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
    pub verify_connection: bool,
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
