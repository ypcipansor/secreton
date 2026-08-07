//! Database models and data structures

use serde::{Deserialize, Serialize};

/// Database type
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
}

/// Database role configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DatabaseRole {
    pub sql: String,
    /// Maximum allowed TTL in seconds.  Defaults to 86400 (24 h) when omitted
    /// or set to `null` in JSON, preserving backward compatibility with older
    /// API clients that used `Option<u64>`.
    #[serde(default = "default_max_ttl", deserialize_with = "deserialize_ttl_max")]
    pub max_ttl: u64,
    /// Default lease TTL in seconds.  Defaults to 3600 (1 h) when omitted or
    /// set to `null`.
    #[serde(default = "default_ttl", deserialize_with = "deserialize_ttl_default")]
    pub default_ttl: u64,
}

fn default_max_ttl() -> u64 {
    86400
}

fn default_ttl() -> u64 {
    3600
}

/// Deserialize a TTL field that may be `null` (from old `Option<u64>` clients)
/// into a `u64`, falling back to the provided default when `null`.
fn deserialize_ttl_max<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<u64>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_else(default_max_ttl))
}

fn deserialize_ttl_default<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<u64>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_else(default_ttl))
}

/// Database secret engine configuration
#[derive(Clone, Serialize, Deserialize)]
pub struct DatabaseConfig {
    pub connection_url: String,
    pub username: Option<String>,
    pub password: Option<String>,
    pub database_name: Option<String>,
    pub max_open_connections: Option<u32>,
    pub max_idle_connections: Option<u32>,
    pub connection_timeout: Option<u64>,
    #[serde(
        default = "default_verify_connection",
        deserialize_with = "deserialize_verify_connection"
    )]
    pub verify_connection: bool,
}

/// Deserialize `verify_connection` accepting `null` (→ `true`) for backward
/// compatibility with clients that may send explicit null.
fn deserialize_verify_connection<'de, D>(deserializer: D) -> Result<bool, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<bool>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_else(default_verify_connection))
}

// Manual Debug impl to prevent accidental logging of database credentials.
impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DatabaseConfig")
            .field("connection_url", &"[REDACTED]")
            .field("username", &self.username.as_deref().map(|_| "[REDACTED]"))
            .field("password", &"[REDACTED]")
            .field("database_name", &self.database_name)
            .field("max_open_connections", &self.max_open_connections)
            .field("max_idle_connections", &self.max_idle_connections)
            .field("connection_timeout", &self.connection_timeout)
            .field("verify_connection", &self.verify_connection)
            .finish()
    }
}

fn default_verify_connection() -> bool {
    true
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
