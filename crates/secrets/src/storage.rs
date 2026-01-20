use anyhow::Result;
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// Represents a versioned secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub id: String,
    pub version: u32,
    pub data: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub created_by: String,
    pub metadata: HashMap<String, String>,
    pub deleted: bool,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: String,
    pub path: String,
    pub current_version: u32,
    pub versions: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub max_versions: u32,
    pub custom_metadata: HashMap<String, String>,
}

#[async_trait]
pub trait SecretStorage: Send + Sync {
    /// Store a new version of a secret
    async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32>;

    /// Get the latest version of a secret
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>>;

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>>;

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()>;

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()>;
}
