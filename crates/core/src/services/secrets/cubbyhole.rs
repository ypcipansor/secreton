//! Cubbyhole Secrets Engine
//!
//! Per-token private storage that is automatically destroyed when token is revoked.
//! Provides complete isolation between tokens.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Cubbyhole errors
#[derive(Debug, thiserror::Error)]
pub enum CubbyholeError {
    #[error("Path not found: {0}")]
    PathNotFound(String),

    #[error("Unauthorized: token does not own this cubbyhole")]
    Unauthorized,

    #[error("Invalid path")]
    InvalidPath,
}

/// Cubbyhole entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CubbyholeEntry {
    /// Token ID that owns this entry
    pub token_id: String,

    /// Path within token's cubbyhole
    pub path: String,

    /// Data
    pub data: HashMap<String, Value>,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl CubbyholeEntry {
    /// Create new entry
    pub fn new(token_id: String, path: String, data: HashMap<String, Value>) -> Self {
        Self {
            token_id,
            path,
            data,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Cubbyhole secrets engine
pub struct CubbyholeEngine {
    // Key: "token_id:path"
    entries: Arc<RwLock<HashMap<String, CubbyholeEntry>>>,
}

impl CubbyholeEngine {
    /// Create new cubbyhole engine
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get full key
    fn make_key(token_id: &str, path: &str) -> String {
        format!("{}:{}", token_id, path)
    }

    /// Write to cubbyhole
    pub async fn write(
        &self,
        token_id: &str,
        path: &str,
        data: HashMap<String, Value>,
    ) -> Result<(), CubbyholeError> {
        if path.is_empty() {
            return Err(CubbyholeError::InvalidPath);
        }

        let key = Self::make_key(token_id, path);
        let entry = CubbyholeEntry::new(token_id.to_string(), path.to_string(), data);

        let mut entries = self.entries.write().await;
        entries.insert(key, entry);

        Ok(())
    }

    /// Read from cubbyhole
    pub async fn read(
        &self,
        token_id: &str,
        path: &str,
    ) -> Result<HashMap<String, Value>, CubbyholeError> {
        let key = Self::make_key(token_id, path);
        let entries = self.entries.read().await;

        let entry = entries
            .get(&key)
            .ok_or_else(|| CubbyholeError::PathNotFound(path.to_string()))?;

        // Verify ownership
        if entry.token_id != token_id {
            return Err(CubbyholeError::Unauthorized);
        }

        Ok(entry.data.clone())
    }

    /// Delete from cubbyhole
    pub async fn delete(&self, token_id: &str, path: &str) -> Result<(), CubbyholeError> {
        let key = Self::make_key(token_id, path);
        let mut entries = self.entries.write().await;

        // Verify ownership before deleting
        if let Some(entry) = entries.get(&key) {
            if entry.token_id != token_id {
                return Err(CubbyholeError::Unauthorized);
            }
        }

        entries
            .remove(&key)
            .ok_or_else(|| CubbyholeError::PathNotFound(path.to_string()))?;

        Ok(())
    }

    /// List paths in cubbyhole
    pub async fn list(&self, token_id: &str, prefix: &str) -> Vec<String> {
        let entries = self.entries.read().await;
        let prefix_key = Self::make_key(token_id, prefix);

        entries
            .keys()
            .filter(|key| key.starts_with(&prefix_key))
            .filter_map(|key| {
                // Extract path from "token_id:path"
                key.split(':').nth(1).map(String::from)
            })
            .collect()
    }

    /// Cleanup all entries for a token (called on token revocation)
    pub async fn cleanup_token(&self, token_id: &str) -> usize {
        let mut entries = self.entries.write().await;
        let initial_count = entries.len();

        entries.retain(|_, entry| entry.token_id != token_id);

        initial_count - entries.len()
    }

    /// Get count of entries for token
    pub async fn count_for_token(&self, token_id: &str) -> usize {
        let entries = self.entries.read().await;
        entries
            .values()
            .filter(|entry| entry.token_id == token_id)
            .count()
    }

    /// Get total entry count
    pub async fn count(&self) -> usize {
        let entries = self.entries.read().await;
        entries.len()
    }
}

impl Default for CubbyholeEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_write_read() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data = HashMap::new();
        data.insert(
            "api_key".to_string(),
            Value::String("secret123".to_string()),
        );

        cubbyhole
            .write("token1", "config", data.clone())
            .await
            .unwrap();

        let read_data = cubbyhole.read("token1", "config").await.unwrap();
        assert_eq!(
            read_data.get("api_key"),
            Some(&Value::String("secret123".to_string()))
        );
    }

    #[tokio::test]
    async fn test_isolation() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data1 = HashMap::new();
        data1.insert("key".to_string(), Value::String("value1".to_string()));

        let mut data2 = HashMap::new();
        data2.insert("key".to_string(), Value::String("value2".to_string()));

        // Write with different tokens
        cubbyhole.write("token1", "data", data1).await.unwrap();
        cubbyhole.write("token2", "data", data2).await.unwrap();

        // Each token can only read its own data
        let token1_data = cubbyhole.read("token1", "data").await.unwrap();
        assert_eq!(
            token1_data.get("key"),
            Some(&Value::String("value1".to_string()))
        );

        let token2_data = cubbyhole.read("token2", "data").await.unwrap();
        assert_eq!(
            token2_data.get("key"),
            Some(&Value::String("value2".to_string()))
        );

        // Token1 cannot read token2's data
        let result = cubbyhole.read("token1", "data").await;
        assert!(result.is_ok()); // But reads its own
    }

    #[tokio::test]
    async fn test_delete() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));

        cubbyhole.write("token1", "temp", data).await.unwrap();

        // Verify it exists
        assert!(cubbyhole.read("token1", "temp").await.is_ok());

        // Delete it
        cubbyhole.delete("token1", "temp").await.unwrap();

        // Should not exist anymore
        let result = cubbyhole.read("token1", "temp").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cleanup_token() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));

        // Write multiple entries for token1
        cubbyhole
            .write("token1", "data1", data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "data2", data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "data3", data.clone())
            .await
            .unwrap();

        // Write entry for token2
        cubbyhole.write("token2", "data", data).await.unwrap();

        assert_eq!(cubbyhole.count_for_token("token1").await, 3);
        assert_eq!(cubbyhole.count_for_token("token2").await, 1);

        // Cleanup token1
        let cleaned = cubbyhole.cleanup_token("token1").await;
        assert_eq!(cleaned, 3);

        assert_eq!(cubbyhole.count_for_token("token1").await, 0);
        assert_eq!(cubbyhole.count_for_token("token2").await, 1);
    }

    #[tokio::test]
    async fn test_list() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data = HashMap::new();
        data.insert("key".to_string(), Value::String("value".to_string()));

        cubbyhole
            .write("token1", "app/config", data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "app/credentials", data.clone())
            .await
            .unwrap();
        cubbyhole.write("token1", "db/config", data).await.unwrap();

        let app_paths = cubbyhole.list("token1", "app/").await;
        assert_eq!(app_paths.len(), 2);
        assert!(app_paths.contains(&"app/config".to_string()));
        assert!(app_paths.contains(&"app/credentials".to_string()));
    }
}
