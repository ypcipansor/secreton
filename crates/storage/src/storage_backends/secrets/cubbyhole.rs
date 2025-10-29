//! Cubbyhole Secrets Engine
//!
//! Per-token private storage that is automatically destroyed when token is revoked.
//! Provides complete isolation between tokens.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

/// Cubbyhole errors
#[derive(Error, Debug)]
pub enum CubbyholeError {
    #[error("Path not found: {0}")]
    PathNotFound(String),

    #[error("Unauthorized: token does not own this cubbyhole")]
    Unauthorized,

    #[error("Invalid _path")]
    InvalidPath,
}

/// Cubbyhole entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CubbyholeEntry {
    /// Token ID that owns this entry
    pub token_id: String,

    /// Path within token's cubbyhole
    pub _path: String,

    /// Data
    pub _data: HashMap<String, Value>,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Updated at
    pub updated_at: DateTime<Utc>,
}

impl CubbyholeEntry {
    /// Create new entry
    pub fn new(token_id: String, _path: String, _data: HashMap<String, Value>) -> Self {
        Self {
            token_id,
            _path,
            _data,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
}

/// Cubbyhole secrets engine
pub struct CubbyholeEngine {
    // Key: "token_id:_path"
    entries: Arc<RwLock<HashMap<String, CubbyholeEntry>>>,
}

impl CubbyholeEngine {
    /// Create new cubbyhole engine
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get full _key
    fn make_key(token_id: &str, _path: &str) -> String {
        format!("{}:{}", token_id, _path)
    }

    /// Write to cubbyhole
    pub async fn write(
        &self,
        token_id: &str,
        _path: &str,
        _data: HashMap<String, Value>,
    ) -> Result<(), CubbyholeError> {
        if _path.is_empty() {
            return Err(CubbyholeError::InvalidPath);
        }

        let _key = Self::make_key(token_id, _path);
        let entry = CubbyholeEntry::new(token_id.to_string(), _path.to_string(), _data);

        let mut entries = self.entries.write().await;
        entries.insert(_key, entry);

        Ok(())
    }

    /// Read from cubbyhole
    pub async fn read(
        &self,
        token_id: &str,
        _path: &str,
    ) -> Result<HashMap<String, Value>, CubbyholeError> {
        let _key = Self::make_key(token_id, _path);
        let entries = self.entries.read().await;

        let entry = entries
            .get(&_key)
            .ok_or_else(|| CubbyholeError::PathNotFound(_path.to_string()))?;

        // Verify ownership
        if entry.token_id != token_id {
            return Err(CubbyholeError::Unauthorized);
        }

        Ok(entry._data.clone())
    }

    /// Delete from cubbyhole
    pub async fn delete(&self, token_id: &str, _path: &str) -> Result<(), CubbyholeError> {
        let _key = Self::make_key(token_id, _path);
        let mut entries = self.entries.write().await;

        // Verify ownership before deleting
        if let Some(entry) = entries.get(&_key)
            && entry.token_id != token_id
        {
            return Err(CubbyholeError::Unauthorized);
        }

        entries
            .remove(&_key)
            .ok_or_else(|| CubbyholeError::PathNotFound(_path.to_string()))?;

        Ok(())
    }

    /// List paths in cubbyhole
    pub async fn list(&self, token_id: &str, prefix: &str) -> Vec<String> {
        let entries = self.entries.read().await;
        let prefix_key = Self::make_key(token_id, prefix);

        entries
            .keys()
            .filter(|_key| _key.starts_with(&prefix_key))
            .filter_map(|_key| {
                // Extract _path from "token_id:_path"
                _key.split(':').nth(1).map(String::from)
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

        let mut _data = HashMap::new();
        _data.insert(
            "api_key".to_string(),
            Value::String("secret123".to_string()),
        );

        cubbyhole
            .write("token1", "_config", _data.clone())
            .await
            .unwrap();

        let read_data = cubbyhole.read("token1", "_config").await.unwrap();
        assert_eq!(
            read_data.get("api_key"),
            Some(&Value::String("secret123".to_string()))
        );
    }

    #[tokio::test]
    async fn test_isolation() {
        let cubbyhole = CubbyholeEngine::new();

        let mut data1 = HashMap::new();
        data1.insert("_key".to_string(), Value::String("value1".to_string()));

        let mut data2 = HashMap::new();
        data2.insert("_key".to_string(), Value::String("value2".to_string()));

        // Write with different tokens
        cubbyhole.write("token1", "_data", data1).await.unwrap();
        cubbyhole.write("token2", "_data", data2).await.unwrap();

        // Each token can only read its own _data
        let token1_data = cubbyhole.read("token1", "_data").await.unwrap();
        assert_eq!(
            token1_data.get("_key"),
            Some(&Value::String("value1".to_string()))
        );

        let token2_data = cubbyhole.read("token2", "_data").await.unwrap();
        assert_eq!(
            token2_data.get("_key"),
            Some(&Value::String("value2".to_string()))
        );

        // Token1 cannot read token2's _data
        let result = cubbyhole.read("token1", "_data").await;
        assert!(result.is_ok()); // But reads its own
    }

    #[tokio::test]
    async fn test_delete() {
        let cubbyhole = CubbyholeEngine::new();

        let mut _data = HashMap::new();
        _data.insert("_key".to_string(), Value::String("value".to_string()));

        cubbyhole.write("token1", "temp", _data).await.unwrap();

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

        let mut _data = HashMap::new();
        _data.insert("_key".to_string(), Value::String("value".to_string()));

        // Write multiple entries for token1
        cubbyhole
            .write("token1", "data1", _data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "data2", _data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "data3", _data.clone())
            .await
            .unwrap();

        // Write entry for token2
        cubbyhole.write("token2", "_data", _data).await.unwrap();

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

        let mut _data = HashMap::new();
        _data.insert("_key".to_string(), Value::String("value".to_string()));

        cubbyhole
            .write("token1", "app/_config", _data.clone())
            .await
            .unwrap();
        cubbyhole
            .write("token1", "app/credentials", _data.clone())
            .await
            .unwrap();
        cubbyhole.write("token1", "db/_config", _data).await.unwrap();

        let app_paths = cubbyhole.list("token1", "app/").await;
        assert_eq!(app_paths.len(), 2);
        assert!(app_paths.contains(&"app/_config".to_string()));
        assert!(app_paths.contains(&"app/credentials".to_string()));
    }
}
