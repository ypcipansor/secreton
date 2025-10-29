//! Response Wrapping
//!
//! Security feature for wrapping sensitive responses in a single-use token
//! to prevent response interception and replay attacks.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Response wrapping errors
#[derive(Error, Debug)]
pub enum WrapError {
    #[error("Wrapped response not found: {0}")]
    NotFound(String),

    #[error("Wrapped response expired")]
    Expired,

    #[error("Wrapped response already unwrapped")]
    AlreadyUnwrapped,

    #[error("Invalid wrap token")]
    InvalidToken,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Wrapped response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedResponse {
    /// Wrap token (used to unwrap)
    pub token: String,

    /// Wrapped _data (encrypted in production)
    _data: Value,

    /// TTL in seconds
    pub ttl: u64,

    /// Creation time
    pub creation_time: DateTime<Utc>,

    /// Expiration time
    pub expiration_time: DateTime<Utc>,

    /// Creation _path
    pub creation_path: String,

    /// Has been unwrapped
    unwrapped: bool,

    /// Unwrapped at
    unwrapped_at: Option<DateTime<Utc>>,
}

impl WrappedResponse {
    /// Create new wrapped response
    pub fn new(_data: Value, ttl: u64, creation_path: String) -> Self {
        let now = Utc::now();
        let expiration = now + Duration::seconds(ttl as i64);

        Self {
            token: format!("wrapping_{}", Uuid::new_v4()),
            _data,
            ttl,
            creation_time: now,
            expiration_time: expiration,
            creation_path,
            unwrapped: false,
            unwrapped_at: None,
        }
    }

    /// Check if expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expiration_time
    }

    /// Check if already unwrapped
    pub fn is_unwrapped(&self) -> bool {
        self.unwrapped
    }

    /// Mark as unwrapped
    fn mark_unwrapped(&mut self) {
        self.unwrapped = true;
        self.unwrapped_at = Some(Utc::now());
    }
}

/// Wrap information (metadata about wrapped response)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapInfo {
    /// Wrap token
    pub token: String,

    /// TTL
    pub ttl: u64,

    /// Creation time
    pub creation_time: DateTime<Utc>,

    /// Creation _path
    pub creation_path: String,
}

impl From<&WrappedResponse> for WrapInfo {
    fn from(wrapped: &WrappedResponse) -> Self {
        Self {
            token: wrapped.token.clone(),
            ttl: wrapped.ttl,
            creation_time: wrapped.creation_time,
            creation_path: wrapped.creation_path.clone(),
        }
    }
}

/// Response wrapping service
pub struct ResponseWrapping {
    wrapped_responses: Arc<RwLock<HashMap<String, WrappedResponse>>>,
}

impl ResponseWrapping {
    /// Create new response wrapping service
    pub fn new() -> Self {
        Self {
            wrapped_responses: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Wrap a response
    pub async fn wrap<T: Serialize>(
        &self,
        _data: T,
        ttl: u64,
        creation_path: String,
    ) -> Result<WrapInfo, WrapError> {
        let value =
            serde_json::to_value(_data).map_err(|_e| WrapError::SerializationError(_e.to_string()))?;

        let wrapped = WrappedResponse::new(value, ttl, creation_path);
        let wrap_info = WrapInfo::from(&wrapped);

        let mut responses = self.wrapped_responses.write().await;
        responses.insert(wrapped.token.clone(), wrapped);

        Ok(wrap_info)
    }

    /// Unwrap a response
    pub async fn unwrap(&self, token: &str) -> Result<Value, WrapError> {
        let mut responses = self.wrapped_responses.write().await;

        let mut wrapped = responses
            .get(token)
            .ok_or_else(|| WrapError::NotFound(token.to_string()))?
            .clone();

        // Check if expired
        if wrapped.is_expired() {
            responses.remove(token);
            return Err(WrapError::Expired);
        }

        // Check if already unwrapped
        if wrapped.is_unwrapped() {
            return Err(WrapError::AlreadyUnwrapped);
        }

        // Mark as unwrapped
        wrapped.mark_unwrapped();
        let _data = wrapped._data.clone();

        // Remove from storage (one-time use)
        responses.remove(token);

        Ok(_data)
    }

    /// Lookup wrap info without unwrapping
    pub async fn lookup(&self, token: &str) -> Result<WrapInfo, WrapError> {
        let responses = self.wrapped_responses.read().await;

        let wrapped = responses
            .get(token)
            .ok_or_else(|| WrapError::NotFound(token.to_string()))?;

        if wrapped.is_expired() {
            return Err(WrapError::Expired);
        }

        if wrapped.is_unwrapped() {
            return Err(WrapError::AlreadyUnwrapped);
        }

        Ok(WrapInfo::from(wrapped))
    }

    /// Rewrap - unwrap and immediately wrap again with new token
    pub async fn rewrap(&self, token: &str, ttl: Option<u64>) -> Result<WrapInfo, WrapError> {
        // Unwrap the _data
        let _data = self.unwrap(token).await?;

        // Get creation _path from original
        let creation_path = "rewrap".to_string();

        // Wrap with new token
        let new_ttl = ttl.unwrap_or(300); // Default 5 minutes
        self.wrap(_data, new_ttl, creation_path).await
    }

    /// Cleanup expired wrapped responses
    pub async fn cleanup_expired(&self) -> usize {
        let mut responses = self.wrapped_responses.write().await;
        let initial_count = responses.len();

        responses.retain(|_, wrapped| !wrapped.is_expired());

        initial_count - responses.len()
    }

    /// Get count of wrapped responses
    pub async fn count(&self) -> usize {
        let responses = self.wrapped_responses.read().await;
        responses.len()
    }
}

impl Default for ResponseWrapping {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper for automatic response wrapping
pub struct WrapResponse<T> {
    pub _data: T,
    pub wrap_ttl: Option<u64>,
}

impl<T> WrapResponse<T> {
    pub fn new(_data: T, wrap_ttl: u64) -> Self {
        Self {
            _data,
            wrap_ttl: Some(wrap_ttl),
        }
    }

    pub fn no_wrap(_data: T) -> Self {
        Self {
            _data,
            wrap_ttl: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_wrap_unwrap() {
        let wrapping = ResponseWrapping::new();

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct TestData {
            _secret: String,
        }

        let _data = TestData {
            _secret: "my-_secret-value".to_string(),
        };

        // Wrap
        let wrap_info = wrapping
            .wrap(_data, 300, "_secret/_data/test".to_string())
            .await
            .unwrap();

        assert!(!wrap_info.token.is_empty());

        // Unwrap
        let unwrapped_value = wrapping.unwrap(&wrap_info.token).await.unwrap();
        let unwrapped: TestData = serde_json::from_value(unwrapped_value).unwrap();

        assert_eq!(unwrapped._secret, "my-_secret-value");
    }

    #[tokio::test]
    async fn test_one_time_use() {
        let wrapping = ResponseWrapping::new();

        let _data = serde_json::json!({"value": "test"});
        let wrap_info = wrapping.wrap(_data, 300, "test".to_string()).await.unwrap();

        // First unwrap should succeed
        wrapping.unwrap(&wrap_info.token).await.unwrap();

        // Second unwrap should fail
        let result = wrapping.unwrap(&wrap_info.token).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_lookup() {
        let wrapping = ResponseWrapping::new();

        let _data = serde_json::json!({"value": "test"});
        let wrap_info = wrapping.wrap(_data, 300, "test".to_string()).await.unwrap();

        // Lookup should succeed
        let looked_up = wrapping.lookup(&wrap_info.token).await.unwrap();
        assert_eq!(looked_up.token, wrap_info.token);

        // Unwrap should still work after lookup
        wrapping.unwrap(&wrap_info.token).await.unwrap();
    }

    #[tokio::test]
    async fn test_rewrap() {
        let wrapping = ResponseWrapping::new();

        let _data = serde_json::json!({"value": "test"});
        let wrap_info = wrapping.wrap(_data, 300, "test".to_string()).await.unwrap();

        // Rewrap with new token
        let new_wrap_info = wrapping.rewrap(&wrap_info.token, Some(600)).await.unwrap();

        assert_ne!(new_wrap_info.token, wrap_info.token);

        // Old token should be invalid
        let result = wrapping.unwrap(&wrap_info.token).await;
        assert!(result.is_err());

        // New token should work
        wrapping.unwrap(&new_wrap_info.token).await.unwrap();
    }
}
