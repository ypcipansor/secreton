//! Common types and traits for SDK libraries
//!
//! This module contains the shared types, configurations, and traits
//! used across all SDK implementations.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Common SDK configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkConfig {
    /// Server URL
    pub server_url: String,
    /// API token for authentication
    pub api_token: String,
    /// Request timeout in seconds
    pub timeout: u64,
    /// Enable TLS verification
    pub verify_tls: bool,
    /// Custom headers
    pub headers: HashMap<String, String>,
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self {
            server_url: "https://localhost:8200".to_string(),
            api_token: "".to_string(),
            timeout: 30,
            verify_tls: true,
            headers: HashMap::new(),
        }
    }
}

/// SDK response wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data
    pub data: Option<T>,
    /// Error message
    pub error: Option<String>,
    /// Response metadata
    pub metadata: HashMap<String, String>,
}

/// Secret data for SDK operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkSecret {
    /// Secret path
    pub path: String,
    /// Secret data
    pub data: HashMap<String, String>,
    /// Custom metadata
    pub metadata: Option<HashMap<String, String>>,
    /// Time-to-live in seconds
    pub ttl: Option<u64>,
}

/// SDK operation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkOperationResult {
    /// Operation success
    pub success: bool,
    /// Operation message
    pub message: String,
    /// Operation metadata
    pub metadata: HashMap<String, String>,
}

/// Base SDK trait that all language SDKs implement
pub trait SecretonSdk {
    /// Create a new secret
    fn create_secret(&self, secret: SdkSecret) -> Result<SdkOperationResult, String>;

    /// Read a secret
    fn read_secret(&self, path: &str) -> Result<SdkResponse<SdkSecret>, String>;

    /// Update a secret
    fn update_secret(
        &self,
        path: &str,
        data: HashMap<String, String>,
    ) -> Result<SdkOperationResult, String>;

    /// Delete a secret
    fn delete_secret(&self, path: &str) -> Result<SdkOperationResult, String>;

    /// List secrets under a path
    fn list_secrets(&self, path: &str) -> Result<SdkResponse<Vec<String>>, String>;

    /// Health check
    fn health_check(&self) -> Result<SdkResponse<HashMap<String, String>>, String>;
}