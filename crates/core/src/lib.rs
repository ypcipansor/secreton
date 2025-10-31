//! # Brankas Core
//!
//! Core types, traits, and utilities shared across the Brankas security system.
//! Provides foundational abstractions for security levels, audit logging,
//! error handling, and common data structures.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod api;
pub mod models;
pub mod sdk_libraries;
pub mod security;
pub mod services;
pub mod storage;
pub mod types;

// Re-export shared crates with specific imports to avoid conflicts
pub use secreton_common::{Result as CommonResult, SecurityLevel};
pub use secreton_config::{
    AuthConfig, Config, ConsulStorageConfig as ConfigConsulStorageConfig, DatabaseConfig,
    DynamoDBStorageConfig as ConfigDynamoDBStorageConfig,
    EtcdStorageConfig as ConfigEtcdStorageConfig, MySQLStorageConfig as ConfigMySQLStorageConfig,
    RaftConfig as ConfigRaftConfig, S3StorageConfig as ConfigS3StorageConfig, ServerConfig,
    StorageBackendType as ConfigStorageBackendType, StorageConfig as ConfigStorageConfig,
    TlsConfig,
};
pub use secreton_errors::*;
pub use secreton_replication::{DisasterRecoveryService, PerformanceReplication};
pub use secreton_storage::{
    QueryParams as StorageQueryParams, RaftConfig as StorageRaftConfig, StorageBackend,
    StorageBackendType as StorageStorageBackendType, StorageConfig as StorageStorageConfig,
    StorageResult, VaultEntry,
};

// Re-export for backward compatibility
pub type CoreError = SecretonError;
pub type CoreResult<T> = secreton_common::Result<T>;
// Commented out imports that don't exist yet
// pub use auth::mfa::MfaMethod;
// pub use graphql_api::{create_graphql_schema, GraphQLConfig, DefaultSecretsManager as GraphQLSecretsManager};
// pub use grpc_api::{GrpcConfig, SecretsGrpcService};
// pub use utils::error::AppError;

// Re-export commonly used models
// Auth models now exported from auth-methods crate
// pub use models::auth::{
//     AuthMethod, AuthMethodType, AuthRequest, AuthResponse, LoginRequest, LoginResponse,
//     RefreshTokenRequest, UserInfo,
// };
// Use security crate for policy types
pub use secreton_security::policies::policy::{ControlGroup, Policy, PolicyRule};
// User and Token models now exported from auth-methods crate
// pub use models::user::{Token, User};

// Include integration tests - Disabled: missing dependencies
// #[cfg(test)]
// mod integration_tests;

/// Metadata structure for extensible data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Metadata {
    pub fields: HashMap<String, serde_json::Value>,
}

impl Metadata {
    /// Create new empty metadata
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Set a metadata field
    pub fn set<K, V>(&mut self, key: K, value: V)
    where
        K: Into<String>,
        V: Into<serde_json::Value>,
    {
        self.fields.insert(key.into(), value.into());
    }

    /// Get a metadata field
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.fields.get(key)
    }

    /// Get a typed metadata field
    pub fn get_typed<T>(&self, key: &str) -> Option<T>
    where
        T: serde::de::DeserializeOwned,
    {
        self.fields
            .get(key)
            .and_then(|v| serde_json::from_value(v.clone()).ok())
    }

    /// Check if metadata contains key
    pub fn contains_key(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Remove a metadata field
    pub fn remove(&mut self, key: &str) -> Option<serde_json::Value> {
        self.fields.remove(key)
    }

    /// Get all field names
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.fields.keys()
    }

    /// Check if metadata is empty
    pub fn is_empty(&self) -> bool {
        self.fields.is_empty()
    }

    /// Get number of fields
    pub fn len(&self) -> usize {
        self.fields.len()
    }
}

impl Default for Metadata {
    fn default() -> Self {
        Self::new()
    }
}

/// Tag system for organizing resources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tags {
    pub tags: Vec<String>,
}

impl Tags {
    /// Create new empty tags
    pub fn new() -> Self {
        Self { tags: Vec::new() }
    }

    /// Create tags from vector
    pub fn from_vec(tags: Vec<String>) -> Self {
        Self { tags }
    }

    /// Add a tag
    pub fn add<S: Into<String>>(&mut self, tag: S) {
        let tag = tag.into();
        if !self.tags.contains(&tag) {
            self.tags.push(tag);
        }
    }

    /// Remove a tag
    pub fn remove(&mut self, tag: &str) {
        self.tags.retain(|t| t != tag);
    }

    /// Check if contains tag
    pub fn contains(&self, tag: &str) -> bool {
        self.tags.contains(&tag.to_string())
    }

    /// Get all tags
    pub fn as_slice(&self) -> &[String] {
        &self.tags
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.tags.is_empty()
    }

    /// Get tag count
    pub fn len(&self) -> usize {
        self.tags.len()
    }
}

impl Default for Tags {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Vec<String>> for Tags {
    fn from(tags: Vec<String>) -> Self {
        Self::from_vec(tags)
    }
}

impl IntoIterator for Tags {
    type Item = String;
    type IntoIter = std::vec::IntoIter<String>;

    fn into_iter(self) -> Self::IntoIter {
        self.tags.into_iter()
    }
}

/// Resource identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResourceId {
    pub namespace: String,
    pub id: String,
}

impl ResourceId {
    /// Create new resource ID
    pub fn new(namespace: String, id: String) -> Self {
        Self { namespace, id }
    }

    /// Get the full resource path
    pub fn full_path(&self) -> String {
        format!("{}/{}", self.namespace, self.id)
    }
}

impl std::fmt::Display for ResourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert!(SecurityLevel::TopSecret > SecurityLevel::Secret);
        assert!(SecurityLevel::Secret > SecurityLevel::Confidential);
        assert!(SecurityLevel::Confidential > SecurityLevel::Internal);
        assert!(SecurityLevel::Internal > SecurityLevel::Public);

        assert!(SecurityLevel::TopSecret.can_access(SecurityLevel::Public));
        assert!(!SecurityLevel::Public.can_access(SecurityLevel::Secret));
    }

    #[test]
    fn test_security_level_from_string() {
        assert_eq!(SecurityLevel::parse("public"), Some(SecurityLevel::Public));
        assert_eq!(
            SecurityLevel::parse("CONFIDENTIAL"),
            Some(SecurityLevel::Confidential)
        );
        assert_eq!(
            SecurityLevel::parse("top-secret"),
            Some(SecurityLevel::TopSecret)
        );
        assert_eq!(SecurityLevel::parse("invalid"), None);

        // Test FromStr trait implementation
        assert_eq!("public".parse::<SecurityLevel>(), Ok(SecurityLevel::Public));
        assert_eq!(
            "confidential".parse::<SecurityLevel>(),
            Ok(SecurityLevel::Confidential)
        );
        assert!("invalid".parse::<SecurityLevel>().is_err());
    }

    #[test]
    fn test_metadata() {
        let mut metadata = Metadata::new();
        assert!(metadata.is_empty());

        metadata.set("key1", "value1");
        metadata.set("key2", 42);

        assert_eq!(metadata.len(), 2);
        assert!(metadata.contains_key("key1"));
        assert_eq!(
            metadata.get_typed::<String>("key1"),
            Some("value1".to_string())
        );
        assert_eq!(metadata.get_typed::<i32>("key2"), Some(42));
    }

    #[test]
    fn test_tags() {
        let mut tags = Tags::new();
        assert!(tags.is_empty());

        tags.add("important");
        tags.add("secure");
        tags.add("important"); // Should not duplicate

        assert_eq!(tags.len(), 2);
        assert!(tags.contains("important"));
        assert!(tags.contains("secure"));
        assert!(!tags.contains("other"));

        tags.remove("important");
        assert_eq!(tags.len(), 1);
        assert!(!tags.contains("important"));
    }

    #[test]
    fn test_resource_id() {
        let id = ResourceId::new("secrets".to_string(), "database-password".to_string());
        assert_eq!(id.full_path(), "secrets/database-password");
        assert_eq!(id.to_string(), "secrets/database-password");
    }
}
