//! Audit logging functionality for security tracking.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use crate::{error::CoreError, ResourceId, SecurityLevel};

/// Audit log entry representing a security-relevant event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Unique identifier for this audit entry
    pub id: String,
    
    /// Timestamp when the event occurred
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// User ID who performed the action (if applicable)
    pub user_id: Option<String>,
    
    /// Session ID associated with the action
    pub session_id: Option<String>,
    
    /// Action that was performed
    pub action: String,
    
    /// Resource that was acted upon
    pub resource: Option<ResourceId>,
    
    /// IP address of the client
    pub client_ip: Option<String>,
    
    /// User agent string
    pub user_agent: Option<String>,
    
    /// Whether the action was successful
    pub success: bool,
    
    /// Error message if the action failed
    pub error: Option<String>,
    
    /// Additional context and metadata
    pub metadata: HashMap<String, serde_json::Value>,
    
    /// Security classification of this audit entry
    pub security_level: SecurityLevel,
    
    /// Source component that generated this entry
    pub source: String,
}

impl AuditEntry {
    /// Create a new audit entry builder
    pub fn builder() -> AuditEntryBuilder {
        AuditEntryBuilder::new()
    }

    /// Create a successful audit entry
    pub fn success(action: String, resource: Option<ResourceId>) -> Self {
        Self::builder()
            .action(action)
            .resource(resource)
            .success(true)
            .build()
    }

    /// Create a failed audit entry
    pub fn failure(action: String, resource: Option<ResourceId>, error: String) -> Self {
        Self::builder()
            .action(action)
            .resource(resource)
            .success(false)
            .error(error)
            .build()
    }

    /// Add metadata to the audit entry
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Set user context
    pub fn with_user(mut self, user_id: String, session_id: Option<String>) -> Self {
        self.user_id = Some(user_id);
        self.session_id = session_id;
        self
    }

    /// Set client context
    pub fn with_client(mut self, ip: Option<String>, user_agent: Option<String>) -> Self {
        self.client_ip = ip;
        self.user_agent = user_agent;
        self
    }
}

/// Builder for creating audit entries
pub struct AuditEntryBuilder {
    entry: AuditEntry,
}

impl AuditEntryBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            entry: AuditEntry {
                id: Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now(),
                user_id: None,
                session_id: None,
                action: String::new(),
                resource: None,
                client_ip: None,
                user_agent: None,
                success: false,
                error: None,
                metadata: HashMap::new(),
                security_level: SecurityLevel::Internal,
                source: "brankas-core".to_string(),
            },
        }
    }

    /// Set the action
    pub fn action(mut self, action: String) -> Self {
        self.entry.action = action;
        self
    }

    /// Set the resource
    pub fn resource(mut self, resource: Option<ResourceId>) -> Self {
        self.entry.resource = resource;
        self
    }

    /// Set the user ID
    pub fn user_id(mut self, user_id: String) -> Self {
        self.entry.user_id = Some(user_id);
        self
    }

    /// Set the session ID
    pub fn session_id(mut self, session_id: String) -> Self {
        self.entry.session_id = Some(session_id);
        self
    }

    /// Set success status
    pub fn success(mut self, success: bool) -> Self {
        self.entry.success = success;
        self
    }

    /// Set error message
    pub fn error(mut self, error: String) -> Self {
        self.entry.error = Some(error);
        self
    }

    /// Set client IP
    pub fn client_ip(mut self, ip: String) -> Self {
        self.entry.client_ip = Some(ip);
        self
    }

    /// Set user agent
    pub fn user_agent(mut self, user_agent: String) -> Self {
        self.entry.user_agent = Some(user_agent);
        self
    }

    /// Set security level
    pub fn security_level(mut self, level: SecurityLevel) -> Self {
        self.entry.security_level = level;
        self
    }

    /// Set source component
    pub fn source(mut self, source: String) -> Self {
        self.entry.source = source;
        self
    }

    /// Add metadata
    pub fn metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.entry.metadata.insert(key, value);
        self
    }

    /// Build the audit entry
    pub fn build(self) -> AuditEntry {
        self.entry
    }
}

/// Trait for audit log storage backends
#[async_trait::async_trait]
pub trait AuditStorage: Send + Sync {
    /// Store an audit entry
    async fn store(&self, entry: &AuditEntry) -> Result<(), CoreError>;
    
    /// Retrieve audit entries with optional filtering
    async fn retrieve(
        &self,
        filters: AuditFilters,
    ) -> Result<Vec<AuditEntry>, CoreError>;
    
    /// Count total audit entries matching filters
    async fn count(&self, filters: AuditFilters) -> Result<u64, CoreError>;
    
    /// Delete audit entries older than specified date
    async fn cleanup_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, CoreError>;
}

/// Filters for querying audit entries
#[derive(Debug, Clone, Default)]
pub struct AuditFilters {
    /// Start time (inclusive)
    pub start_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// End time (inclusive)
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    
    /// User ID filter
    pub user_id: Option<String>,
    
    /// Action filter (can use wildcards)
    pub action: Option<String>,
    
    /// Resource filter
    pub resource: Option<ResourceId>,
    
    /// Success status filter
    pub success: Option<bool>,
    
    /// Security level filter (minimum level)
    pub min_security_level: Option<SecurityLevel>,
    
    /// Source component filter
    pub source: Option<String>,
    
    /// Maximum number of results
    pub limit: Option<u32>,
    
    /// Number of results to skip
    pub offset: Option<u32>,
}

impl AuditFilters {
    /// Create a new filter builder
    pub fn builder() -> AuditFiltersBuilder {
        AuditFiltersBuilder::new()
    }
}

/// Builder for audit filters
pub struct AuditFiltersBuilder {
    filters: AuditFilters,
}

impl AuditFiltersBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            filters: AuditFilters::default(),
        }
    }

    /// Set time range
    pub fn time_range(
        mut self,
        start: chrono::DateTime<chrono::Utc>,
        end: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        self.filters.start_time = Some(start);
        self.filters.end_time = Some(end);
        self
    }

    /// Set user ID filter
    pub fn user_id(mut self, user_id: String) -> Self {
        self.filters.user_id = Some(user_id);
        self
    }

    /// Set action filter
    pub fn action(mut self, action: String) -> Self {
        self.filters.action = Some(action);
        self
    }

    /// Set resource filter
    pub fn resource(mut self, resource: ResourceId) -> Self {
        self.filters.resource = Some(resource);
        self
    }

    /// Set success filter
    pub fn success_only(mut self) -> Self {
        self.filters.success = Some(true);
        self
    }

    /// Set failure filter
    pub fn failures_only(mut self) -> Self {
        self.filters.success = Some(false);
        self
    }

    /// Set minimum security level
    pub fn min_security_level(mut self, level: SecurityLevel) -> Self {
        self.filters.min_security_level = Some(level);
        self
    }

    /// Set pagination
    pub fn paginate(mut self, limit: u32, offset: u32) -> Self {
        self.filters.limit = Some(limit);
        self.filters.offset = Some(offset);
        self
    }

    /// Build the filters
    pub fn build(self) -> AuditFilters {
        self.filters
    }
}

/// Audit logger for recording security events
pub struct AuditLogger {
    storage: Arc<dyn AuditStorage>,
    source: String,
}

impl AuditLogger {
    /// Create a new audit logger
    pub async fn new(storage: Arc<dyn AuditStorage>) -> Result<Self, CoreError> {
        Ok(Self {
            storage,
            source: "brankas".to_string(),
        })
    }

    /// Create audit logger with custom source
    pub async fn with_source(
        storage: Arc<dyn AuditStorage>,
        source: String,
    ) -> Result<Self, CoreError> {
        Ok(Self { storage, source })
    }

    /// Log a successful action
    pub async fn log_success(
        &self,
        action: String,
        resource: Option<ResourceId>,
        user_id: Option<String>,
    ) -> Result<(), CoreError> {
        let entry = AuditEntry::builder()
            .action(action)
            .resource(resource)
            .user_id(user_id.unwrap_or_default())
            .success(true)
            .source(self.source.clone())
            .build();

        self.storage.store(&entry).await
    }

    /// Log a failed action
    pub async fn log_failure(
        &self,
        action: String,
        resource: Option<ResourceId>,
        user_id: Option<String>,
        error: String,
    ) -> Result<(), CoreError> {
        let entry = AuditEntry::builder()
            .action(action)
            .resource(resource)
            .user_id(user_id.unwrap_or_default())
            .success(false)
            .error(error)
            .source(self.source.clone())
            .build();

        self.storage.store(&entry).await
    }

    /// Log a custom audit entry
    pub async fn log(&self, entry: AuditEntry) -> Result<(), CoreError> {
        self.storage.store(&entry).await
    }

    /// Retrieve audit entries
    pub async fn get_entries(&self, filters: AuditFilters) -> Result<Vec<AuditEntry>, CoreError> {
        self.storage.retrieve(filters).await
    }

    /// Count audit entries
    pub async fn count_entries(&self, filters: AuditFilters) -> Result<u64, CoreError> {
        self.storage.count(filters).await
    }

    /// Cleanup old audit entries
    pub async fn cleanup_before(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, CoreError> {
        self.storage.cleanup_before(before).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_entry_builder() {
        let entry = AuditEntry::builder()
            .action("create_secret".to_string())
            .user_id("user123".to_string())
            .success(true)
            .metadata("key".to_string(), serde_json::Value::String("value".to_string()))
            .build();

        assert_eq!(entry.action, "create_secret");
        assert_eq!(entry.user_id, Some("user123".to_string()));
        assert!(entry.success);
        assert_eq!(
            entry.metadata.get("key"),
            Some(&serde_json::Value::String("value".to_string()))
        );
    }

    #[test]
    fn test_audit_filters_builder() {
        let filters = AuditFilters::builder()
            .user_id("user123".to_string())
            .action("create_*".to_string())
            .success_only()
            .paginate(50, 0)
            .build();

        assert_eq!(filters.user_id, Some("user123".to_string()));
        assert_eq!(filters.action, Some("create_*".to_string()));
        assert_eq!(filters.success, Some(true));
        assert_eq!(filters.limit, Some(50));
        assert_eq!(filters.offset, Some(0));
    }
}
