//! Comprehensive Audit Logging Service
//!
//! Provides detailed audit trails for all operations in Secreton with support
//! for multiple backends (file, database, syslog, webhook).

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Audit event type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Authentication events
    #[serde(rename = "auth.login")]
    AuthLogin,
    #[serde(rename = "auth.logout")]
    AuthLogout,
    #[serde(rename = "auth.token.create")]
    AuthTokenCreate,
    #[serde(rename = "auth.token.revoke")]
    AuthTokenRevoke,
    #[serde(rename = "auth.token.renew")]
    AuthTokenRenew,

    /// Secret operations
    #[serde(rename = "secret.read")]
    SecretRead,
    #[serde(rename = "secret.write")]
    SecretWrite,
    #[serde(rename = "secret.delete")]
    SecretDelete,
    #[serde(rename = "secret.list")]
    SecretList,

    /// Policy operations
    #[serde(rename = "policy.create")]
    PolicyCreate,
    #[serde(rename = "policy.update")]
    PolicyUpdate,
    #[serde(rename = "policy.delete")]
    PolicyDelete,
    #[serde(rename = "policy.read")]
    PolicyRead,

    /// Lease operations
    #[serde(rename = "lease.create")]
    LeaseCreate,
    #[serde(rename = "lease.renew")]
    LeaseRenew,
    #[serde(rename = "lease.revoke")]
    LeaseRevoke,

    /// System operations
    #[serde(rename = "sys.mount")]
    SysMount,
    #[serde(rename = "sys.unmount")]
    SysUnmount,
    #[serde(rename = "sys.rekey")]
    SysRekey,
    #[serde(rename = "sys.seal")]
    SysSeal,
    #[serde(rename = "sys.unseal")]
    SysUnseal,
    #[serde(rename = "sys.rotate")]
    SysRotate,

    /// Other
    #[serde(untagged)]
    Custom(String),
}

impl AuditEventType {
    pub fn as_str(&self) -> &str {
        match self {
            AuditEventType::AuthLogin => "auth.login",
            AuditEventType::AuthLogout => "auth.logout",
            AuditEventType::AuthTokenCreate => "auth.token.create",
            AuditEventType::AuthTokenRevoke => "auth.token.revoke",
            AuditEventType::AuthTokenRenew => "auth.token.renew",
            AuditEventType::SecretRead => "secret.read",
            AuditEventType::SecretWrite => "secret.write",
            AuditEventType::SecretDelete => "secret.delete",
            AuditEventType::SecretList => "secret.list",
            AuditEventType::PolicyCreate => "policy.create",
            AuditEventType::PolicyUpdate => "policy.update",
            AuditEventType::PolicyDelete => "policy.delete",
            AuditEventType::PolicyRead => "policy.read",
            AuditEventType::LeaseCreate => "lease.create",
            AuditEventType::LeaseRenew => "lease.renew",
            AuditEventType::LeaseRevoke => "lease.revoke",
            AuditEventType::SysMount => "sys.mount",
            AuditEventType::SysUnmount => "sys.unmount",
            AuditEventType::SysRekey => "sys.rekey",
            AuditEventType::SysSeal => "sys.seal",
            AuditEventType::SysUnseal => "sys.unseal",
            AuditEventType::SysRotate => "sys.rotate",
            AuditEventType::Custom(s) => s,
        }
    }
}

/// Audit event status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditStatus {
    Success,
    Failure,
    Denied,
}

impl AuditStatus {
    pub fn as_str(&self) -> &str {
        match self {
            AuditStatus::Success => "success",
            AuditStatus::Failure => "failure",
            AuditStatus::Denied => "denied",
        }
    }
}

/// Comprehensive audit event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Event ID
    pub id: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Event type
    pub event_type: AuditEventType,

    /// Status
    pub status: AuditStatus,

    /// User/entity performing the action
    pub user: String,

    /// User display name
    pub display_name: Option<String>,

    /// Client IP address
    pub client_ip: Option<String>,

    /// Resource path/identifier
    pub resource: String,

    /// Operation details
    pub operation: String,

    /// HTTP method (if applicable)
    pub method: Option<String>,

    /// Request ID
    pub request_id: Option<String>,

    /// Token accessor (not the actual token)
    pub token_accessor: Option<String>,

    /// Policies applied
    pub policies: Vec<String>,

    /// Error message (if failed)
    pub error: Option<String>,

    /// Additional metadata
    pub metadata: HashMap<String, String>,

    /// Duration in milliseconds
    pub duration_ms: Option<u64>,
}

impl AuditEvent {
    /// Create new audit event
    pub fn new(
        event_type: AuditEventType,
        status: AuditStatus,
        user: String,
        resource: String,
        operation: String,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            status,
            user,
            display_name: None,
            client_ip: None,
            resource,
            operation,
            method: None,
            request_id: None,
            token_accessor: None,
            policies: Vec::new(),
            error: None,
            metadata: HashMap::new(),
            duration_ms: None,
        }
    }

    /// Format as JSON line
    pub fn to_json_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Format as syslog message
    pub fn to_syslog(&self) -> String {
        format!(
            "<134>1 {} secreton {} - - - event={} user={} resource={} status={}",
            self.timestamp.to_rfc3339(),
            self.id,
            self.event_type.as_str(),
            self.user,
            self.resource,
            self.status.as_str()
        )
    }
}

/// Audit device trait
#[async_trait]
pub trait AuditDevice: Send + Sync {
    /// Log audit event
    async fn log(&self, event: &AuditEvent)
    -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Flush buffered events
    async fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

/// File audit device
pub struct FileAuditDevice {
    pub file_path: String,
    pub format: FileFormat,
}

#[derive(Debug, Clone)]
pub enum FileFormat {
    Json,
    Text,
}

#[async_trait]
impl AuditDevice for FileAuditDevice {
    async fn log(
        &self,
        event: &AuditEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.file_path)?;

        let line = match self.format {
            FileFormat::Json => format!("{}\n", event.to_json_line()),
            FileFormat::Text => format!(
                "{} [{}] user={} op={} resource={} status={}\n",
                event.timestamp.to_rfc3339(),
                event.event_type.as_str(),
                event.user,
                event.operation,
                event.resource,
                event.status.as_str()
            ),
        };

        file.write_all(line.as_bytes())?;
        Ok(())
    }
}

/// Database audit device
pub struct DbAuditDevice {
    // In production, would have database connection pool
}

#[async_trait]
impl AuditDevice for DbAuditDevice {
    async fn log(
        &self,
        event: &AuditEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In production, would insert into database
        log_audit_db(
            &event.user,
            event.event_type.as_str(),
            &event.resource,
            event.status.as_str(),
        );
        Ok(())
    }
}

/// Syslog audit device
pub struct SyslogAuditDevice {
    pub address: String,
}

#[async_trait]
impl AuditDevice for SyslogAuditDevice {
    async fn log(
        &self,
        event: &AuditEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // In production, would send to syslog server
        // For now, just format the message
        let _message = event.to_syslog();
        Ok(())
    }
}

/// Webhook audit device.
///
/// Behind the `webhook` feature, so the type cannot exist in a build with no HTTP client
/// to send with.
#[cfg(feature = "webhook")]
pub struct WebhookAuditDevice {
    pub url: String,
}

#[cfg(feature = "webhook")]
#[async_trait]
impl AuditDevice for WebhookAuditDevice {
    async fn log(
        &self,
        event: &AuditEvent,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let payload = serde_json::json!({
            "id": event.id,
            "timestamp": event.timestamp.to_rfc3339(),
            "event": event.event_type.as_str(),
            "user": event.user,
            "resource": event.resource,
            "operation": event.operation,
            "status": event.status.as_str(),
            "metadata": event.metadata,
        });

        // `error_for_status` matters: without it a 500 from the collector counted as a
        // delivered audit event.
        reqwest::Client::new()
            .post(&self.url)
            .json(&payload)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

/// Audit service
pub struct AuditService {
    devices: Arc<RwLock<Vec<Box<dyn AuditDevice>>>>,
    buffer: Arc<RwLock<Vec<AuditEvent>>>,
    buffer_size: usize,
}

impl AuditService {
    /// Create new audit service
    pub fn new(buffer_size: usize) -> Self {
        Self {
            devices: Arc::new(RwLock::new(Vec::new())),
            buffer: Arc::new(RwLock::new(Vec::new())),
            buffer_size,
        }
    }

    /// Add audit device
    pub async fn add_device(&self, device: Box<dyn AuditDevice>) {
        let mut devices = self.devices.write().await;
        devices.push(device);
    }

    /// Log audit event
    pub async fn log(&self, event: AuditEvent) {
        // Log to devices immediately for critical events, without buffering
        if matches!(event.status, AuditStatus::Denied | AuditStatus::Failure) {
            let devices = self.devices.read().await;
            for device in devices.iter() {
                let _ = device.log(&event).await;
            }
            return;
        }

        let mut buffer = self.buffer.write().await;
        buffer.push(event.clone());

        // Flush if buffer is full
        if buffer.len() >= self.buffer_size {
            drop(buffer);
            let _ = self.flush().await;
        }
    }

    /// Flush buffered events
    pub async fn flush(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut buffer = self.buffer.write().await;
        let events: Vec<AuditEvent> = buffer.drain(..).collect();
        drop(buffer);

        let devices = self.devices.read().await;
        for event in events {
            for device in devices.iter() {
                let _ = device.log(&event).await;
            }
        }

        Ok(())
    }

    /// Get buffer size
    pub async fn buffer_len(&self) -> usize {
        let buffer = self.buffer.read().await;
        buffer.len()
    }
}

impl Default for AuditService {
    fn default() -> Self {
        Self::new(100)
    }
}

// Legacy compatibility functions
pub fn log_audit(
    _devices: &[Box<dyn AuditDevice>],
    _user: &str,
    _action: &str,
    _path: &str,
    _status: &str,
) {
    // Legacy sync function - kept for compatibility
}

pub fn log_audit_db(_user: &str, _action: &str, _path: &str, _status: &str) {
    // Legacy DB logging - kept for compatibility
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_event_creation() {
        let event = AuditEvent::new(
            AuditEventType::SecretRead,
            AuditStatus::Success,
            "user@example.com".to_string(),
            "/secret/data/myapp".to_string(),
            "read".to_string(),
        );

        assert_eq!(event.event_type.as_str(), "secret.read");
        assert_eq!(event.status.as_str(), "success");
        assert!(!event.id.is_empty());
    }

    #[tokio::test]
    async fn test_audit_service() {
        let service = AuditService::new(10);

        let event = AuditEvent::new(
            AuditEventType::AuthLogin,
            AuditStatus::Success,
            "testuser".to_string(),
            "/auth/login".to_string(),
            "login".to_string(),
        );

        service.log(event).await;
        assert_eq!(service.buffer_len().await, 1);
    }

    #[tokio::test]
    async fn test_json_formatting() {
        let event = AuditEvent::new(
            AuditEventType::SecretWrite,
            AuditStatus::Success,
            "admin".to_string(),
            "/secret/data/test".to_string(),
            "write".to_string(),
        );

        let json = event.to_json_line();
        assert!(json.contains("secret.write"));
        assert!(json.contains("admin"));
    }
}
