//! Audit service module
//! TODO: Implement full audit functionality

use async_trait::async_trait;

/// External audit device trait
#[async_trait]
pub trait ExternalAuditDevice: Send + Sync {
    /// Send audit log to external device
    async fn send_audit_log(&self, log: &str) -> Result<(), Box<dyn std::error::Error>>;
}
