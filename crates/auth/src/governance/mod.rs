//! Governance: policy enforcement, quotas, RBAC, audit devices and the seal.
//!
//! This was a separate `secreton-security` crate. It is a submodule of `secreton-auth`
//! because every type here answers the same question the rest of the crate does — may
//! this principal perform this operation, and what is recorded about it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub mod audit;
pub mod auto_unseal;
pub mod error;
pub mod policies;

pub use audit::{AuditBackend, AuditError, AuditLog, AuditStatus};
pub use auto_unseal::{AutoUnsealError, KmsProvider};
pub use error::SecurityError;
pub use policies::audit::{AuditEvent, AuditEventType, AuditStatus as PolicyAuditStatus};
pub use policies::quotas::{QuotaConfig, QuotaType, QuotaUsage};

/// Security context for operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// User identity
    pub identity: String,
    /// Client IP address
    pub client_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
    /// Session ID
    pub session_id: Option<String>,
    /// Request path
    pub path: String,
    /// HTTP method
    pub method: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Security decision
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityDecision {
    /// Access allowed
    Allow,
    /// Access denied with reason
    Deny { reason: String },
    /// Access requires additional verification
    Challenge { challenge_type: String },
}

/// Security policy engine trait
#[async_trait::async_trait]
pub trait SecurityEngine: Send + Sync {
    /// Evaluate security context against policies
    async fn evaluate(&self, context: &SecurityContext) -> Result<SecurityDecision, SecurityError>;

    /// Log security event
    async fn log_event(&self, event: AuditEvent) -> Result<(), SecurityError>;
}
