//! Security and compliance errors

use thiserror::Error;

/// Security and compliance errors
#[derive(Debug, Error)]
pub enum SecurityError {
    #[error("Policy violation: {policy} - {reason}")]
    PolicyViolation { policy: String, reason: String },

    #[error("Compliance violation: {standard} - {requirement}")]
    ComplianceViolation { standard: String, requirement: String },

    #[error("Access denied: {reason}")]
    AccessDenied { reason: String },

    #[error("Audit logging failed: {0}")]
    AuditError(String),

    #[error("Quota exceeded: {resource} limit {limit}, used {used}")]
    QuotaExceeded { resource: String, limit: u64, used: u64 },

    #[error("Security context invalid: {reason}")]
    InvalidSecurityContext { reason: String },

    #[error("Governance policy error: {0}")]
    GovernanceError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] Box<dyn std::error::Error + Send + Sync>),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal security error: {0}")]
    InternalError(String),
}