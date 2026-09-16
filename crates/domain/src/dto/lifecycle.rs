use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Shared Secret Lifecycle Status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretStatus {
    Active,
    Expiring,
    Expired,
    Archived,
}

/// Shared Secret Lifecycle Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretLifecycle {
    pub secret_path: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub archived_at: Option<DateTime<Utc>>,
    pub status: SecretStatus,
    pub ttl_days: u32,
    pub grace_period_days: u32,
}

/// Shared Lifecycle Statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleStatistics {
    pub total_secrets: usize,
    pub active_secrets: usize,
    pub expiring_secrets: usize,
    pub expired_secrets: usize,
    pub archived_secrets: usize,
}
