//! Storage models and data structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// User information for access control in storage layer
/// Note: This is a simplified version for storage. The full User model is in secreton-core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub roles: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub is_active: bool,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub user_id: Uuid,
    pub action: String,
    pub resource_type: String,
    pub resource_id: Option<String>,
    pub details: HashMap<String, serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub success: bool,
    pub error_message: Option<String>,
}

/// Session information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_activity: DateTime<Utc>,
    pub is_active: bool,
}

/// Access control policy
/// Note: Simplified version for storage. Full Policy model is in secreton-core.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub rules: Vec<PolicyRule>,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub is_active: bool,
}

/// Individual policy rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    pub resource_pattern: String,
    pub actions: Vec<String>,
    pub effect: PolicyEffect,
    pub conditions: Option<HashMap<String, serde_json::Value>>,
}

/// Policy effect (allow or deny)
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum PolicyEffect {
    Allow,
    Deny,
}

/// Backup information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub backup_type: BackupType,
    pub size_bytes: u64,
    pub entry_count: u64,
    pub created_by: Uuid,
    pub created_at: DateTime<Utc>,
    pub storage_location: String,
    pub encryption_key_id: String,
    pub checksum: String,
}

/// Type of backup
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum BackupType {
    Full,
    Incremental,
    Differential,
}
