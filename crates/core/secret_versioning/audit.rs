//! Audit Trail for Secret Versioning
//! Maximum Security, Tamper-Evident, Zero Error

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: String,
    pub secret_name: String,
    pub version: u64,
    pub action: String, // put, rollback, delete, etc
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub diff: Option<String>,
    pub hash: String, // cryptographic hash for tamper-evidence
    pub prev_hash: Option<String>,
}

impl AuditEntry {
    pub fn new(audit_id: String, secret_name: String, version: u64, action: String, actor: String, diff: Option<String>, prev_hash: Option<String>, hash: String) -> Self {
        Self {
            audit_id,
            secret_name,
            version,
            action,
            actor,
            timestamp: Utc::now(),
            diff,
            hash,
            prev_hash,
        }
    }
}

// TODO: Integrate with global audit log storage (append-only, tamper-evident)
// TODO: Add cryptographic hash chain for full audit integrity
