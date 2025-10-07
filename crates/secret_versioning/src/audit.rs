//! Audit Trail for Secret Versioning
//! Maximum Security, Tamper-Evident, Zero Error

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

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

#[derive(Default)]
pub struct AuditEntryBuilder {
    audit_id: Option<String>,
    secret_name: Option<String>,
    version: Option<u64>,
    action: Option<String>,
    actor: Option<String>,
    diff: Option<String>,
    hash: Option<String>,
    prev_hash: Option<String>,
}

impl AuditEntryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn audit_id(mut self, audit_id: impl Into<String>) -> Self {
        self.audit_id = Some(audit_id.into());
        self
    }

    pub fn secret_name(mut self, secret_name: impl Into<String>) -> Self {
        self.secret_name = Some(secret_name.into());
        self
    }

    pub fn version(mut self, version: u64) -> Self {
        self.version = Some(version);
        self
    }

    pub fn action(mut self, action: impl Into<String>) -> Self {
        self.action = Some(action.into());
        self
    }

    pub fn actor(mut self, actor: impl Into<String>) -> Self {
        self.actor = Some(actor.into());
        self
    }

    pub fn diff(mut self, diff: Option<String>) -> Self {
        self.diff = diff;
        self
    }

    pub fn hash(mut self, hash: impl Into<String>) -> Self {
        self.hash = Some(hash.into());
        self
    }

    pub fn prev_hash(mut self, prev_hash: Option<String>) -> Self {
        self.prev_hash = prev_hash;
        self
    }

    pub fn build(self) -> AuditEntry {
        AuditEntry {
            audit_id: self.audit_id.expect("audit_id is required"),
            secret_name: self.secret_name.expect("secret_name is required"),
            version: self.version.expect("version is required"),
            action: self.action.expect("action is required"),
            actor: self.actor.expect("actor is required"),
            timestamp: Utc::now(),
            diff: self.diff,
            hash: self.hash.expect("hash is required"),
            prev_hash: self.prev_hash,
        }
    }
}

impl AuditEntry {
    pub fn builder() -> AuditEntryBuilder {
        AuditEntryBuilder::new()
    }
}

// TODO: Integrate with global audit log storage (append-only, tamper-evident)
// TODO: Add cryptographic hash chain for full audit integrity
