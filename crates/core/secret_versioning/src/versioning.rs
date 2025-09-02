use audit_log::{AuditLog, AuditEvent};
impl SecretHistory {
    /// Utility: Log a secret event to the audit log
    pub fn log_audit_event(
        &self,
        audit_log: &mut AuditLog,
        event_type: &str,
        actor: &str,
        details: &str,
        hash: &str,
        prev_hash: Option<String>,
    ) {
        let event = AuditEvent::new(
            uuid::Uuid::new_v4().to_string(),
            event_type.to_string(),
            actor.to_string(),
            self.name.clone(),
            details.to_string(),
            prev_hash,
            hash.to_string(),
        );
        let _ = audit_log.append_event(event);
    }
}
// Secret Versioning & Audit Trail Module - Maximum Security, Zero Trust, Forever Secret

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub version: u64,
    pub value: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
    pub diff: Option<String>, // Optional: diff from previous version
    pub audit_id: String,     // Link to audit log entry
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SecretHistory {
    pub name: String,
    pub versions: BTreeMap<u64, SecretVersion>, // version -> SecretVersion
    pub current_version: u64,
}

impl SecretHistory {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            versions: BTreeMap::new(),
            current_version: 0,
        }
    }

    pub fn put_secret(&mut self, value: String, created_by: String, diff: Option<String>, audit_id: String) -> u64 {
        self.current_version += 1;
        let version = self.current_version;
        let secret_version = SecretVersion {
            version,
            value,
            created_at: Utc::now(),
            created_by,
            diff,
            audit_id,
        };
        self.versions.insert(version, secret_version);
        version
    }

    pub fn get_secret(&self, version: Option<u64>) -> Option<&SecretVersion> {
        match version {
            Some(v) => self.versions.get(&v),
            None => self.versions.get(&self.current_version),
        }
    }

    pub fn list_versions(&self) -> Vec<u64> {
        self.versions.keys().cloned().collect()
    }

    pub fn rollback(&mut self, version: u64, by: String, audit_id: String) -> Option<u64> {
        if let Some(secret) = self.versions.get(&version) {
            let rollback_value = secret.value.clone();
            Some(self.put_secret(rollback_value, by, Some(format!("rollback to v{}", version)), audit_id))
        } else {
            None
        }
    }
}

// TODO: Integrate with global audit log, access control, and storage backend
// TODO: Add cryptographic proof (hash chain) for tamper-evidence
// TODO: Add secure deletion/ephemeral secret support
