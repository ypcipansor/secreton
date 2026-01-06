//! Audit Trail for Secret Versioning
//! Maximum Security, Tamper-Evident, Zero Error

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

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

    /// Calculate hash for this audit entry
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.audit_id);
        hasher.update(&self.secret_name);
        hasher.update(self.version.to_string().as_bytes());
        hasher.update(&self.action);
        hasher.update(&self.actor);
        hasher.update(self.timestamp.timestamp().to_string().as_bytes());
        if let Some(diff) = &self.diff {
            hasher.update(diff);
        }
        if let Some(prev) = &self.prev_hash {
            hasher.update(prev);
        }
        format!("{:x}", hasher.finalize())
    }

    /// Verify this entry's hash matches calculated hash
    pub fn verify_hash(&self) -> bool {
        self.calculate_hash() == self.hash
    }
}

/// Tamper-evident audit log storage
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct AuditLog {
    pub entries: Vec<AuditEntry>,
    pub entry_index: HashMap<String, usize>, // audit_id -> index
    pub latest_hash: Option<String>,
}

impl AuditLog {
    /// Create new audit log
    pub fn new() -> Self {
        Self::default()
    }

    /// Add audit entry with hash chain integrity
    pub fn add_entry(&mut self, mut entry: AuditEntry) -> Result<(), String> {
        // Set previous hash to current latest
        entry.prev_hash = self.latest_hash.clone();

        // Calculate and set hash
        entry.hash = entry.calculate_hash();

        // Update latest hash
        self.latest_hash = Some(entry.hash.clone());

        // Store entry
        let index = self.entries.len();
        self.entry_index.insert(entry.audit_id.clone(), index);
        self.entries.push(entry);

        Ok(())
    }

    /// Get entry by audit ID
    pub fn get_entry(&self, audit_id: &str) -> Option<&AuditEntry> {
        self.entry_index
            .get(audit_id)
            .and_then(|&index| self.entries.get(index))
    }

    /// Verify integrity of entire hash chain
    pub fn verify_chain(&self) -> bool {
        let mut expected_prev_hash = None;

        for entry in &self.entries {
            // Verify entry's hash
            if !entry.verify_hash() {
                return false;
            }

            // Verify chain continuity
            if entry.prev_hash != expected_prev_hash {
                return false;
            }

            // Update expected previous hash for next entry
            expected_prev_hash = Some(entry.hash.clone());
        }

        true
    }

    /// Get all entries for a specific secret
    pub fn get_secret_entries(&self, secret_name: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .filter(|e| e.secret_name == secret_name)
            .collect()
    }
}
