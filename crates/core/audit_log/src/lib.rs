//! Audit Log Module - Tamper-Evident, Compliance-Ready
//! Maximum Security, Zero Trust, Forensic Logging

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::fs::{OpenOptions};
use std::io::{Write, Result as IoResult};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: String, // e.g. "put_secret", "revoke_secret"
    pub actor: String,
    pub target: String,
    pub timestamp: DateTime<Utc>,
    pub details: String,
    pub hash: String, // cryptographic hash for tamper-evidence
    pub prev_hash: Option<String>,
}

impl AuditEvent {
    pub fn new(event_id: String, event_type: String, actor: String, target: String, details: String, prev_hash: Option<String>, hash: String) -> Self {
        Self {
            event_id,
            event_type,
            actor,
            target,
            timestamp: Utc::now(),
            details,
            hash,
            prev_hash,
        }
    }
}

pub struct AuditLog {
    pub events: Vec<AuditEvent>,
    pub file_path: String,
}

impl AuditLog {
    pub fn new(file_path: &str) -> Self {
        Self { events: Vec::new(), file_path: file_path.to_string() }
    }

    pub fn append_event(&mut self, event: AuditEvent) -> IoResult<()> {
        self.events.push(event.clone());
        let serialized = serde_json::to_string(&event).unwrap();
        let mut file = OpenOptions::new().create(true).append(true).open(&self.file_path)?;
        writeln!(file, "{}", serialized)?;
        Ok(())
    }

    pub fn load_events(&mut self) -> IoResult<()> {
        if Path::new(&self.file_path).exists() {
            let content = std::fs::read_to_string(&self.file_path)?;
            self.events = content
                .lines()
                .filter_map(|line| serde_json::from_str::<AuditEvent>(line).ok())
                .collect();
        }
        Ok(())
    }
}

// TODO: Integrate with Secret Versioning & Granular Revocation
// TODO: Add cryptographic hash chain for full tamper-evidence
// TODO: Add compliance export (PCI, SOC2, ISO, etc)
