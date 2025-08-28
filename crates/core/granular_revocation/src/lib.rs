use audit_log::{AuditLog, AuditEvent};
impl RevocationRegistry {
    /// Utility: Log a revocation event to the audit log
    pub fn log_audit_event(
        &self,
        audit_log: &mut AuditLog,
        scope: &RevocationScope,
        actor: &str,
        reason: &str,
        hash: &str,
        prev_hash: Option<String>,
    ) {
        let event = AuditEvent::new(
            uuid::Uuid::new_v4().to_string(),
            "revoke_secret".to_string(),
            actor.to_string(),
            format!("{:?}", scope),
            reason.to_string(),
            prev_hash,
            hash.to_string(),
        );
        let _ = audit_log.append_event(event);
    }
}
// Granular Revocation Module - Maximum Security, Zero Trust, Tamper-Evident

use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RevocationScope {
    Secret(String),      // Single secret by name
    Subtree(String),     // All secrets under a path/prefix
    User(String),        // All secrets accessed by a user
    Session(String),     // All secrets in a session
    Type(String),        // All secrets of a type (e.g., API key)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEvent {
    pub scope: RevocationScope,
    pub reason: String,
    pub actor: String,
    pub timestamp: DateTime<Utc>,
    pub audit_id: String,
}

#[derive(Default)]
pub struct RevocationRegistry {
    pub revoked: HashSet<RevocationScope>,
    pub events: Vec<RevocationEvent>,
}

impl RevocationRegistry {
    pub fn new() -> Self {
        Self { revoked: HashSet::new(), events: Vec::new() }
    }

    pub fn revoke(&mut self, scope: RevocationScope, reason: String, actor: String, audit_id: String) {
        self.revoked.insert(scope.clone());
        self.events.push(RevocationEvent {
            scope,
            reason,
            actor,
            timestamp: Utc::now(),
            audit_id,
        });
    }

    pub fn is_revoked(&self, scope: &RevocationScope) -> bool {
        self.revoked.contains(scope)
    }

    pub fn list_events(&self) -> &Vec<RevocationEvent> {
        &self.events
    }
}

// TODO: Integrate with Secret Versioning, Audit Trail, and Policy Engine
// TODO: Add cascading revoke (subtree, user, session)
// TODO: Tamper-evident log and compliance export
