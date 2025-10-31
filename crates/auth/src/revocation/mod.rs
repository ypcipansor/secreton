// Granular Revocation Module - Maximum Security, Zero Trust, Tamper-Evident

use chrono::{DateTime, Utc};
use secreton_security::audit::{AuditLog, AuditLogger, AuditStatus};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RevocationScope {
    Secret(String),  // Single secret by name
    Subtree(String), // All secrets under a path/prefix
    User(String),    // All secrets accessed by a user
    Session(String), // All secrets in a session
    Type(String),    // All secrets of a type (e.g., API key)
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
        Self {
            revoked: HashSet::new(),
            events: Vec::new(),
        }
    }

    /// Utility: Log a revocation event to the audit log
    pub async fn log_audit_event(
        &self,
        audit_logger: &AuditLogger,
        scope: &RevocationScope,
        actor: &str,
        reason: &str,
        hash: &str,
        prev_hash: Option<String>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut metadata = HashMap::new();
        metadata.insert("scope".to_string(), format!("{:?}", scope));
        metadata.insert("reason".to_string(), reason.to_string());
        metadata.insert("hash".to_string(), hash.to_string());
        if let Some(prev) = prev_hash {
            metadata.insert("prev_hash".to_string(), prev);
        }

        let entry = AuditLog {
            id: uuid::Uuid::new_v4(),
            timestamp: Utc::now(),
            action: "revoke_secret".to_string(),
            actor: Some(actor.to_string()),
            resource_type: "revocation".to_string(),
            resource_id: hash.to_string(),
            status: AuditStatus::Success,
            ip: None,
            user_agent: None,
            metadata,
        };

        audit_logger.log(entry).await?;
        Ok(())
    }

    pub fn revoke(
        &mut self,
        scope: RevocationScope,
        reason: String,
        actor: String,
        audit_id: String,
    ) {
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
