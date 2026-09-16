//! Audit event vocabulary.
//!
//! Audit records are the compliance surface of a secrets manager, so the shape lives in the
//! domain crate and every producer — REST handlers, gRPC services, background workers — emits
//! the same structure rather than an ad-hoc map.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

/// Outcome of the audited operation. Recorded explicitly so a denied access is
/// distinguishable from one that never completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Success,
    Denied,
    Failure,
}

/// A single audited operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    /// Dotted event name, e.g. `secret.read` or `auth.login`.
    pub event_type: String,
    /// Principal that performed the action, or `"anonymous"` for unauthenticated attempts.
    pub actor: String,
    /// Resource acted upon, e.g. a secret path.
    pub resource: String,
    pub action: String,
    pub outcome: AuditOutcome,
    /// Client IP as resolved by the trusted-proxy configuration, when known.
    pub client_ip: Option<String>,
    /// Correlates the event with the `x-request-id` on the originating request.
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl AuditEvent {
    /// Start a successful event. Use the builder methods to attach context.
    pub fn new(
        event_type: impl Into<String>,
        actor: impl Into<String>,
        resource: impl Into<String>,
        action: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type: event_type.into(),
            actor: actor.into(),
            resource: resource.into(),
            action: action.into(),
            outcome: AuditOutcome::Success,
            client_ip: None,
            request_id: None,
            metadata: HashMap::new(),
        }
    }

    pub fn with_outcome(mut self, outcome: AuditOutcome) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn with_client_ip(mut self, ip: Option<String>) -> Self {
        self.client_ip = ip;
        self
    }

    pub fn with_request_id(mut self, id: Option<String>) -> Self {
        self.request_id = id;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_default_to_success_and_carry_no_empty_metadata_key() {
        let event = AuditEvent::new("secret.read", "alice", "kv/db/password", "read");
        assert_eq!(event.outcome, AuditOutcome::Success);
        let json = serde_json::to_value(&event).unwrap();
        assert!(json.get("metadata").is_none());
    }

    #[test]
    fn builder_records_denial_context() {
        let event = AuditEvent::new("secret.read", "mallory", "kv/db/password", "read")
            .with_outcome(AuditOutcome::Denied)
            .with_client_ip(Some("203.0.113.7".into()))
            .with_request_id(Some("req-1".into()));
        assert_eq!(event.outcome, AuditOutcome::Denied);
        assert_eq!(event.client_ip.as_deref(), Some("203.0.113.7"));
        assert_eq!(event.request_id.as_deref(), Some("req-1"));
    }
}
