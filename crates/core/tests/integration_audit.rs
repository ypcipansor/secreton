use secret_versioning::SecretHistory;
use granular_revocation::{RevocationRegistry, RevocationScope};
use audit_log::{AuditLog, AuditEvent};

#[test]
fn test_secret_versioning_and_revocation_audit() {
    let mut audit_log = AuditLog::new("/tmp/secreton_integration_audit.log");
    let _ = std::fs::remove_file("/tmp/secreton_integration_audit.log");

    // Secret Versioning: put_secret
    let mut history = SecretHistory::new("bank-api-key");
    let v1 = history.put_secret("secret1".to_string(), "alice".to_string(), None, "audit1".to_string());
    history.log_audit_event(&mut audit_log, "put_secret", "alice", "created v1", "hash1", None);

    // Secret Versioning: update
    let v2 = history.put_secret("secret2".to_string(), "bob".to_string(), Some("changed value".to_string()), "audit2".to_string());
    history.log_audit_event(&mut audit_log, "put_secret", "bob", "updated to v2", "hash2", Some("hash1".to_string()));

    // Granular Revocation
    let mut registry = RevocationRegistry::new();
    let scope = RevocationScope::Secret("bank-api-key".to_string());
    registry.revoke(scope.clone(), "compromised".to_string(), "admin".to_string(), "audit3".to_string());
    registry.log_audit_event(&mut audit_log, &scope, "admin", "revoked due to compromise", "hash3", Some("hash2".to_string()));

    // Audit log must contain all events
    audit_log.load_events().unwrap();
    assert_eq!(audit_log.events.len(), 3);
    assert_eq!(audit_log.events[0].event_type, "put_secret");
    assert_eq!(audit_log.events[1].event_type, "put_secret");
    assert_eq!(audit_log.events[2].event_type, "revoke_secret");
    let _ = std::fs::remove_file("/tmp/secreton_integration_audit.log");
}
