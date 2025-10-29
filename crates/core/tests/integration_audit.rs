use std::collections::HashMap;
use std::sync::Arc;
use secreton_security::audit::{AuditLogger, AuditLog, AuditStatus, MemoryBackend};
use secreton_auth::revocation::{RevocationRegistry, RevocationScope};
use secreton_storage::storage_backends::secret_versioning::{VersionHistory, SecretVersion, VersionMetadata, ChangeType};

#[test]
fn test_secret_versioning_and_revocation_audit() {
    let audit_backend = Arc::new(MemoryBackend::default());
    let audit_logger = AuditLogger::new(vec![audit_backend.clone()]);

    // Secret Versioning: Create version history
    let mut history = VersionHistory {
        secret_path: "bank-api-key".to_string(),
        versions: Vec::new(),
        current_version: 0,
    };

    // Create first version
    let v1 = SecretVersion {
        version: 1,
        data: "secret1".to_string(),
        created_by: "alice".to_string(),
        created_at: chrono::Utc::now(),
        checksum: "hash1".to_string(),
        metadata: VersionMetadata {
            change_type: ChangeType::Create,
            change_reason: None,
            tags: vec![],
            approved_by: None,
        },
    };
    history.versions.push(v1);
    history.current_version = 1;

    // Log audit event for creation
    let audit_entry = AuditLog {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        action: "put_secret".to_string(),
        actor: Some("alice".to_string()),
        resource_type: "secret".to_string(),
        resource_id: "bank-api-key".to_string(),
        status: AuditStatus::Success,
        ip: None,
        user_agent: None,
        metadata: HashMap::from([
            ("version".to_string(), "1".to_string()),
            ("change".to_string(), "created v1".to_string()),
        ]),
    };
    let _ = tokio::runtime::Runtime::new().unwrap().block_on(audit_logger.log(audit_entry));

    // Create second version
    let v2 = SecretVersion {
        version: 2,
        data: "secret2".to_string(),
        created_by: "bob".to_string(),
        created_at: chrono::Utc::now(),
        checksum: "hash2".to_string(),
        metadata: VersionMetadata {
            change_type: ChangeType::Update,
            change_reason: Some("changed value".to_string()),
            tags: vec![],
            approved_by: None,
        },
    };
    history.versions.push(v2);
    history.current_version = 2;

    // Log audit event for update
    let audit_entry2 = AuditLog {
        id: uuid::Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        action: "put_secret".to_string(),
        actor: Some("bob".to_string()),
        resource_type: "secret".to_string(),
        resource_id: "bank-api-key".to_string(),
        status: AuditStatus::Success,
        ip: None,
        user_agent: None,
        metadata: HashMap::from([
            ("version".to_string(), "2".to_string()),
            ("change".to_string(), "updated to v2".to_string()),
            ("previous_hash".to_string(), "hash1".to_string()),
        ]),
    };
    let _ = tokio::runtime::Runtime::new().unwrap().block_on(audit_logger.log(audit_entry2));

    // Granular Revocation
    let mut registry = RevocationRegistry::new();
    let scope = RevocationScope::Secret("bank-api-key".to_string());
    registry.revoke(
        scope.clone(),
        "compromised".to_string(),
        "admin".to_string(),
        "audit3".to_string(),
    );

    // Verify revocation
    assert!(registry.is_revoked(&scope));

    // Verify audit logs were recorded
    let logs = audit_backend.logs();
    assert_eq!(logs.len(), 2);

    println!("✅ Secret versioning, revocation, and audit integration test passed");
}
