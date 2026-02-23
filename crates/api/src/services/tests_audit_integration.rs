
use std::sync::Arc;
use crate::services::audit::{AuditLogger, SecurityEventType};
use secreton_storage::{MockStorageBackend, QueryParams, StorageBackend};
use secreton_security::policies::audit::{AuditEventType, AuditStatus};

#[tokio::test]
async fn test_audit_log_persistence() {
    // 1. Setup Storage
    let storage = Arc::new(MockStorageBackend::new());

    // 2. Setup Logger
    let logger = AuditLogger::new(storage.clone()).await.expect("Failed to create logger");

    // 3. Log an event (success - might buffer)
    let event = SecurityEventType::SecretAccess {
        secret_path: "secret/data/test".to_string(),
        user: "user-123".to_string(),
        action: "read".to_string(),
    };
    logger.log_event(event).await;

    // 4. Log a critical event (failure - should flush immediately)
    let fail_event = SecurityEventType::AuthenticationFailure {
        user: "bad-user".to_string(),
        method: "password".to_string(),
        reason: "wrong password".to_string(),
    };
    logger.log_event(fail_event).await;

    // Wait a small bit just in case of async dispatch
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 5. Verify Persistence
    let params = QueryParams {
        path_prefix: Some("sys/audit/".to_string()),
        ..Default::default()
    };
    let entries = storage.list(&params).await.expect("Failed to list entries");

    // We expect at least one entry (the failure one should definitely be there if logic holds)
    assert!(!entries.is_empty(), "Storage should contain audit logs");

    // Verify content of one entry
    let entry = &entries[0];
    assert!(entry.path.starts_with("sys/audit/"));
    assert!(entry.metadata.contains_key("log_data"));

    let log_json = entry.metadata.get("log_data").unwrap();
    // Check fields in JSON
    assert!(log_json.contains("auth.login") || log_json.contains("secret.read"));

    // If we only flushed one, it should be the failure one
    if entries.len() == 1 {
        assert!(log_json.contains("bad-user"));
        assert!(log_json.contains("failure"));
    }
}
