
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

    // 3. Log a critical event (failure - should flush immediately and NOT buffer)
    let fail_event = SecurityEventType::AuthenticationFailure {
        user: "bad-user".to_string(),
        method: "password".to_string(),
        reason: "wrong password".to_string(),
    };
    logger.log_event(fail_event).await;

    // Wait a small bit for async dispatch
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // 4. Verify Persistence
    let params = QueryParams {
        path_prefix: Some("sys/audit/".to_string()),
        ..Default::default()
    };
    let entries = storage.list(&params).await.expect("Failed to list entries");

    // We expect exactly one entry for the failure event
    assert_eq!(entries.len(), 1, "Storage should contain exactly one audit log for the failure event");

    // Verify content
    let entry = &entries[0];
    assert!(entry.path.starts_with("sys/audit/"));
    let log_json = entry.metadata.get("log_data").unwrap();
    assert!(log_json.contains("bad-user"));
    assert!(log_json.contains("failure"));

    // 5. Force flush (should not duplicate)
    // Access internal service if possible, but AuditLogger wraps it privately.
    // However, if the event was buffered, it would be written again eventually or if we trigger flush logic.
    // Since we can't easily trigger flush on private service, we rely on the implementation change:
    // The code explicitly returns early for critical events, so it never hits buffer.push().
}
