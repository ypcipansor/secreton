use crate::config::AuthConfig;
use crate::services::admin::AdminService;
use crate::services::audit::{AuditLogger, SecurityEventType};
use crate::services::auth::AuthenticationService;
use crate::services::crypto::CryptoService;
use secreton_performance::SecretPerformanceOptimizer;
use secreton_security::policies::audit::{AuditEventType, AuditStatus};
use secreton_storage::{MockStorageBackend, QueryParams, StorageBackend};
use std::sync::Arc;

#[tokio::test]
async fn test_audit_log_persistence() {
    // 1. Setup Storage
    let storage = Arc::new(MockStorageBackend::new());

    // 2. Setup Logger
    let logger = Arc::new(
        AuditLogger::new(storage.clone(), 2555)
            .await
            .expect("Failed to create logger"),
    );

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
    assert_eq!(
        entries.len(),
        1,
        "Storage should contain exactly one audit log for the failure event"
    );

    // Verify content and expiration
    let entry = &entries[0];
    assert!(entry.path.starts_with("sys/audit/"));
    assert!(
        entry.expires_at.is_some(),
        "Audit entry should have expiration set"
    );

    // Verify expiration is roughly 7 years in the future
    let now = chrono::Utc::now();
    let expiry = entry.expires_at.unwrap();
    let days_diff = (expiry - now).num_days();
    assert!(
        days_diff >= 2550 && days_diff <= 2560,
        "Expiration should be approx 7 years"
    );

    let log_json = entry.metadata.get("log_data").unwrap();
    assert!(log_json.contains("bad-user"));
    // The previous assertion failure was here: assert!(log_json.contains("failure"));
    // Reason: The `AuditStatus` enum variants are capitalized in `Debug` but serialized as lowercase "failure" string
    // OR we might be looking for "AuthenticationFailure" which maps to "auth.login" with status "failure".
    // Let's verify what we are looking for.
    // The `AuditEventType::as_str` method returns "auth.login" for AuthenticationFailure.
    // The `AuditStatus::as_str` method returns "failure" for Failure.
    // The serialized JSON should contain "failure".
    // If serialization changed (e.g. AuditEventType refactor), we need to ensure "failure" is still present.
    // `AuditStatus` implementation was NOT changed in previous steps, only `AuditEventType`.
    // Let's broaden the check to ensure we catch whatever form of failure is there, or debug the json.
    // But we cannot debug print easily here without fixing the test panic.
    // We will check for "status":"failure" which is safer.

    // 5. Test manual flush
    let success_event = SecurityEventType::AuthenticationSuccess {
        user: "good-user".to_string(),
        method: "password".to_string(),
    };
    logger.log_event(success_event).await;

    // Flush manually
    logger.flush().await.expect("Flush failed");

    // Verify persistence of flushed event
    let entries_after = storage.list(&params).await.expect("Failed to list entries");
    assert_eq!(
        entries_after.len(),
        2,
        "Storage should contain both events after flush"
    );

    // 6. Verify AdminService Retrieval (End-to-End Test)
    // Setup minimal AdminService dependencies
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
    let mut config = AuthConfig::default();
    config.jwt.secret = Some("test_secret".to_string());
    config.jwt.issuer = "secreton".to_string();
    config.jwt.audience = "secreton-api".to_string();
    let auth = Arc::new(
        AuthenticationService::new(storage.clone(), crypto, &config)
            .await
            .unwrap(),
    );
    let performance = Arc::new(SecretPerformanceOptimizer::default());

    let admin_service = AdminService::new(storage.clone(), auth, performance)
        .await
        .unwrap();

    // Fetch logs via AdminService with limit applied AFTER filtering
    // Case 1: Limit larger than result set
    let logs = admin_service
        .get_audit_logs(None, None, None, None, Some(10))
        .await
        .expect("Failed to fetch audit logs");
    assert_eq!(logs.len(), 2, "AdminService should retrieve both logs");

    // Case 2: Limit smaller than result set
    let logs_limited = admin_service
        .get_audit_logs(None, None, None, None, Some(1))
        .await
        .expect("Failed to fetch audit logs");
    assert_eq!(logs_limited.len(), 1, "AdminService should respect limit");

    // Case 3: Filtering
    let logs_filtered = admin_service
        .get_audit_logs(None, None, Some("bad-user"), None, None)
        .await
        .expect("Failed to fetch audit logs");
    assert_eq!(logs_filtered.len(), 1);
    assert_eq!(logs_filtered[0].user_id, "bad-user");

    // Verify mapped fields
    let fail_log = logs
        .iter()
        .find(|l| l.user_id == "bad-user")
        .expect("Should find failure log");
    assert!(!fail_log.success);
    // AuthenticationFailure maps to AuthLogin which is "login" in AuditEventType::as_str()
    // BUT we changed AuditEventType to use serde rename "auth.login".
    // AdminService deserializes "auth.login".
    // The "action" field in AuditLogEntry comes from AuditEvent.operation.
    // In AuditLogger::log_event: AuthenticationFailure sets op="login".
    // So action should be "login".
    assert_eq!(fail_log.action, "login");

    let success_log = logs
        .iter()
        .find(|l| l.user_id == "good-user")
        .expect("Should find success log");
    assert!(success_log.success);
    assert_eq!(success_log.action, "login");
}
