
use std::sync::Arc;
use crate::services::audit::{AuditLogger, SecurityEventType};
use secreton_storage::{MockStorageBackend, QueryParams, StorageBackend};
use secreton_security::policies::audit::{AuditEventType, AuditStatus};
use crate::services::admin::AdminService;
use secreton_performance::SecretPerformanceOptimizer;
use crate::config::AuthConfig;
use crate::services::auth::AuthenticationService;
use crate::services::crypto::CryptoService;

#[tokio::test]
async fn test_audit_log_persistence() {
    // 1. Setup Storage
    let storage = Arc::new(MockStorageBackend::new());

    // 2. Setup Logger
    let logger = Arc::new(AuditLogger::new(storage.clone()).await.expect("Failed to create logger"));

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

    // Verify content and expiration
    let entry = &entries[0];
    assert!(entry.path.starts_with("sys/audit/"));
    assert!(entry.expires_at.is_some(), "Audit entry should have expiration set");

    let log_json = entry.metadata.get("log_data").unwrap();
    assert!(log_json.contains("bad-user"));
    assert!(log_json.contains("failure"));

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
    assert_eq!(entries_after.len(), 2, "Storage should contain both events after flush");

    // 6. Verify AdminService Retrieval (End-to-End Test)
    // Setup minimal AdminService dependencies
    let crypto = Arc::new(CryptoService::new(storage.clone()).await.unwrap());
    let mut config = AuthConfig::default();
    config.jwt.secret = Some("test_secret".to_string());
    config.jwt.issuer = "secreton".to_string();
    config.jwt.audience = "secreton-api".to_string();
    let auth = Arc::new(AuthenticationService::new(storage.clone(), crypto, &config).await.unwrap());
    let performance = Arc::new(SecretPerformanceOptimizer::default());

    let admin_service = AdminService::new(storage.clone(), auth, logger.clone(), performance).await.unwrap();

    // Fetch logs via AdminService
    let logs = admin_service.get_audit_logs(None, None, None, None, None).await.expect("Failed to fetch audit logs");

    assert_eq!(logs.len(), 2, "AdminService should retrieve both logs");

    // Verify mapped fields
    let fail_log = logs.iter().find(|l| l.user_id == "bad-user").expect("Should find failure log");
    assert!(!fail_log.success);
    assert_eq!(fail_log.action, "login"); // AuthenticationFailure -> AuthLogin -> "login"

    let success_log = logs.iter().find(|l| l.user_id == "good-user").expect("Should find success log");
    assert!(success_log.success);
    assert_eq!(success_log.action, "login"); // AuthenticationSuccess -> AuthLogin -> "login"
}
