//! Test untuk MemorySecretsEngine: zero trust, audit, policy, MFA
use serde_json::json;
use brankas_adhyaksa::secrets::engine::memory::MemorySecretsEngine;
use brankas_adhyaksa::audit::{AuditLogger, MemoryBackend, AuditStatus};
use brankas_adhyaksa::services::policy::{PolicySet, PolicyRule};
use std::sync::Arc;

#[tokio::test]
async fn test_memory_engine_policy_and_audit() {
    let audit_backend = Arc::new(MemoryBackend::default());
    let audit_logger = AuditLogger::new(vec![audit_backend.clone()]);
    let policy = PolicySet {
        rules: vec![
            PolicyRule {
                effect: "allow".to_string(),
                action: "read".to_string(),
                path: "secret/foo".to_string(),
                condition: None,
                control_group: None,
                mfa: Some(true),
            },
        ],
    };
    let engine = MemorySecretsEngine::with_audit_and_policy(audit_logger.clone(), policy);
    let context = json!({"mfa_passed": true});
    let user = "alice";
    let path = "secret/foo";
    // Create (tanpa policy create, harus denied)
    let res = engine.create_secret(path, json!({"foo": "bar"}), None, user, Some(&context)).await;
    assert!(res.is_err());
    // Tambah policy create
    let mut engine = MemorySecretsEngine::with_audit_and_policy(audit_logger.clone(), PolicySet {
        rules: vec![
            PolicyRule {
                effect: "allow".to_string(),
                action: "create".to_string(),
                path: "secret/foo".to_string(),
                condition: None,
                control_group: None,
                mfa: Some(true),
            },
            PolicyRule {
                effect: "allow".to_string(),
                action: "read".to_string(),
                path: "secret/foo".to_string(),
                condition: None,
                control_group: None,
                mfa: Some(true),
            },
        ],
    });
    let res = engine.create_secret(path, json!({"foo": "bar"}), None, user, Some(&context)).await;
    assert!(res.is_ok());
    // Read (MFA wajib, context harus benar)
    let res = engine.read_secret(path, user, Some(&context)).await;
    assert!(res.is_ok());
    // Read (MFA gagal)
    let context_fail = json!({"mfa_passed": false});
    let res = engine.read_secret(path, user, Some(&context_fail)).await;
    assert!(res.is_err());
    // Audit log harus ada
    let logs = audit_backend.logs();
    assert!(logs.iter().any(|l| l.action == "create" && l.status == AuditStatus::Success));
    assert!(logs.iter().any(|l| l.action == "read" && l.status == AuditStatus::Success));
    assert!(logs.iter().any(|l| l.action == "read" && l.status == AuditStatus::Denied));
}
