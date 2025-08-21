//! Contoh penggunaan MemorySecretsEngine dengan audit log dan policy enforcement
use serde_json::json;
use brankas_adhyaksa::secrets::engine::memory::MemorySecretsEngine;
use brankas_adhyaksa::audit::{AuditLogger, MemoryBackend};
use brankas_adhyaksa::services::policy::{PolicySet, PolicyRule};
use std::sync::Arc;

tokio::main]
async fn main() {
    // Setup audit logger
    let audit_backend = Arc::new(MemoryBackend::default());
    let audit_logger = AuditLogger::new(vec![audit_backend.clone()]);

    // Setup policy: hanya user "alice" boleh create/read/update/delete path "secret/foo" dengan MFA
    let policy = PolicySet {
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
            PolicyRule {
                effect: "allow".to_string(),
                action: "update".to_string(),
                path: "secret/foo".to_string(),
                condition: None,
                control_group: None,
                mfa: Some(true),
            },
            PolicyRule {
                effect: "allow".to_string(),
                action: "delete".to_string(),
                path: "secret/foo".to_string(),
                condition: None,
                control_group: None,
                mfa: Some(true),
            },
        ],
    };

    // Inisialisasi engine dengan audit dan policy
    let engine = MemorySecretsEngine::with_audit_and_policy(audit_logger.clone(), policy);

    // Simulasi context MFA lolos
    let context = json!({"mfa_passed": true});
    let user = "alice";
    let path = "secret/foo";

    // Create secret
    let secret = engine.create_secret(path, json!({"foo": "bar"}), None, user, Some(&context)).await;
    println!("Create: {:?}", secret);

    // Read secret
    let secret = engine.read_secret(path, user, Some(&context)).await;
    println!("Read: {:?}", secret);

    // Update secret
    let secret = engine.update_secret(path, json!({"foo": "baz"}), None, user, Some(&context)).await;
    println!("Update: {:?}", secret);

    // Delete secret
    let result = engine.delete_secret(path, user, Some(&context)).await;
    println!("Delete: {:?}", result);

    // Audit log
    let logs = audit_backend.logs();
    println!("Audit log: {:#?}", logs);
}
