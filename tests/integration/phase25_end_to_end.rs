//! Phase 25: End-to-End Integration Tests
//!
//! Tests comprehensive workflows across all 5 enterprise integration services:
//! 1. authenticated_key_operations
//! 2. policy_enforced_crypto
//! 3. privacy_preserving_auth
//! 4. secure_collaborative_operations
//! 5. end_to_end_observability_pipeline

use chrono::Utc;
use secreton_core::services::authenticated_key_operations::*;
use secreton_core::services::policy_enforced_crypto::*;
use secreton_core::services::privacy_preserving_auth::*;
use secreton_core::services::secure_collaborative_operations::*;
use secreton_core::services::end_to_end_observability_pipeline::*;
use std::collections::HashMap;
use uuid::Uuid;

#[tokio::test]
async fn test_complete_key_lifecycle_with_audit() {
    // Test authenticated key operations with full audit trail
    let service = AuthenticatedKeyService::new();

    // Generate new key with authentication
    let token = "test-token-123".to_string();
    let generate_req = KeyOperationRequest {
        token: token.clone(),
        operation: KeyOperation::Generate {
            key_type: KeyType::AES256,
            purpose: KeyPurpose::Encryption,
            owner: "user@example.com".to_string(),
        },
        metadata: HashMap::from([
            ("environment".to_string(), "production".to_string()),
            ("compliance".to_string(), "pci-dss".to_string()),
        ]),
    };

    let result = service.perform_operation(generate_req).await;
    assert!(result.is_ok());
    let generate_result = result.unwrap();
    assert!(generate_result.success);
    assert!(generate_result.metrics_recorded);
    let key_id = generate_result.key_id.clone();

    // Rotate the key
    let rotate_req = KeyOperationRequest {
        token: token.clone(),
        operation: KeyOperation::Rotate { key_id: key_id.clone() },
        metadata: HashMap::new(),
    };

    let rotate_result = service.perform_operation(rotate_req).await;
    assert!(rotate_result.is_ok());

    // Escrow the key
    let escrow_req = KeyOperationRequest {
        token: token.clone(),
        operation: KeyOperation::Escrow {
            key_id: key_id.clone(),
            threshold: 3,
            approvers: vec![
                "admin1@example.com".to_string(),
                "admin2@example.com".to_string(),
                "admin3@example.com".to_string(),
                "admin4@example.com".to_string(),
                "admin5@example.com".to_string(),
            ],
        },
        metadata: HashMap::new(),
    };

    let escrow_result = service.perform_operation(escrow_req).await;
    assert!(escrow_result.is_ok());

    // Verify audit records were created
    let audit_records = service.get_audit_records().await;
    assert!(audit_records.len() >= 3); // generate, rotate, escrow
    
    // Verify no sensitive data in audit
    for record in &audit_records {
        assert!(record.key_material.is_none());
        assert!(record.sensitive_metadata.is_none());
    }

    // Verify metrics recorded
    let metrics = service.get_metrics().await;
    assert!(metrics.len() >= 3);
    
    println!("✓ Complete key lifecycle with audit: {} operations tracked", audit_records.len());
}

#[tokio::test]
async fn test_policy_compliant_secret_operations() {
    // Test policy-enforced crypto operations with compliance validation
    let engine = CryptoPolicyEngine::new();

    // Create encryption policy
    let policy = CryptoPolicy {
        policy_id: Uuid::new_v4().to_string(),
        name: "PCI-DSS Encryption".to_string(),
        allowed_algorithms: vec![
            "AES-256-GCM".to_string(),
            "RSA-4096".to_string(),
        ],
        required_key_strength: 256,
        mandatory_rotation_days: 90,
        compliance_frameworks: vec!["pci-dss".to_string(), "hipaa".to_string()],
        enforcement_level: EnforcementLevel::Strict,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let policy_id = engine.register_policy(policy).await.unwrap();

    // Validate compliant operation
    let compliant_req = CryptoOperationRequest {
        operation_type: CryptoOperationType::Encrypt,
        algorithm: "AES-256-GCM".to_string(),
        key_strength: 256,
        data_classification: "sensitive".to_string(),
        requester: "service@example.com".to_string(),
        context: HashMap::from([
            ("purpose".to_string(), "customer-data".to_string()),
        ]),
    };

    let validation = engine.validate_operation(&policy_id, &compliant_req).await;
    assert!(validation.is_ok());
    let valid_result = validation.unwrap();
    assert_eq!(valid_result.compliance_status, ComplianceStatus::Compliant);
    assert_eq!(valid_result.violations.len(), 0);

    // Validate non-compliant operation
    let non_compliant_req = CryptoOperationRequest {
        operation_type: CryptoOperationType::Encrypt,
        algorithm: "DES".to_string(), // Weak algorithm
        key_strength: 56,
        data_classification: "sensitive".to_string(),
        requester: "service@example.com".to_string(),
        context: HashMap::new(),
    };

    let non_valid = engine.validate_operation(&policy_id, &non_compliant_req).await;
    assert!(non_valid.is_ok());
    let non_valid_result = non_valid.unwrap();
    assert_eq!(non_valid_result.compliance_status, ComplianceStatus::NonCompliant);
    assert!(non_valid_result.violations.len() > 0);
    assert!(non_valid_result.violations.contains(&ComplianceViolationType::WeakAlgorithm));

    // Run compliance scan
    let scan_result = engine.run_compliance_scan(&policy_id).await.unwrap();
    assert!(scan_result.compliance_score >= 0.0);
    assert!(scan_result.compliance_score <= 100.0);

    println!("✓ Policy-enforced crypto: {} violations detected in non-compliant ops", 
             non_valid_result.violations.len());
}

#[tokio::test]
async fn test_zkp_authentication_to_secret_access() {
    // Test zero-knowledge proof authentication without exposing secrets
    let zkp_system = ZKPAuthenticationSystem::new();

    // Register user with ZKP
    let username = "alice@example.com".to_string();
    let password = "strong-password-123".to_string();

    let registration = zkp_system.register_user(username.clone(), password.clone()).await;
    assert!(registration.is_ok());
    let identity = registration.unwrap();

    // Authenticate with ZKP (password never transmitted)
    let auth_result = zkp_system.authenticate_zkp(username.clone(), password.clone()).await;
    assert!(auth_result.is_ok());
    let privacy_token = auth_result.unwrap();
    assert!(privacy_token.token_id.len() > 0);
    assert!(privacy_token.valid_until > Utc::now());

    // Verify token grants access
    let verify_result = zkp_system.verify_privacy_token(&privacy_token.token_id).await;
    assert!(verify_result.is_ok());
    let verified_identity = verify_result.unwrap();
    assert_eq!(verified_identity.user_id, username);

    // Check audit records don't contain sensitive data
    let audit_records = zkp_system.get_privacy_audit_records().await;
    assert!(audit_records.len() >= 2); // register + auth
    
    for record in &audit_records {
        // CRITICAL: Verify no password/credentials/proof in audit
        assert!(!record.action.contains("password"));
        assert!(!record.action.contains(&password));
    }

    // Test authentication with wrong password
    let wrong_auth = zkp_system.authenticate_zkp(username.clone(), "wrong-password".to_string()).await;
    assert!(wrong_auth.is_err());

    println!("✓ ZKP authentication: {} privacy-preserving audit records", audit_records.len());
}

#[tokio::test]
async fn test_multi_tenant_smpc_collaboration() {
    // Test secure multi-party computation with tenant isolation
    let smpc_service = SecureCollaborationService::new();

    // Create collaboration session
    let session_id = Uuid::new_v4().to_string();
    let participants = vec![
        "tenant-a".to_string(),
        "tenant-b".to_string(),
        "tenant-c".to_string(),
    ];

    let policy = CollaborationPolicy {
        session_id: session_id.clone(),
        allowed_tenants: participants.clone(),
        required_threshold: 2,
        operation_type: "secure-aggregation".to_string(),
        data_classification: "confidential".to_string(),
        timeout_minutes: 30,
        created_at: Utc::now(),
    };

    let session = smpc_service.create_session(session_id.clone(), policy).await;
    assert!(session.is_ok());

    // Tenant A contributes
    let contribute_a = smpc_service.contribute_data(
        session_id.clone(),
        "tenant-a".to_string(),
        vec![1.0, 2.0, 3.0],
    ).await;
    assert!(contribute_a.is_ok());

    // Tenant B contributes
    let contribute_b = smpc_service.contribute_data(
        session_id.clone(),
        "tenant-b".to_string(),
        vec![4.0, 5.0, 6.0],
    ).await;
    assert!(contribute_b.is_ok());

    // Test isolation: Unauthorized tenant cannot contribute
    let contribute_unauthorized = smpc_service.contribute_data(
        session_id.clone(),
        "tenant-unauthorized".to_string(),
        vec![7.0, 8.0, 9.0],
    ).await;
    assert!(contribute_unauthorized.is_err());

    // Compute with threshold (2 out of 3)
    let compute_result = smpc_service.compute_secure_result(&session_id).await;
    assert!(compute_result.is_ok());
    let result = compute_result.unwrap();
    assert_eq!(result.participants_count, 2);
    assert!(result.threshold_met);

    // Verify tenant isolation in session
    let session_info = smpc_service.get_session_info(&session_id).await.unwrap();
    assert_eq!(session_info.allowed_tenants.len(), 3);
    assert!(session_info.allowed_tenants.contains(&"tenant-a".to_string()));
    assert!(session_info.allowed_tenants.contains(&"tenant-b".to_string()));
    assert!(session_info.allowed_tenants.contains(&"tenant-c".to_string()));

    println!("✓ SMPC collaboration: {} tenants with secure isolation", participants.len());
}

#[tokio::test]
async fn test_full_observability_incident_response() {
    // Test end-to-end observability with anomaly detection and incident response
    let pipeline = ObservabilityPipeline::new();

    // Trace operation
    let trace_future = async {
        // Simulate operation
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        Ok::<_, String>(())
    };

    let trace_result = pipeline.trace_operation(
        "secret-access".to_string(),
        "secreton-service".to_string(),
        trace_future,
    ).await;
    assert!(trace_result.is_ok());
    let operation_trace = trace_result.unwrap();
    assert_eq!(operation_trace.operation_name, "secret-access");
    assert!(operation_trace.success);
    assert!(operation_trace.duration_ms > 0.0);

    // Perform comprehensive health check
    let health_check = pipeline.perform_health_check().await;
    assert!(health_check.is_ok());
    let health = health_check.unwrap();
    assert_eq!(health.component_health.len(), 10); // All 10 components checked
    
    // Count healthy components
    let healthy_count = health.component_health.values()
        .filter(|c| c.status == HealthStatus::Healthy)
        .count();
    assert!(healthy_count >= 8); // At least 8 out of 10 healthy

    // Detect anomaly
    let anomaly_result = pipeline.detect_anomaly(
        "high-error-rate".to_string(),
        95.0, // Severity score
        HashMap::from([
            ("error_rate".to_string(), "15%".to_string()),
            ("threshold".to_string(), "5%".to_string()),
        ]),
    ).await;
    assert!(anomaly_result.is_ok());

    // Correlate incident
    let incident_result = pipeline.correlate_incident(
        "service-degradation".to_string(),
        vec![operation_trace.trace_id.clone()],
        vec!["high-error-rate".to_string()],
    ).await;
    assert!(incident_result.is_ok());
    let incident = incident_result.unwrap();
    assert!(incident.severity_score > 50.0);
    assert!(incident.related_traces.len() > 0);
    assert!(incident.related_anomalies.len() > 0);

    // Trigger emergency response
    let response_result = pipeline.trigger_emergency_response(&incident.incident_id).await;
    assert!(response_result.is_ok());
    let response = response_result.unwrap();
    assert!(response.actions_taken.len() > 0);
    assert!(response.responders_notified.len() > 0);

    // Get performance metrics
    let metrics = pipeline.get_performance_metrics().await;
    assert!(metrics.is_ok());
    let perf = metrics.unwrap();
    assert!(perf.total_operations > 0);
    assert!(perf.p50_latency_ms >= 0.0);
    assert!(perf.p95_latency_ms >= perf.p50_latency_ms);
    assert!(perf.p99_latency_ms >= perf.p95_latency_ms);

    println!("✓ Full observability: {} components monitored, incident {} handled",
             health.component_health.len(), incident.incident_id);
}
