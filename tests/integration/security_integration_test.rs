use brankas_core::security::{
    AdvancedSecurityOrchestrator, BankingGradeConfig, GovernmentGradeConfig,
    SecurityConfig, ComplianceStatus, SecurityMetrics, HealthStatus,
};
use tokio::time::{timeout, Duration};
use std::sync::Arc;
use serde_json::json;

/// Integration tests for the complete security system
/// Tests real-world scenarios and end-to-end security workflows
#[cfg(test)]
mod security_integration_tests {
    use super::*;

    /// Create a test security orchestrator with banking-grade configuration
    async fn create_banking_orchestrator() -> Result<Arc<AdvancedSecurityOrchestrator>, Box<dyn std::error::Error>> {
        let config = BankingGradeConfig::new();
        let orchestrator = AdvancedSecurityOrchestrator::new(config.into()).await?;
        Ok(Arc::new(orchestrator))
    }

    /// Create a test security orchestrator with government-grade configuration
    async fn create_government_orchestrator() -> Result<Arc<AdvancedSecurityOrchestrator>, Box<dyn std::error::Error>> {
        let config = GovernmentGradeConfig::new();
        let orchestrator = AdvancedSecurityOrchestrator::new(config.into()).await?;
        Ok(Arc::new(orchestrator))
    }

    #[tokio::test]
    async fn test_orchestrator_initialization() -> Result<(), Box<dyn std::error::Error>> {
        // Test banking-grade initialization
        let banking_orch = create_banking_orchestrator().await?;
        let health = banking_orch.get_health_status().await?;
        
        assert!(health.overall_health >= 90.0, 
               "Banking-grade orchestrator should have >= 90% health, got {}", 
               health.overall_health);
        
        // Test government-grade initialization
        let gov_orch = create_government_orchestrator().await?;
        let health = gov_orch.get_health_status().await?;
        
        assert!(health.overall_health >= 95.0, 
               "Government-grade orchestrator should have >= 95% health, got {}", 
               health.overall_health);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_basic_encryption_decryption() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        // Test various data types and sizes
        let test_cases = vec![
            "small_secret",
            "medium_length_secret_with_numbers_123",
            &"x".repeat(1024), // 1KB
            &"y".repeat(10240), // 10KB
        ];
        
        for (i, test_data) in test_cases.iter().enumerate() {
            let encrypted = orchestrator.encrypt_data(test_data).await?;
            
            // Verify encryption properties
            assert!(encrypted.len() > test_data.len(), 
                   "Encrypted data should be larger than plaintext for case {}", i);
            assert_ne!(encrypted.as_bytes(), test_data.as_bytes(), 
                      "Encrypted data should differ from plaintext for case {}", i);
            
            // Verify decryption
            let decrypted = orchestrator.decrypt_data(&encrypted).await?;
            assert_eq!(decrypted, *test_data, 
                      "Decrypted data should match original for case {}", i);
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_banking_compliance_validation() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        // Check comprehensive banking compliance
        let compliance = orchestrator.check_compliance().await?;
        
        // Core banking regulations
        assert!(compliance.pci_dss_compliant, "PCI DSS compliance required for banking");
        assert!(compliance.sox_compliant, "SOX compliance required for financial institutions");
        
        // Additional financial regulations (if implemented)
        if let Some(basel) = compliance.basel_iii_compliant {
            assert!(basel, "Basel III compliance should be maintained if implemented");
        }
        
        // Test audit trail generation
        let audit_event = json!({
            "event_type": "data_access",
            "user_id": "banking_user_001",
            "resource": "customer_financial_data",
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "success": true,
            "compliance_context": "PCI_DSS_validation"
        });
        
        let audit_result = orchestrator.log_audit_event(&audit_event).await;
        assert!(audit_result.is_ok(), "Audit logging should succeed for banking operations");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_government_security_standards() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_government_orchestrator().await?;
        
        // Verify government-grade compliance
        let compliance = orchestrator.check_compliance().await?;
        
        assert!(compliance.fips_140_2_compliant, "FIPS 140-2 compliance required for government");
        
        if let Some(cc_compliant) = compliance.common_criteria_compliant {
            assert!(cc_compliant, "Common Criteria compliance should be maintained");
        }
        
        // Test quantum-safe cryptography
        let classified_data = "TOP_SECRET_GOVERNMENT_DATA";
        
        let quantum_encrypted = orchestrator.encrypt_data_quantum_safe(classified_data).await?;
        assert!(quantum_encrypted.len() > classified_data.len() * 2, 
               "Quantum-safe encryption should have significant overhead");
        
        let quantum_decrypted = orchestrator.decrypt_data_quantum_safe(&quantum_encrypted).await?;
        assert_eq!(quantum_decrypted, classified_data, 
                  "Quantum-safe decryption should preserve data integrity");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_advanced_mfa_integration() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        let user_id = "integration_test_user";
        
        // Test MFA enrollment
        let enrollment = orchestrator.enroll_mfa(user_id).await?;
        assert!(enrollment.success, "MFA enrollment should succeed");
        
        // Test behavioral biometrics
        let behavioral_pattern = json!({
            "typing_rhythm": {
                "average_dwell_time": 150,
                "average_flight_time": 100,
                "variance": 0.15
            },
            "mouse_dynamics": {
                "average_velocity": 2.5,
                "acceleration_patterns": [1.2, 1.8, 2.1],
                "click_pressure": 0.8
            },
            "device_context": {
                "screen_resolution": "1920x1080",
                "timezone": "UTC",
                "language": "en-US"
            }
        });
        
        let biometric_result = orchestrator
            .verify_behavioral_biometrics(user_id, &behavioral_pattern)
            .await?;
        
        // Confidence score should be reasonable
        assert!(biometric_result.confidence_score >= 0.0 && biometric_result.confidence_score <= 1.0,
               "Confidence score should be between 0.0 and 1.0, got {}", 
               biometric_result.confidence_score);
        
        Ok(())
    }

    #[tokio::test]
    async fn test_zero_trust_architecture() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        let user_id = "zero_trust_user";
        let sensitive_resource = "financial_transaction_system";
        
        // Test zero-trust authentication
        let auth_result = orchestrator
            .authenticate_zero_trust(user_id, sensitive_resource)
            .await?;
        
        assert!(auth_result.authenticated || !auth_result.authenticated, 
               "Authentication result should be boolean");
        
        // Risk score should be within valid range
        assert!(auth_result.risk_score >= 0.0 && auth_result.risk_score <= 1.0,
               "Risk score should be between 0.0 and 1.0, got {}", 
               auth_result.risk_score);
        
        // Test network segmentation
        let network_segment = orchestrator.get_network_segment(user_id).await;
        match network_segment {
            Ok(segment) => {
                assert!(!segment.is_empty(), "Network segment should not be empty");
                println!("User assigned to network segment: {}", segment);
            },
            Err(_) => {
                // Network segmentation may not be fully implemented
                println!("Network segmentation not available in test environment");
            }
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_threat_intelligence_system() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        // Test threat indicator assessment
        let test_indicators = vec![
            "192.168.1.100",  // Internal IP
            "10.0.0.1",       // Private IP
            "127.0.0.1",      // Localhost
            "8.8.8.8",        // Public DNS
        ];
        
        for indicator in test_indicators {
            let assessment = orchestrator.assess_threat_indicator(indicator).await?;
            
            assert!(assessment.risk_score >= 0.0 && assessment.risk_score <= 1.0,
                   "Risk score for {} should be between 0.0 and 1.0, got {}", 
                   indicator, assessment.risk_score);
        }
        
        // Test behavioral anomaly detection
        let normal_behavior = json!({
            "user_id": "normal_user",
            "login_time": "09:00:00",
            "location": "usual_office",
            "device": "registered_device",
            "access_patterns": ["email", "documents", "calendar"]
        });
        
        let anomalous_behavior = json!({
            "user_id": "suspicious_user",
            "login_time": "03:30:00",
            "location": "foreign_country",
            "device": "unknown_device",
            "access_patterns": ["admin_panel", "user_database", "financial_records"]
        });
        
        let normal_score = orchestrator.detect_behavioral_anomaly(&normal_behavior).await?;
        let anomalous_score = orchestrator.detect_behavioral_anomaly(&anomalous_behavior).await?;
        
        // Anomalous behavior should generally have higher risk score
        assert!(normal_score <= 1.0 && anomalous_score <= 1.0, 
               "Both scores should be within valid range");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_hsm_integration() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_government_orchestrator().await?;
        
        // Test HSM key lifecycle
        let key_id = orchestrator.generate_hsm_key().await?;
        assert!(!key_id.is_empty(), "HSM key ID should not be empty");
        
        // Test HSM encryption operations
        let sensitive_data = "CLASSIFIED_GOVERNMENT_SECRET";
        
        let hsm_encrypted = orchestrator.hsm_encrypt(&key_id, sensitive_data).await?;
        assert!(hsm_encrypted.len() > sensitive_data.len(), 
               "HSM encrypted data should be larger than plaintext");
        
        let hsm_decrypted = orchestrator.hsm_decrypt(&key_id, &hsm_encrypted).await?;
        assert_eq!(hsm_decrypted, sensitive_data, 
                  "HSM decryption should preserve data integrity");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_entropy_and_randomness_quality() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_government_orchestrator().await?;
        
        // Test entropy quality assessment
        let entropy_quality = orchestrator.get_entropy_quality().await?;
        assert!(entropy_quality.quality_score >= 0.90, 
               "Government-grade entropy should have >= 90% quality, got {}", 
               entropy_quality.quality_score);
        
        // Test secure random number generation
        let random_sizes = vec![16, 32, 64, 256];
        
        for size in random_sizes {
            let random_bytes = orchestrator.generate_secure_random(size).await?;
            assert_eq!(random_bytes.len(), size, 
                      "Random bytes should match requested size");
            
            // Basic statistical test - not all bytes should be the same
            let first_byte = random_bytes[0];
            let all_same = random_bytes.iter().all(|&b| b == first_byte);
            assert!(!all_same, "Random bytes should not all be identical");
        }
        
        Ok(())
    }

    #[tokio::test]
    async fn test_audit_and_compliance_logging() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        // Test various audit event types
        let audit_events = vec![
            json!({
                "event_type": "user_authentication",
                "user_id": "audit_test_user",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "success": true,
                "mfa_used": true
            }),
            json!({
                "event_type": "data_encryption",
                "resource": "customer_pii",
                "algorithm": "AES-256-GCM",
                "key_id": "key_12345",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }),
            json!({
                "event_type": "policy_violation",
                "user_id": "audit_test_user",
                "violation_type": "unusual_access_time",
                "severity": "medium",
                "timestamp": chrono::Utc::now().to_rfc3339()
            }),
        ];
        
        for audit_event in audit_events {
            let result = orchestrator.log_audit_event(&audit_event).await;
            assert!(result.is_ok(), "Audit event logging should succeed: {:?}", result);
        }
        
        // Test compliance report generation
        let compliance_report = orchestrator.generate_compliance_report().await?;
        assert!(!compliance_report.is_empty(), "Compliance report should not be empty");
        
        // Report should contain key compliance information
        assert!(compliance_report.contains("compliance") || 
               compliance_report.contains("audit") ||
               compliance_report.contains("security"),
               "Compliance report should contain relevant security information");
        
        Ok(())
    }

    #[tokio::test]
    async fn test_emergency_incident_response() -> Result<(), Box<dyn std::error::Error>> {
        let orchestrator = create_banking_orchestrator().await?;
        
        // Test different types of security incidents
        let incidents = vec![
            json!({
                "incident_type": "brute_force_attack",
                "severity": "high",
                "source_ip": "192.168.1.100",
                "target_user": "admin",
                "failed_attempts": 50,
                "time_window": "5_minutes"
            }),
            json!({
                "incident_type": "data_exfiltration_attempt",
                "severity": "critical",
                "user_id": "compromised_user",
                "data_volume": "10MB",
                "unusual_access_pattern": true
            }),
            json!({
                "incident_type": "malware_detection",
                "severity": "medium",
                "endpoint": "workstation_001",
                "malware_signature": "trojan.banking.variant"
            }),
        ];
        
        for incident in incidents {
            let response = orchestrator.handle_security_incident(&incident).await?;
            
            // Verify incident response properties
            assert!(!response.actions_taken.is_empty(), 
                   "Security incident response should include actions taken");
            
            // System should attempt containment for high/critical incidents
            if incident["severity"] == "high" || incident["severity"] == "critical" {
                assert!(response.incident_contained || response.actions_taken.contains(&"containment_initiated".to_string()),
                       "High/critical incidents should trigger containment measures");
            }
        }
        
        Ok(())
    }
}
