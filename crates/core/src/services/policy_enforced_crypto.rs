//! Policy-Enforced Cryptographic Operations
//!
//! Integrates crypto policy engine with secret operations and compliance framework
//! to ensure all cryptographic operations comply with organizational policies,
//! industry standards, and regulatory requirements.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::services::crypto_policy_engine::{AlgorithmMetadata, AlgorithmStatus, CryptoPolicy};
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::crypto_policy_engine::{
    ComplianceStandard, CryptoAlgorithm, CryptoOperationRequest, CryptoPolicyEngine,
};

#[derive(Debug, Error)]
pub enum PolicyEnforcementError {
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Compliance check failed: {0}")]
    ComplianceFailed(String),
    #[error("Encryption operation failed: {0}")]
    EncryptionFailed(String),
    #[error("Algorithm migration failed: {0}")]
    MigrationFailed(String),
}

pub type Result<T> = std::result::Result<T, PolicyEnforcementError>;

/// Secret encryption request with policy validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyEnforcedEncryptionRequest {
    pub secret_path: String,
    pub data: HashMap<String, String>,
    pub policy_id: String,
    pub requester: String,
    pub purpose: String,
}

/// Encrypted secret with policy compliance metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub secret_id: String,
    pub secret_path: String,
    pub encrypted_data: Vec<u8>,
    pub algorithm: CryptoAlgorithm,
    pub key_id: String,
    pub policy_id: String,
    pub compliance_standards: Vec<ComplianceStandard>,
    pub encrypted_at: DateTime<Utc>,
    pub encrypted_by: String,
}

/// Compliance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceViolation {
    pub violation_id: String,
    pub secret_id: String,
    pub secret_path: String,
    pub algorithm: CryptoAlgorithm,
    pub policy_id: String,
    pub violation_type: ViolationType,
    pub detected_at: DateTime<Utc>,
    pub remediation_status: RemediationStatus,
}

/// Violation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ViolationType {
    ProhibitedAlgorithm,
    DeprecatedAlgorithm,
    InsufficientKeySize,
    ExpiredCompliance,
    MissingAuditTrail,
}

/// Remediation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationStatus {
    Detected,
    InProgress,
    Remediated,
    Exception,
}

/// Algorithm migration plan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationPlan {
    pub plan_id: String,
    pub from_algorithm: CryptoAlgorithm,
    pub to_algorithm: CryptoAlgorithm,
    pub affected_secrets: Vec<String>,
    pub migration_start: Option<DateTime<Utc>>,
    pub migration_end: Option<DateTime<Utc>>,
    pub progress: MigrationProgress,
}

/// Migration progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MigrationProgress {
    pub total_secrets: usize,
    pub migrated_secrets: usize,
    pub failed_secrets: usize,
}

/// Compliance scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceScanResult {
    pub scan_id: String,
    pub scanned_at: DateTime<Utc>,
    pub total_secrets: usize,
    pub compliant_secrets: usize,
    pub non_compliant_secrets: usize,
    pub violations: Vec<ComplianceViolation>,
    pub compliance_score: f64,
}

/// Policy-enforced crypto operations service
pub struct PolicyEnforcedCryptoOperations {
    policy_engine: Arc<RwLock<CryptoPolicyEngine>>,
    encrypted_secrets: Arc<RwLock<HashMap<String, EncryptedSecret>>>,
    violations: Arc<RwLock<Vec<ComplianceViolation>>>,
    migration_plans: Arc<RwLock<HashMap<String, MigrationPlan>>>,
}

impl PolicyEnforcedCryptoOperations {
    pub fn new() -> Self {
        Self {
            policy_engine: Arc::new(RwLock::new(CryptoPolicyEngine::new())),
            encrypted_secrets: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(Vec::new())),
            migration_plans: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Encrypt secret with policy validation
    pub async fn encrypt_with_policy(
        &self,
        request: PolicyEnforcedEncryptionRequest,
    ) -> Result<EncryptedSecret> {
        // 1. Validate operation against policy
        let (selected_algorithm, compliance_standards) = {
            let policy_engine = self.policy_engine.read().await;
            let selected_algorithm = policy_engine
                .select_algorithm(&request.purpose, &request.policy_id)
                .await
                .map_err(|e| PolicyEnforcementError::PolicyViolation(e.to_string()))?;

            let operation_request = CryptoOperationRequest {
                operation_id: Uuid::new_v4().to_string(),
                algorithm: selected_algorithm.clone(),
                key_size: 256, // AES-256 or equivalent
                purpose: request.purpose.clone(),
                requester: request.requester.clone(),
                timestamp: Utc::now(),
            };

            policy_engine
                .validate_operation(&operation_request, &request.policy_id)
                .await
                .map_err(|e| PolicyEnforcementError::PolicyViolation(e.to_string()))?;

            // 2. Get compliance standards for policy
            let compliance_standards = policy_engine
                .check_compliance(ComplianceStandard::FIPS_140_3)
                .await;

            (selected_algorithm, compliance_standards)
        };

        // 3. Perform encryption (mock)
        let encrypted_data = self.mock_encrypt(&request.data);
        let key_id = Uuid::new_v4().to_string();

        let encrypted_secret = EncryptedSecret {
            secret_id: Uuid::new_v4().to_string(),
            secret_path: request.secret_path.clone(),
            encrypted_data,
            algorithm: selected_algorithm.clone(),
            key_id,
            policy_id: request.policy_id,
            compliance_standards: vec![ComplianceStandard::FIPS_140_3],
            encrypted_at: Utc::now(),
            encrypted_by: request.requester,
        };

        // 4. Store encrypted secret
        self.encrypted_secrets
            .write()
            .await
            .insert(encrypted_secret.secret_id.clone(), encrypted_secret.clone());

        Ok(encrypted_secret)
    }

    /// Scan all secrets for compliance violations
    pub async fn compliance_scan(&self) -> Result<ComplianceScanResult> {
        let scan_id = Uuid::new_v4().to_string();
        let scanned_at = Utc::now();

        let secrets = self.encrypted_secrets.read().await;
        let total_secrets = secrets.len();
        let mut violations = Vec::new();

        let policy_engine = self.policy_engine.read().await;

        for (secret_id, secret) in secrets.iter() {
            // Check if algorithm is still compliant
            let algo_metadata = policy_engine
                .get_algorithm_metadata(&secret.algorithm)
                .await
                .unwrap();

            if algo_metadata.status == super::crypto_policy_engine::AlgorithmStatus::Prohibited {
                violations.push(ComplianceViolation {
                    violation_id: Uuid::new_v4().to_string(),
                    secret_id: secret_id.clone(),
                    secret_path: secret.secret_path.clone(),
                    algorithm: secret.algorithm.clone(),
                    policy_id: secret.policy_id.clone(),
                    violation_type: ViolationType::ProhibitedAlgorithm,
                    detected_at: scanned_at,
                    remediation_status: RemediationStatus::Detected,
                });
            } else if algo_metadata.status
                == super::crypto_policy_engine::AlgorithmStatus::Deprecated
            {
                violations.push(ComplianceViolation {
                    violation_id: Uuid::new_v4().to_string(),
                    secret_id: secret_id.clone(),
                    secret_path: secret.secret_path.clone(),
                    algorithm: secret.algorithm.clone(),
                    policy_id: secret.policy_id.clone(),
                    violation_type: ViolationType::DeprecatedAlgorithm,
                    detected_at: scanned_at,
                    remediation_status: RemediationStatus::Detected,
                });
            }
        }

        drop(policy_engine);

        let non_compliant_secrets = violations.len();
        let compliant_secrets = total_secrets - non_compliant_secrets;
        let compliance_score = if total_secrets > 0 {
            (compliant_secrets as f64 / total_secrets as f64) * 100.0
        } else {
            100.0
        };

        // Store violations
        self.violations.write().await.extend(violations.clone());

        Ok(ComplianceScanResult {
            scan_id,
            scanned_at,
            total_secrets,
            compliant_secrets,
            non_compliant_secrets,
            violations,
            compliance_score,
        })
    }

    /// Create algorithm migration plan
    pub async fn create_migration_plan(
        &self,
        from_algorithm: CryptoAlgorithm,
        to_algorithm: CryptoAlgorithm,
    ) -> Result<MigrationPlan> {
        let secrets = self.encrypted_secrets.read().await;

        // Find secrets using deprecated algorithm
        let affected_secrets: Vec<String> = secrets
            .values()
            .filter(|s| s.algorithm == from_algorithm)
            .map(|s| s.secret_id.clone())
            .collect();

        let plan = MigrationPlan {
            plan_id: Uuid::new_v4().to_string(),
            from_algorithm,
            to_algorithm,
            affected_secrets: affected_secrets.clone(),
            migration_start: None,
            migration_end: None,
            progress: MigrationProgress {
                total_secrets: affected_secrets.len(),
                migrated_secrets: 0,
                failed_secrets: 0,
            },
        };

        self.migration_plans
            .write()
            .await
            .insert(plan.plan_id.clone(), plan.clone());

        Ok(plan)
    }

    /// Execute automatic algorithm migration
    pub async fn execute_migration(&self, plan_id: &str) -> Result<MigrationProgress> {
        let mut plans = self.migration_plans.write().await;
        let plan = plans
            .get_mut(plan_id)
            .ok_or_else(|| PolicyEnforcementError::MigrationFailed("Plan not found".to_string()))?;

        plan.migration_start = Some(Utc::now());

        let affected_secrets = plan.affected_secrets.clone();
        let to_algorithm = plan.to_algorithm.clone();

        drop(plans);

        let mut secrets = self.encrypted_secrets.write().await;
        let mut migrated = 0;
        let mut failed = 0;

        for secret_id in affected_secrets {
            if let Some(secret) = secrets.get_mut(&secret_id) {
                // Re-encrypt with new algorithm (mock)
                let re_encrypted_data = self.mock_encrypt(&HashMap::new());
                secret.encrypted_data = re_encrypted_data;
                secret.algorithm = to_algorithm.clone();
                secret.encrypted_at = Utc::now();
                migrated += 1;
            } else {
                failed += 1;
            }
        }

        // Update plan progress
        let mut plans = self.migration_plans.write().await;
        if let Some(plan) = plans.get_mut(plan_id) {
            plan.progress.migrated_secrets = migrated;
            plan.progress.failed_secrets = failed;
            plan.migration_end = Some(Utc::now());
        }

        Ok(MigrationProgress {
            total_secrets: migrated + failed,
            migrated_secrets: migrated,
            failed_secrets: failed,
        })
    }

    /// Get all violations
    pub async fn get_violations(&self) -> Vec<ComplianceViolation> {
        self.violations.read().await.clone()
    }

    /// Get violations by type
    pub async fn get_violations_by_type(
        &self,
        violation_type: ViolationType,
    ) -> Vec<ComplianceViolation> {
        self.violations
            .read()
            .await
            .iter()
            .filter(|v| v.violation_type == violation_type)
            .cloned()
            .collect()
    }

    /// Update remediation status
    pub async fn update_remediation_status(
        &self,
        violation_id: &str,
        status: RemediationStatus,
    ) -> Result<()> {
        let mut violations = self.violations.write().await;
        if let Some(violation) = violations
            .iter_mut()
            .find(|v| v.violation_id == violation_id)
        {
            violation.remediation_status = status;
            Ok(())
        } else {
            Err(PolicyEnforcementError::ComplianceFailed(
                "Violation not found".to_string(),
            ))
        }
    }

    /// Mock encryption function
    fn mock_encrypt(&self, data: &HashMap<String, String>) -> Vec<u8> {
        // Mock: serialize to JSON and return as bytes
        serde_json::to_vec(data).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_policy_enforced_encryption() {
        let ops = PolicyEnforcedCryptoOperations::new();

        // Register ChaCha20Poly1305 as approved algorithm
        {
            let policy_engine = ops.policy_engine.read().await;
            policy_engine
                .register_algorithm(AlgorithmMetadata {
                    algorithm: CryptoAlgorithm::ChaCha20Poly1305,
                    status: AlgorithmStatus::Approved,
                    security_level: 256,
                    compliance: vec![ComplianceStandard::FIPS_140_3],
                    deprecation_date: None,
                    recommended_replacement: None,
                })
                .await
                .unwrap();
        }

        // Create a test policy first
        let policy = CryptoPolicy {
            policy_id: "test-policy".to_string(),
            name: "Test Policy".to_string(),
            allowed_algorithms: vec![
                CryptoAlgorithm::AES256_GCM,
                CryptoAlgorithm::ChaCha20Poly1305,
                CryptoAlgorithm::ED25519,
            ],
            min_key_sizes: std::collections::HashMap::from([
                ("AES256_GCM".to_string(), 256),
                ("ChaCha20Poly1305".to_string(), 256),
                ("ED25519".to_string(), 256),
            ]),
            compliance_standards: vec![ComplianceStandard::FIPS_140_3],
            enforce_rotation: true,
            max_key_age_days: Some(365),
            enabled: true,
        };

        {
            let policy_engine = ops.policy_engine.read().await;
            policy_engine.create_policy(policy).await.unwrap();
        }

        let request = PolicyEnforcedEncryptionRequest {
            secret_path: "/app/prod/db-password".to_string(),
            data: HashMap::from([("password".to_string(), "secret123".to_string())]),
            policy_id: "test-policy".to_string(),
            requester: "admin".to_string(),
            purpose: "encryption".to_string(),
        };

        let result = ops.encrypt_with_policy(request).await.unwrap();
        assert!(!result.encrypted_data.is_empty());
        assert_eq!(result.secret_path, "/app/prod/db-password");
        assert_eq!(result.encrypted_by, "admin");
    }

    #[tokio::test]
    async fn test_compliance_scan() {
        let ops = PolicyEnforcedCryptoOperations::new();

        // Create a test policy
        let policy = CryptoPolicy {
            policy_id: "policy1".to_string(),
            name: "Test Policy".to_string(),
            allowed_algorithms: vec![CryptoAlgorithm::AES256_GCM],
            min_key_sizes: HashMap::from([("AES256_GCM".to_string(), 256)]),
            compliance_standards: vec![ComplianceStandard::FIPS_140_3],
            enforce_rotation: false,
            max_key_age_days: None,
            enabled: true,
        };

        {
            let policy_engine = ops.policy_engine.read().await;
            policy_engine.create_policy(policy).await.unwrap();
        }

        // Create some test secrets
        let request = PolicyEnforcedEncryptionRequest {
            secret_path: "/test/secret1".to_string(),
            data: HashMap::from([("key".to_string(), "value".to_string())]),
            policy_id: "policy1".to_string(),
            requester: "user1".to_string(),
            purpose: "encryption".to_string(),
        };

        ops.encrypt_with_policy(request).await.unwrap();

        // Run compliance scan
        let scan_result = ops.compliance_scan().await.unwrap();
        assert_eq!(scan_result.total_secrets, 1);
        assert!(scan_result.compliance_score >= 0.0);
        assert!(scan_result.compliance_score <= 100.0);
    }

    #[tokio::test]
    async fn test_migration_plan_creation() {
        let ops = PolicyEnforcedCryptoOperations::new();

        let plan = ops
            .create_migration_plan(CryptoAlgorithm::AES128_GCM, CryptoAlgorithm::AES256_GCM)
            .await
            .unwrap();

        assert_eq!(plan.from_algorithm, CryptoAlgorithm::AES128_GCM);
        assert_eq!(plan.to_algorithm, CryptoAlgorithm::AES256_GCM);
        assert!(plan.migration_start.is_none());
    }

    #[tokio::test]
    async fn test_violation_tracking() {
        let ops = PolicyEnforcedCryptoOperations::new();

        // Create policy first
        let policy = CryptoPolicy {
            policy_id: "policy2".to_string(),
            name: "Test Policy 2".to_string(),
            allowed_algorithms: vec![CryptoAlgorithm::AES256_GCM, CryptoAlgorithm::ED25519],
            min_key_sizes: HashMap::new(),
            compliance_standards: vec![],
            enforce_rotation: false,
            max_key_age_days: None,
            enabled: true,
        };
        {
            let engine = ops.policy_engine.write().await;
            let _ = engine.create_policy(policy).await;
        }

        // Create secret with compliant algorithm
        let request = PolicyEnforcedEncryptionRequest {
            secret_path: "/test/secret2".to_string(),
            data: HashMap::new(),
            policy_id: "policy2".to_string(),
            requester: "user2".to_string(),
            purpose: "encryption".to_string(),
        };

        let _ = ops.encrypt_with_policy(request).await;

        // Run scan (should find no violations initially)
        let scan_result = ops.compliance_scan().await.unwrap();
        let initial_violations = scan_result.violations.len();

        // All violations should be tracked
        let all_violations = ops.get_violations().await;
        assert_eq!(all_violations.len(), initial_violations);
    }

    #[tokio::test]
    async fn test_remediation_status_update() {
        let ops = PolicyEnforcedCryptoOperations::new();

        // Manually add a violation for testing
        let violation = ComplianceViolation {
            violation_id: "test-violation".to_string(),
            secret_id: "secret123".to_string(),
            secret_path: "/test/path".to_string(),
            algorithm: CryptoAlgorithm::AES128_GCM,
            policy_id: "policy".to_string(),
            violation_type: ViolationType::DeprecatedAlgorithm,
            detected_at: Utc::now(),
            remediation_status: RemediationStatus::Detected,
        };

        ops.violations.write().await.push(violation);

        // Update status
        ops.update_remediation_status("test-violation", RemediationStatus::InProgress)
            .await
            .unwrap();

        // Verify update
        let violations = ops.get_violations().await;
        let updated = violations
            .iter()
            .find(|v| v.violation_id == "test-violation")
            .unwrap();
        assert_eq!(updated.remediation_status, RemediationStatus::InProgress);
    }
}
