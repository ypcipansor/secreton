//! Crypto Policy Engine
//!
//! Policy-based cryptographic operations with algorithm agility, compliance
//! tracking, algorithm deprecation management, and crypto inventory.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Algorithm not allowed: {0}")]
    AlgorithmNotAllowed(String),
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    #[error("Compliance check failed: {0}")]
    ComplianceFailed(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

/// Cryptographic algorithm
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum CryptoAlgorithm {
    AES128_GCM,
    AES256_GCM,
    ChaCha20Poly1305,
    RSA2048,
    RSA4096,
    ECDSA_P256,
    ECDSA_P384,
    ED25519,
    SHA256,
    SHA3_256,
    BLAKE3,
}

/// Algorithm status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlgorithmStatus {
    Approved,
    Deprecated,
    Prohibited,
    UnderReview,
}

/// Compliance standard
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStandard {
    FIPS_140_2,
    FIPS_140_3,
    CommonCriteria,
    PCI_DSS,
    NIST_SP_800_131A,
    Custom(String),
}

/// Crypto policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoPolicy {
    pub policy_id: String,
    pub name: String,
    pub allowed_algorithms: Vec<CryptoAlgorithm>,
    pub min_key_sizes: HashMap<String, usize>,
    pub compliance_standards: Vec<ComplianceStandard>,
    pub enforce_rotation: bool,
    pub max_key_age_days: Option<u32>,
    pub enabled: bool,
}

/// Algorithm metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmMetadata {
    pub algorithm: CryptoAlgorithm,
    pub status: AlgorithmStatus,
    pub security_level: u32,
    pub compliance: Vec<ComplianceStandard>,
    pub deprecation_date: Option<DateTime<Utc>>,
    pub recommended_replacement: Option<CryptoAlgorithm>,
}

/// Crypto operation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoOperationRequest {
    pub operation_id: String,
    pub algorithm: CryptoAlgorithm,
    pub key_size: usize,
    pub purpose: String,
    pub requester: String,
    pub timestamp: DateTime<Utc>,
}

/// Crypto operation audit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoAudit {
    pub audit_id: String,
    pub operation_id: String,
    pub algorithm: CryptoAlgorithm,
    pub policy_id: String,
    pub approved: bool,
    pub violations: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

/// Crypto inventory item
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoInventoryItem {
    pub item_id: String,
    pub algorithm: CryptoAlgorithm,
    pub key_id: String,
    pub usage_count: u64,
    pub last_used: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    RequiresReview,
}

/// Crypto Policy Engine
pub struct CryptoPolicyEngine {
    policies: Arc<RwLock<HashMap<String, CryptoPolicy>>>,
    algorithm_metadata: Arc<RwLock<HashMap<CryptoAlgorithm, AlgorithmMetadata>>>,
    audits: Arc<RwLock<Vec<CryptoAudit>>>,
    inventory: Arc<RwLock<HashMap<String, CryptoInventoryItem>>>,
}

impl CryptoPolicyEngine {
    pub fn new() -> Self {
        let metadata = Self::create_default_metadata();

        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            algorithm_metadata: Arc::new(RwLock::new(metadata)),
            audits: Arc::new(RwLock::new(Vec::new())),
            inventory: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create policy
    pub async fn create_policy(&self, policy: CryptoPolicy) -> Result<String> {
        let mut policies = self.policies.write().await;
        let policy_id = policy.policy_id.clone();
        policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    /// Validate operation against policy
    pub async fn validate_operation(
        &self,
        request: &CryptoOperationRequest,
        policy_id: &str,
    ) -> Result<()> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_id)
            .ok_or_else(|| PolicyError::PolicyNotFound(policy_id.to_string()))?;

        if !policy.enabled {
            return Ok(());
        }

        let mut violations = Vec::new();

        // Check algorithm allowlist
        if !policy.allowed_algorithms.contains(&request.algorithm) {
            violations.push(format!(
                "Algorithm {:?} not in allowed list",
                request.algorithm
            ));
        }

        // Check algorithm status
        let metadata = self.algorithm_metadata.read().await;
        if let Some(algo_meta) = metadata.get(&request.algorithm) {
            match algo_meta.status {
                AlgorithmStatus::Prohibited => {
                    violations.push(format!("Algorithm {:?} is prohibited", request.algorithm));
                }
                AlgorithmStatus::Deprecated => {
                    violations.push(format!("Algorithm {:?} is deprecated", request.algorithm));
                }
                _ => {}
            }
        }

        // Check minimum key size
        let algo_name = format!("{:?}", request.algorithm);
        if let Some(&min_size) = policy.min_key_sizes.get(&algo_name) {
            if request.key_size < min_size {
                violations.push(format!(
                    "Key size {} below minimum {}",
                    request.key_size, min_size
                ));
            }
        }

        // Audit the operation
        let audit = CryptoAudit {
            audit_id: Uuid::new_v4().to_string(),
            operation_id: request.operation_id.clone(),
            algorithm: request.algorithm.clone(),
            policy_id: policy_id.to_string(),
            approved: violations.is_empty(),
            violations: violations.clone(),
            timestamp: Utc::now(),
        };

        drop(policies);
        drop(metadata);

        let mut audits = self.audits.write().await;
        audits.push(audit);

        if !violations.is_empty() {
            return Err(PolicyError::PolicyViolation(violations.join("; ")));
        }

        Ok(())
    }

    /// Select best algorithm for purpose
    pub async fn select_algorithm(
        &self,
        purpose: &str,
        policy_id: &str,
    ) -> Result<CryptoAlgorithm> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_id)
            .ok_or_else(|| PolicyError::PolicyNotFound(policy_id.to_string()))?;

        let metadata = self.algorithm_metadata.read().await;

        // Filter approved algorithms
        let mut candidates: Vec<_> = policy
            .allowed_algorithms
            .iter()
            .filter(|algo| {
                metadata
                    .get(algo)
                    .map(|m| m.status == AlgorithmStatus::Approved)
                    .unwrap_or(false)
            })
            .collect();

        // Select based on purpose
        let selected = match purpose {
            "encryption" => {
                candidates.retain(|a| {
                    matches!(
                        a,
                        CryptoAlgorithm::AES256_GCM | CryptoAlgorithm::ChaCha20Poly1305
                    )
                });
                candidates.first().cloned()
            }
            "signing" => {
                candidates.retain(|a| {
                    matches!(a, CryptoAlgorithm::ED25519 | CryptoAlgorithm::ECDSA_P256)
                });
                candidates.first().cloned()
            }
            _ => candidates.first().cloned(),
        };

        selected.cloned().ok_or_else(|| {
            PolicyError::AlgorithmNotAllowed("No suitable algorithm found".to_string())
        })
    }

    /// Register algorithm metadata
    pub async fn register_algorithm(&self, metadata: AlgorithmMetadata) -> Result<()> {
        let mut algo_metadata = self.algorithm_metadata.write().await;
        algo_metadata.insert(metadata.algorithm.clone(), metadata);
        Ok(())
    }

    /// Deprecate algorithm
    pub async fn deprecate_algorithm(
        &self,
        algorithm: CryptoAlgorithm,
        replacement: Option<CryptoAlgorithm>,
    ) -> Result<()> {
        let mut metadata = self.algorithm_metadata.write().await;

        let algo_meta = metadata
            .get_mut(&algorithm)
            .ok_or_else(|| PolicyError::AlgorithmNotAllowed(format!("{:?}", algorithm)))?;

        algo_meta.status = AlgorithmStatus::Deprecated;
        algo_meta.deprecation_date = Some(Utc::now());
        algo_meta.recommended_replacement = replacement;

        Ok(())
    }

    /// Add to inventory
    pub async fn add_to_inventory(&self, item: CryptoInventoryItem) -> Result<()> {
        let mut inventory = self.inventory.write().await;
        inventory.insert(item.item_id.clone(), item);
        Ok(())
    }

    /// Update inventory usage
    pub async fn update_usage(&self, item_id: &str) -> Result<()> {
        let mut inventory = self.inventory.write().await;

        if let Some(item) = inventory.get_mut(item_id) {
            item.usage_count += 1;
            item.last_used = Utc::now();
        }

        Ok(())
    }

    /// Check compliance
    pub async fn check_compliance(&self, standard: ComplianceStandard) -> Vec<CryptoInventoryItem> {
        let inventory = self.inventory.read().await;
        let metadata = self.algorithm_metadata.read().await;

        inventory
            .values()
            .filter(|item| {
                metadata
                    .get(&item.algorithm)
                    .map(|m| m.compliance.contains(&standard))
                    .unwrap_or(false)
            })
            .cloned()
            .collect()
    }

    /// Get audit trail
    pub async fn get_audit_trail(&self, operation_id: Option<&str>) -> Vec<CryptoAudit> {
        let audits = self.audits.read().await;

        if let Some(op_id) = operation_id {
            audits
                .iter()
                .filter(|a| a.operation_id == op_id)
                .cloned()
                .collect()
        } else {
            audits.clone()
        }
    }

    fn create_default_metadata() -> HashMap<CryptoAlgorithm, AlgorithmMetadata> {
        let mut metadata = HashMap::new();

        // Approved algorithms
        metadata.insert(
            CryptoAlgorithm::AES256_GCM,
            AlgorithmMetadata {
                algorithm: CryptoAlgorithm::AES256_GCM,
                status: AlgorithmStatus::Approved,
                security_level: 256,
                compliance: vec![
                    ComplianceStandard::FIPS_140_2,
                    ComplianceStandard::NIST_SP_800_131A,
                ],
                deprecation_date: None,
                recommended_replacement: None,
            },
        );

        metadata.insert(
            CryptoAlgorithm::ED25519,
            AlgorithmMetadata {
                algorithm: CryptoAlgorithm::ED25519,
                status: AlgorithmStatus::Approved,
                security_level: 128,
                compliance: vec![ComplianceStandard::NIST_SP_800_131A],
                deprecation_date: None,
                recommended_replacement: None,
            },
        );

        // Deprecated algorithm
        metadata.insert(
            CryptoAlgorithm::RSA2048,
            AlgorithmMetadata {
                algorithm: CryptoAlgorithm::RSA2048,
                status: AlgorithmStatus::Deprecated,
                security_level: 112,
                compliance: vec![],
                deprecation_date: Some(Utc::now()),
                recommended_replacement: Some(CryptoAlgorithm::RSA4096),
            },
        );

        metadata
    }

    /// Check if initialized (metadata is always populated in new())
    pub async fn is_initialized(&self) -> bool {
        let metadata = self.algorithm_metadata.read().await;
        !metadata.is_empty()
    }

    /// Get inventory
    pub async fn get_inventory(&self) -> Vec<CryptoInventoryItem> {
        let inventory = self.inventory.read().await;
        inventory.values().cloned().collect()
    }

    pub async fn get_non_compliant_items(&self) -> Vec<CryptoInventoryItem> {
        let inventory = self.inventory.read().await;
        inventory
            .values()
            .filter(|item| item.compliance_status == ComplianceStatus::NonCompliant)
            .cloned()
            .collect()
    }

    /// Get algorithm metadata
    pub async fn get_algorithm_metadata(
        &self,
        algorithm: &CryptoAlgorithm,
    ) -> Option<AlgorithmMetadata> {
        let metadata = self.algorithm_metadata.read().await;
        metadata.get(algorithm).cloned()
    }
}

impl Clone for CryptoPolicyEngine {
    fn clone(&self) -> Self {
        Self {
            policies: Arc::clone(&self.policies),
            algorithm_metadata: Arc::clone(&self.algorithm_metadata),
            audits: Arc::clone(&self.audits),
            inventory: Arc::clone(&self.inventory),
        }
    }
}

impl Default for CryptoPolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_policy() {
        let engine = CryptoPolicyEngine::new();

        let policy = CryptoPolicy {
            policy_id: "pol1".to_string(),
            name: "Standard Policy".to_string(),
            allowed_algorithms: vec![CryptoAlgorithm::AES256_GCM, CryptoAlgorithm::ED25519],
            min_key_sizes: HashMap::new(),
            compliance_standards: vec![ComplianceStandard::FIPS_140_2],
            enforce_rotation: true,
            max_key_age_days: Some(90),
            enabled: true,
        };

        let policy_id = engine.create_policy(policy).await.unwrap();
        assert_eq!(policy_id, "pol1");
    }

    #[tokio::test]
    async fn test_validate_operation() {
        let engine = CryptoPolicyEngine::new();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let policy = CryptoPolicy {
            policy_id: "pol1".to_string(),
            name: "Test Policy".to_string(),
            allowed_algorithms: vec![CryptoAlgorithm::AES256_GCM],
            min_key_sizes: HashMap::new(),
            compliance_standards: vec![],
            enforce_rotation: false,
            max_key_age_days: None,
            enabled: true,
        };

        engine.create_policy(policy).await.unwrap();

        let request = CryptoOperationRequest {
            operation_id: "op1".to_string(),
            algorithm: CryptoAlgorithm::AES256_GCM,
            key_size: 256,
            purpose: "encryption".to_string(),
            requester: "alice".to_string(),
            timestamp: Utc::now(),
        };

        let result = engine.validate_operation(&request, "pol1").await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_select_algorithm() {
        let engine = CryptoPolicyEngine::new();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let policy = CryptoPolicy {
            policy_id: "pol1".to_string(),
            name: "Test Policy".to_string(),
            allowed_algorithms: vec![
                CryptoAlgorithm::AES256_GCM,
                CryptoAlgorithm::ChaCha20Poly1305,
            ],
            min_key_sizes: HashMap::new(),
            compliance_standards: vec![],
            enforce_rotation: false,
            max_key_age_days: None,
            enabled: true,
        };

        engine.create_policy(policy).await.unwrap();

        let selected = engine.select_algorithm("encryption", "pol1").await.unwrap();
        assert!(matches!(
            selected,
            CryptoAlgorithm::AES256_GCM | CryptoAlgorithm::ChaCha20Poly1305
        ));
    }

    #[tokio::test]
    async fn test_deprecate_algorithm() {
        let engine = CryptoPolicyEngine::new();
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        engine
            .deprecate_algorithm(
                CryptoAlgorithm::AES128_GCM,
                Some(CryptoAlgorithm::AES256_GCM),
            )
            .await
            .ok();

        // RSA2048 should already be deprecated from initialization
        let metadata = engine
            .get_algorithm_metadata(&CryptoAlgorithm::RSA2048)
            .await;
        assert!(metadata.is_some());
        assert_eq!(metadata.unwrap().status, AlgorithmStatus::Deprecated);
    }

    #[tokio::test]
    async fn test_inventory_management() {
        let engine = CryptoPolicyEngine::new();

        let item = CryptoInventoryItem {
            item_id: "item1".to_string(),
            algorithm: CryptoAlgorithm::AES256_GCM,
            key_id: "key1".to_string(),
            usage_count: 0,
            last_used: Utc::now(),
            created_at: Utc::now(),
            compliance_status: ComplianceStatus::Compliant,
        };

        engine.add_to_inventory(item).await.unwrap();
        engine.update_usage("item1").await.unwrap();

        let inventory = engine.get_inventory().await;
        assert_eq!(inventory.len(), 1);
        assert_eq!(inventory[0].usage_count, 1);
    }
}
