//! Unified Security Management System
//!
//! This module integrates all security components into a comprehensive
//! security framework that provides maximum protection and compliance.

use crate::{
    audit::{AuditLogger, SecurityEventType, ComplianceStandard},
    hsm::{HSMOperations, HSMProvider},
    pqcrypto::{PostQuantumCrypto, PQCAlgorithm, HybridCrypto},
    mfa::{MFAProvider, MFAMethod, MFAChallenge},
    error::CoreError,
    SecurityLevel,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Unified security manager integrating all security components
pub struct SecurityManager {
    /// Hardware Security Module operations
    hsm: Arc<dyn HSMOperations>,
    /// Post-quantum cryptography engine
    pqc: Arc<PostQuantumCrypto>,
    /// Multi-factor authentication provider
    mfa: Arc<dyn MFAProvider>,
    /// Audit logging system
    audit: Arc<AuditLogger>,
    /// Security policies
    policies: Arc<RwLock<SecurityPolicies>>,
    /// Active security sessions
    sessions: Arc<RwLock<HashMap<String, SecuritySession>>>,
}

/// Security policies configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicies {
    /// Minimum security level required
    pub min_security_level: SecurityLevel,
    /// Require HSM for cryptographic operations
    pub require_hsm: bool,
    /// Require post-quantum cryptography
    pub require_pqc: bool,
    /// MFA requirements
    pub mfa_requirements: MFARequirements,
    /// Key rotation policies
    pub key_rotation: KeyRotationPolicy,
    /// Compliance standards to enforce
    pub compliance_standards: Vec<ComplianceStandard>,
    /// Maximum session duration
    pub max_session_duration: chrono::Duration,
    /// Risk tolerance levels
    pub risk_tolerance: RiskTolerance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MFARequirements {
    pub required_methods: u8,
    pub mandatory_methods: Vec<MFAMethod>,
    pub hardware_key_required: bool,
    pub biometric_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationPolicy {
    pub automatic_rotation: bool,
    pub rotation_interval: chrono::Duration,
    pub max_key_age: chrono::Duration,
    pub require_dual_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskTolerance {
    pub max_risk_score: f64,
    pub auto_block_threshold: f64,
    pub require_approval_threshold: f64,
}

/// Security session with comprehensive context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySession {
    pub id: String,
    pub user_id: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub security_level: SecurityLevel,
    pub authenticated_methods: Vec<MFAMethod>,
    pub risk_score: f64,
    pub client_info: ClientInfo,
    pub permissions: Vec<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub geo_location: Option<String>,
    pub device_fingerprint: Option<String>,
}

/// Security operation request with full context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityRequest {
    pub operation: SecurityOperation,
    pub session_id: String,
    pub resource_id: Option<String>,
    pub data_classification: SecurityLevel,
    pub client_info: ClientInfo,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityOperation {
    /// Cryptographic operations
    GenerateKey { algorithm: String, key_size: u32 },
    EncryptData { data: Vec<u8>, key_id: String },
    DecryptData { data: Vec<u8>, key_id: String },
    SignData { data: Vec<u8>, key_id: String },
    VerifySignature { data: Vec<u8>, signature: Vec<u8>, key_id: String },
    
    /// Secret management
    CreateSecret { path: String, value: String },
    ReadSecret { path: String },
    UpdateSecret { path: String, value: String },
    DeleteSecret { path: String },
    
    /// Policy management
    CreatePolicy { name: String, policy: String },
    UpdatePolicy { name: String, policy: String },
    DeletePolicy { name: String },
    
    /// Administrative operations
    RotateKeys { key_ids: Vec<String> },
    BackupData { backup_id: String },
    RestoreData { backup_id: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityResponse {
    pub success: bool,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub risk_assessment: RiskAssessment,
    pub compliance_status: ComplianceStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk_score: f64,
    pub risk_factors: Vec<String>,
    pub mitigation_required: bool,
    pub recommendations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceStatus {
    pub compliant: bool,
    pub standards_met: Vec<ComplianceStandard>,
    pub violations: Vec<String>,
    pub remediation_steps: Vec<String>,
}

impl Default for SecurityPolicies {
    fn default() -> Self {
        Self {
            min_security_level: SecurityLevel::Internal,
            require_hsm: true,
            require_pqc: true,
            mfa_requirements: MFARequirements {
                required_methods: 2,
                mandatory_methods: vec![MFAMethod::TOTP],
                hardware_key_required: true,
                biometric_required: false,
            },
            key_rotation: KeyRotationPolicy {
                automatic_rotation: true,
                rotation_interval: chrono::Duration::days(90),
                max_key_age: chrono::Duration::days(365),
                require_dual_approval: true,
            },
            compliance_standards: vec![
                ComplianceStandard::FIPS140_3,
                ComplianceStandard::SOC2TypeII,
                ComplianceStandard::ISO27001,
            ],
            max_session_duration: chrono::Duration::hours(8),
            risk_tolerance: RiskTolerance {
                max_risk_score: 7.0,
                auto_block_threshold: 8.5,
                require_approval_threshold: 6.0,
            },
        }
    }
}

impl SecurityManager {
    /// Create new security manager with all components
    pub async fn new(
        hsm: Arc<dyn HSMOperations>,
        pqc: Arc<PostQuantumCrypto>,
        mfa: Arc<dyn MFAProvider>,
        audit: Arc<AuditLogger>,
    ) -> Result<Self, CoreError> {
        let policies = Arc::new(RwLock::new(SecurityPolicies::default()));
        let sessions = Arc::new(RwLock::new(HashMap::new()));
        
        Ok(Self {
            hsm,
            pqc,
            mfa,
            audit,
            policies,
            sessions,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_policies_default() {
        let policies = SecurityPolicies::default();
        assert_eq!(policies.min_security_level, SecurityLevel::Internal);
        assert!(policies.require_hsm);
        assert!(policies.require_pqc);
        assert_eq!(policies.mfa_requirements.required_methods, 2);
    }
}
