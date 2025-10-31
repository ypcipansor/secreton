//! # Secreton Enterprise Features
//!
//! Enterprise-grade security features for Secreton including
//! advanced HSM integration, zero-knowledge proofs, and compliance frameworks.

use serde::{Deserialize, Serialize};

pub mod advanced_features;
pub mod error;
pub mod versioning;
pub mod zkp;

// Re-export main types
pub use advanced_features::*;
pub use error::EnterpriseError;

/// Enterprise feature result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseResult {
    /// Whether the operation was successful
    pub success: bool,
    /// Feature used
    pub feature: String,
    /// Operation performed
    pub operation: String,
    /// Result data
    pub data: Option<serde_json::Value>,
    /// Performance metrics
    pub metrics: Option<PerformanceMetrics>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Performance metrics for enterprise operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Operation duration in milliseconds
    pub duration_ms: u64,
    /// Memory usage in bytes
    pub memory_bytes: u64,
    /// CPU usage percentage
    pub cpu_percentage: f64,
    /// Security level achieved
    pub security_level: String,
}

/// Enterprise feature trait
#[async_trait::async_trait]
pub trait EnterpriseFeature: Send + Sync {
    /// Feature name
    fn name(&self) -> &str;

    /// Check if feature is available
    async fn is_available(&self) -> bool;

    /// Execute enterprise operation
    async fn execute(&self, input: serde_json::Value) -> Result<EnterpriseResult, EnterpriseError>;

    /// Get feature capabilities
    fn capabilities(&self) -> Vec<String>;
}

/// Enterprise security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Standard security
    Standard,
    /// Enhanced security
    Enhanced,
    /// High security with HSM
    High,
    /// Maximum security with quantum resistance
    Maximum,
}

/// Enterprise configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnterpriseConfig {
    /// Security level
    pub security_level: SecurityLevel,
    /// HSM configuration
    pub hsm_config: Option<HsmConfig>,
    /// AI configuration
    pub ai_config: Option<AiConfig>,
    /// Quantum-safe configuration
    pub quantum_config: Option<QuantumConfig>,
    /// Advanced features enabled
    pub features: Vec<String>,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM provider
    pub provider: String,
    /// HSM endpoint
    pub endpoint: String,
    /// Key ID prefix
    pub key_prefix: String,
}

/// AI configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConfig {
    /// AI model endpoint
    pub model_endpoint: String,
    /// API key
    pub api_key: String,
    /// Model name
    pub model_name: String,
}

/// Quantum configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumConfig {
    /// Enable post-quantum algorithms
    pub enable_pqc: bool,
    /// Preferred PQC algorithm
    pub preferred_algorithm: String,
}
