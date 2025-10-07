//! Secret Discovery & Classification
//!
//! Provides automatic secret scanning in code/configs, secret classification
//! by sensitivity levels, metadata enrichment, and discovery policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("Scan failed: {0}")]
    ScanFailed(String),
    #[error("Classification failed: {0}")]
    ClassificationFailed(String),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
}

pub type Result<T> = std::result::Result<T, DiscoveryError>;

/// Sensitivity classification levels
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum SensitivityLevel {
    Public,
    Internal,
    Confidential,
    Restricted,
    TopSecret,
}

/// Discovery rule for pattern matching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryRule {
    pub rule_id: String,
    pub name: String,
    pub pattern: String,
    pub file_types: Vec<String>,
    pub exclusions: Vec<String>,
    pub sensitivity: SensitivityLevel,
    pub enabled: bool,
}

/// Discovered secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSecret {
    pub discovery_id: String,
    pub location: SecretLocation,
    pub secret_type: SecretType,
    pub classification: SensitivityLevel,
    pub confidence_score: f64,
    pub discovered_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
    pub remediation_status: RemediationStatus,
}

/// Secret location information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretLocation {
    pub repository: String,
    pub file_path: String,
    pub line_number: usize,
    pub context: String,
}

/// Secret type classification
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SecretType {
    APIKey,
    Password,
    PrivateKey,
    Certificate,
    Token,
    DatabaseCredential,
    CloudCredential,
    EncryptionKey,
    Unknown,
}

/// Remediation status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum RemediationStatus {
    Pending,
    InProgress,
    Resolved,
    Ignored,
    FalsePositive,
}

/// Scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub scan_id: String,
    pub target: ScanTarget,
    pub rules: Vec<String>,
    pub recursive: bool,
    pub max_file_size_mb: usize,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanTarget {
    Repository(String),
    Directory(String),
    File(String),
}

/// Scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub scan_id: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub files_scanned: usize,
    pub secrets_found: usize,
    pub status: ScanStatus,
    pub discoveries: Vec<DiscoveredSecret>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// Metadata enrichment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentData {
    pub owner: Option<String>,
    pub team: Option<String>,
    pub environment: Option<String>,
    pub cost_center: Option<String>,
    pub compliance_tags: Vec<String>,
    pub custom_fields: HashMap<String, String>,
}

/// Discovery policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPolicy {
    pub policy_id: String,
    pub name: String,
    pub auto_classify: bool,
    pub auto_remediate: bool,
    pub notification_enabled: bool,
    pub notification_channels: Vec<String>,
}

/// Secret discovery & classification engine
pub struct SecretDiscovery {
    rules: Arc<RwLock<HashMap<String, DiscoveryRule>>>,
    discoveries: Arc<RwLock<HashMap<String, DiscoveredSecret>>>,
    scans: Arc<RwLock<HashMap<String, ScanResult>>>,
    policies: Arc<RwLock<HashMap<String, DiscoveryPolicy>>>,
}

impl SecretDiscovery {
    pub fn new() -> Self {
        Self {
            rules: Arc::new(RwLock::new(HashMap::new())),
            discoveries: Arc::new(RwLock::new(HashMap::new())),
            scans: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add discovery rule
    pub async fn add_rule(&self, rule: DiscoveryRule) -> Result<String> {
        let rule_id = rule.rule_id.clone();
        let mut rules = self.rules.write().await;
        rules.insert(rule_id.clone(), rule);
        Ok(rule_id)
    }

    /// Scan repository for secrets
    pub async fn scan_repository(&self, config: ScanConfig) -> Result<ScanResult> {
        let scan_id = config.scan_id.clone();
        
        let mut result = ScanResult {
            scan_id: scan_id.clone(),
            started_at: Utc::now(),
            completed_at: None,
            files_scanned: 0,
            secrets_found: 0,
            status: ScanStatus::Running,
            discoveries: vec![],
        };

        // Mock scanning
        let rules = self.rules.read().await;
        
        // Simulate finding secrets
        for rule in rules.values().filter(|r| r.enabled) {
            if self.should_scan_with_rule(rule, &config) {
                let discovery = self.create_mock_discovery(rule, &config).await;
                result.discoveries.push(discovery);
            }
        }

        result.files_scanned = 10; // Mock
        result.secrets_found = result.discoveries.len();
        result.status = ScanStatus::Completed;
        result.completed_at = Some(Utc::now());

        // Store discoveries
        let mut discoveries = self.discoveries.write().await;
        for discovery in &result.discoveries {
            discoveries.insert(discovery.discovery_id.clone(), discovery.clone());
        }

        let mut scans = self.scans.write().await;
        scans.insert(scan_id, result.clone());

        Ok(result)
    }

    /// Check if rule should be applied to scan
    fn should_scan_with_rule(&self, rule: &DiscoveryRule, config: &ScanConfig) -> bool {
        if config.rules.is_empty() {
            return true;
        }
        config.rules.contains(&rule.rule_id)
    }

    /// Create mock discovery
    async fn create_mock_discovery(
        &self,
        rule: &DiscoveryRule,
        config: &ScanConfig,
    ) -> DiscoveredSecret {
        let target_path = match &config.target {
            ScanTarget::Repository(path) => path.clone(),
            ScanTarget::Directory(path) => path.clone(),
            ScanTarget::File(path) => path.clone(),
        };

        DiscoveredSecret {
            discovery_id: Uuid::new_v4().to_string(),
            location: SecretLocation {
                repository: target_path.clone(),
                file_path: format!("{}/config.yaml", target_path),
                line_number: 42,
                context: "password: ***REDACTED***".to_string(),
            },
            secret_type: SecretType::Password,
            classification: rule.sensitivity.clone(),
            confidence_score: 0.95,
            discovered_at: Utc::now(),
            metadata: HashMap::new(),
            remediation_status: RemediationStatus::Pending,
        }
    }

    /// Classify secret
    pub async fn classify_secret(
        &self,
        secret_value: &str,
        context: Option<String>,
    ) -> Result<(SecretType, SensitivityLevel, f64)> {
        // Mock classification logic
        let (secret_type, sensitivity, confidence) = if secret_value.starts_with("sk-") {
            (SecretType::APIKey, SensitivityLevel::Confidential, 0.95)
        } else if secret_value.starts_with("-----BEGIN") {
            (SecretType::PrivateKey, SensitivityLevel::Restricted, 0.98)
        } else if secret_value.len() > 32 && secret_value.chars().all(|c| c.is_alphanumeric()) {
            (SecretType::Token, SensitivityLevel::Confidential, 0.85)
        } else if context.as_ref().map(|c| c.contains("password")).unwrap_or(false) {
            (SecretType::Password, SensitivityLevel::Confidential, 0.80)
        } else {
            (SecretType::Unknown, SensitivityLevel::Internal, 0.50)
        };

        Ok((secret_type, sensitivity, confidence))
    }

    /// Enrich secret metadata
    pub async fn enrich_metadata(
        &self,
        discovery_id: &str,
        enrichment: EnrichmentData,
    ) -> Result<()> {
        let mut discoveries = self.discoveries.write().await;
        
        if let Some(discovery) = discoveries.get_mut(discovery_id) {
            if let Some(owner) = enrichment.owner {
                discovery.metadata.insert("owner".to_string(), owner);
            }
            if let Some(team) = enrichment.team {
                discovery.metadata.insert("team".to_string(), team);
            }
            if let Some(env) = enrichment.environment {
                discovery.metadata.insert("environment".to_string(), env);
            }
            if let Some(cc) = enrichment.cost_center {
                discovery.metadata.insert("cost_center".to_string(), cc);
            }
            
            for (key, value) in enrichment.custom_fields {
                discovery.metadata.insert(key, value);
            }
        }

        Ok(())
    }

    /// Update remediation status
    pub async fn update_remediation_status(
        &self,
        discovery_id: &str,
        status: RemediationStatus,
    ) -> Result<()> {
        let mut discoveries = self.discoveries.write().await;
        
        if let Some(discovery) = discoveries.get_mut(discovery_id) {
            discovery.remediation_status = status;
        }

        Ok(())
    }

    /// Get discoveries by sensitivity
    pub async fn get_discoveries_by_sensitivity(
        &self,
        level: SensitivityLevel,
    ) -> Vec<DiscoveredSecret> {
        let discoveries = self.discoveries.read().await;
        discoveries
            .values()
            .filter(|d| d.classification == level)
            .cloned()
            .collect()
    }

    /// Get pending remediations
    pub async fn get_pending_remediations(&self) -> Vec<DiscoveredSecret> {
        let discoveries = self.discoveries.read().await;
        discoveries
            .values()
            .filter(|d| d.remediation_status == RemediationStatus::Pending)
            .cloned()
            .collect()
    }

    /// Add discovery policy
    pub async fn add_policy(&self, policy: DiscoveryPolicy) -> Result<String> {
        let policy_id = policy.policy_id.clone();
        let mut policies = self.policies.write().await;
        policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    /// Get scan result
    pub async fn get_scan_result(&self, scan_id: &str) -> Option<ScanResult> {
        let scans = self.scans.read().await;
        scans.get(scan_id).cloned()
    }

    /// List all discoveries
    pub async fn list_discoveries(&self) -> Vec<DiscoveredSecret> {
        let discoveries = self.discoveries.read().await;
        discoveries.values().cloned().collect()
    }

    /// Get discovery statistics
    pub async fn get_statistics(&self) -> HashMap<String, usize> {
        let discoveries = self.discoveries.read().await;
        let mut stats = HashMap::new();

        stats.insert("total".to_string(), discoveries.len());
        
        for level in [
            SensitivityLevel::Public,
            SensitivityLevel::Internal,
            SensitivityLevel::Confidential,
            SensitivityLevel::Restricted,
            SensitivityLevel::TopSecret,
        ] {
            let count = discoveries.values().filter(|d| d.classification == level).count();
            stats.insert(format!("{:?}", level).to_lowercase(), count);
        }

        stats
    }
}

impl Default for SecretDiscovery {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_discovery_rule() {
        let discovery = SecretDiscovery::new();
        let rule = DiscoveryRule {
            rule_id: "rule1".to_string(),
            name: "API Key Pattern".to_string(),
            pattern: r"sk-[a-zA-Z0-9]{32}".to_string(),
            file_types: vec!["*.yaml".to_string(), "*.json".to_string()],
            exclusions: vec!["test/*".to_string()],
            sensitivity: SensitivityLevel::Confidential,
            enabled: true,
        };

        let rule_id = discovery.add_rule(rule).await.unwrap();
        assert_eq!(rule_id, "rule1");
    }

    #[tokio::test]
    async fn test_scan_repository() {
        let discovery = SecretDiscovery::new();
        
        // Add a rule first
        let rule = DiscoveryRule {
            rule_id: "rule1".to_string(),
            name: "Password Pattern".to_string(),
            pattern: r"password\s*=\s*.+".to_string(),
            file_types: vec!["*.yaml".to_string()],
            exclusions: vec![],
            sensitivity: SensitivityLevel::Confidential,
            enabled: true,
        };
        discovery.add_rule(rule).await.unwrap();

        let config = ScanConfig {
            scan_id: Uuid::new_v4().to_string(),
            target: ScanTarget::Repository("/repo/path".to_string()),
            rules: vec![],
            recursive: true,
            max_file_size_mb: 10,
            exclude_patterns: vec![],
        };

        let result = discovery.scan_repository(config).await.unwrap();
        
        assert_eq!(result.status, ScanStatus::Completed);
        assert!(result.secrets_found > 0);
    }

    #[tokio::test]
    async fn test_classify_secret() {
        let discovery = SecretDiscovery::new();
        
        let (secret_type, sensitivity, confidence) = discovery
            .classify_secret("sk-1234567890abcdef1234567890abcdef", None)
            .await
            .unwrap();
        
        assert_eq!(secret_type, SecretType::APIKey);
        assert_eq!(sensitivity, SensitivityLevel::Confidential);
        assert!(confidence > 0.9);
    }

    #[tokio::test]
    async fn test_enrich_metadata() {
        let discovery = SecretDiscovery::new();
        
        // Create a discovery first
        let rule = DiscoveryRule {
            rule_id: "rule1".to_string(),
            name: "Test Rule".to_string(),
            pattern: "test".to_string(),
            file_types: vec![],
            exclusions: vec![],
            sensitivity: SensitivityLevel::Internal,
            enabled: true,
        };
        discovery.add_rule(rule).await.unwrap();

        let config = ScanConfig {
            scan_id: Uuid::new_v4().to_string(),
            target: ScanTarget::File("/test.yaml".to_string()),
            rules: vec![],
            recursive: false,
            max_file_size_mb: 10,
            exclude_patterns: vec![],
        };

        let result = discovery.scan_repository(config).await.unwrap();
        let discovery_id = result.discoveries[0].discovery_id.clone();

        let enrichment = EnrichmentData {
            owner: Some("team-security".to_string()),
            team: Some("security".to_string()),
            environment: Some("production".to_string()),
            cost_center: None,
            compliance_tags: vec![],
            custom_fields: HashMap::new(),
        };

        discovery.enrich_metadata(&discovery_id, enrichment).await.unwrap();

        let discoveries = discovery.list_discoveries().await;
        let enriched = discoveries.iter().find(|d| d.discovery_id == discovery_id).unwrap();
        
        assert_eq!(enriched.metadata.get("owner").unwrap(), "team-security");
    }

    #[tokio::test]
    async fn test_get_discoveries_by_sensitivity() {
        let discovery = SecretDiscovery::new();
        
        let rule = DiscoveryRule {
            rule_id: "rule1".to_string(),
            name: "Test".to_string(),
            pattern: "test".to_string(),
            file_types: vec![],
            exclusions: vec![],
            sensitivity: SensitivityLevel::TopSecret,
            enabled: true,
        };
        discovery.add_rule(rule).await.unwrap();

        let config = ScanConfig {
            scan_id: Uuid::new_v4().to_string(),
            target: ScanTarget::File("/test.yaml".to_string()),
            rules: vec![],
            recursive: false,
            max_file_size_mb: 10,
            exclude_patterns: vec![],
        };

        discovery.scan_repository(config).await.unwrap();

        let top_secret = discovery
            .get_discoveries_by_sensitivity(SensitivityLevel::TopSecret)
            .await;
        
        assert!(!top_secret.is_empty());
    }

    #[tokio::test]
    async fn test_get_statistics() {
        let discovery = SecretDiscovery::new();
        
        let rule = DiscoveryRule {
            rule_id: "rule1".to_string(),
            name: "Test".to_string(),
            pattern: "test".to_string(),
            file_types: vec![],
            exclusions: vec![],
            sensitivity: SensitivityLevel::Confidential,
            enabled: true,
        };
        discovery.add_rule(rule).await.unwrap();

        let config = ScanConfig {
            scan_id: Uuid::new_v4().to_string(),
            target: ScanTarget::File("/test.yaml".to_string()),
            rules: vec![],
            recursive: false,
            max_file_size_mb: 10,
            exclude_patterns: vec![],
        };

        discovery.scan_repository(config).await.unwrap();

        let stats = discovery.get_statistics().await;
        
        assert!(stats.get("total").unwrap() > &0);
    }
}
