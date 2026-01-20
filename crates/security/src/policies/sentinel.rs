//! Sentinel Policies
//!
//! Policy as code with enforcement levels for advanced authorization.

use chrono::{DateTime, Datelike, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Sentinel errors
#[derive(Debug, thiserror::Error)]
pub enum SentinelError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Policy evaluation failed: {0}")]
    EvaluationFailed(String),

    #[error("Policy denied: {0}")]
    PolicyDenied(String),

    #[error("Invalid policy syntax: {0}")]
    InvalidSyntax(String),
}

/// Enforcement level for policies
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementLevel {
    /// Advisory: logged but always passes
    Advisory,

    /// Soft-mandatory: fails by default but can be overridden
    SoftMandatory,

    /// Hard-mandatory: always fails if policy fails
    HardMandatory,
}

/// Sentinel policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelPolicy {
    /// Policy ID
    #[serde(default)]
    pub id: i64,

    /// Namespace
    #[serde(default)]
    pub namespace: String,

    /// Policy name
    pub name: String,

    /// Policy version
    pub version: u32,

    /// Enforcement level
    pub enforcement_level: EnforcementLevel,

    /// Policy type (egp, rgp, wasm, etc.)
    #[serde(default)]
    pub policy_type: String,

    /// Policy code (simple rule language)
    pub policy_code: String,

    /// Description
    pub description: Option<String>,

    /// EGP flag
    #[serde(default)]
    pub egp: bool,

    /// RGP flag
    #[serde(default)]
    pub rgp: bool,

    /// Created timestamp
    pub created_at: DateTime<Utc>,

    /// Modified timestamp
    pub modified_at: DateTime<Utc>,
}

/// Policy evaluation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    /// Request path
    pub path: String,

    /// Operation (read, write, delete, list)
    pub operation: String,

    /// Identity information
    pub identity: HashMap<String, String>,

    /// Request data
    pub request_data: HashMap<String, serde_json::Value>,

    /// Current time
    pub time: DateTime<Utc>,

    /// Custom metadata
    pub metadata: HashMap<String, String>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    /// Policy name
    pub policy_name: String,

    /// Pass or fail
    pub passed: bool,

    /// Enforcement level
    pub enforcement_level: EnforcementLevel,

    /// Advisory message
    pub message: Option<String>,

    /// Can be overridden (for soft-mandatory)
    pub can_override: bool,

    /// Evaluation duration (ms)
    pub duration_ms: u64,
}

impl EvaluationResult {
    /// Check if this result should block the request
    pub fn should_block(&self) -> bool {
        if self.passed {
            return false;
        }

        match self.enforcement_level {
            EnforcementLevel::Advisory => false,
            EnforcementLevel::SoftMandatory => !self.can_override,
            EnforcementLevel::HardMandatory => true,
        }
    }
}

/// Sentinel policy engine
pub struct SentinelEngine {
    policies: Arc<RwLock<HashMap<String, SentinelPolicy>>>,
}

impl SentinelEngine {
    /// Create new Sentinel engine
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create policy
    pub async fn create_policy(&self, policy: SentinelPolicy) -> Result<(), SentinelError> {
        // Validate policy syntax
        self.validate_policy_code(&policy.policy_code)?;

        let mut policies = self.policies.write().await;
        policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    /// Get policy
    pub async fn get_policy(&self, name: &str) -> Option<SentinelPolicy> {
        let policies = self.policies.read().await;
        policies.get(name).cloned()
    }

    /// Update policy
    pub async fn update_policy(&self, policy: SentinelPolicy) -> Result<(), SentinelError> {
        self.validate_policy_code(&policy.policy_code)?;

        let mut policies = self.policies.write().await;
        if !policies.contains_key(&policy.name) {
            return Err(SentinelError::PolicyNotFound(policy.name.clone()));
        }

        policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    /// Delete policy
    pub async fn delete_policy(&self, name: &str) -> Result<(), SentinelError> {
        let mut policies = self.policies.write().await;
        policies
            .remove(name)
            .ok_or_else(|| SentinelError::PolicyNotFound(name.to_string()))?;
        Ok(())
    }

    /// List all policies
    pub async fn list_policies(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        policies.keys().cloned().collect()
    }

    /// Evaluate policy
    pub async fn evaluate(
        &self,
        policy_name: &str,
        context: &EvaluationContext,
    ) -> Result<EvaluationResult, SentinelError> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_name)
            .ok_or_else(|| SentinelError::PolicyNotFound(policy_name.to_string()))?;

        let start = std::time::Instant::now();

        // Parse and evaluate policy
        let passed = self.evaluate_policy_code(&policy.policy_code, context)?;

        let duration_ms = start.elapsed().as_millis() as u64;

        let message = if !passed {
            Some(format!("Policy '{}' denied the request", policy_name))
        } else {
            None
        };

        Ok(EvaluationResult {
            policy_name: policy_name.to_string(),
            passed,
            enforcement_level: policy.enforcement_level.clone(),
            message,
            can_override: false, // Could be determined by context
            duration_ms,
        })
    }

    /// Evaluate multiple policies
    pub async fn evaluate_policies(
        &self,
        policy_names: &[String],
        context: &EvaluationContext,
    ) -> Vec<EvaluationResult> {
        let mut results = Vec::new();

        for policy_name in policy_names {
            match self.evaluate(policy_name, context).await {
                Ok(result) => results.push(result),
                Err(e) => {
                    // Log error and continue
                    eprintln!("Policy evaluation error: {}", e);
                }
            }
        }

        results
    }

    /// Check if request should be allowed
    pub async fn check_allowed(
        &self,
        policy_names: &[String],
        context: &EvaluationContext,
    ) -> Result<bool, SentinelError> {
        let results = self.evaluate_policies(policy_names, context).await;

        // Check if any hard-mandatory or soft-mandatory policy failed
        for result in results {
            if result.should_block() {
                return Err(SentinelError::PolicyDenied(
                    result
                        .message
                        .unwrap_or_else(|| "Policy denied".to_string()),
                ));
            }
        }

        Ok(true)
    }

    /// Validate policy code syntax
    fn validate_policy_code(&self, code: &str) -> Result<(), SentinelError> {
        if code.is_empty() {
            return Err(SentinelError::InvalidSyntax(
                "Policy code cannot be empty".to_string(),
            ));
        }

        // Simple validation (production would use a proper parser)
        let valid_keywords = ["allow", "deny", "path", "time", "identity", "request"];
        let has_keyword = valid_keywords.iter().any(|kw| code.contains(kw));

        if !has_keyword {
            return Err(SentinelError::InvalidSyntax(
                "Policy must contain at least one valid keyword".to_string(),
            ));
        }

        Ok(())
    }

    /// Evaluate policy code
    fn evaluate_policy_code(
        &self,
        code: &str,
        context: &EvaluationContext,
    ) -> Result<bool, SentinelError> {
        // Simple rule evaluation (production would use a proper interpreter)

        // Rule: "allow if path matches secret/*"
        if code.contains("path matches") {
            if let Some(pattern) = code.split("path matches").nth(1) {
                let pattern = pattern.trim().trim_matches('"');
                return Ok(self.path_matches(&context.path, pattern));
            }
        }

        // Rule: "deny if not business_hours"
        if code.contains("business_hours") {
            let is_business_hours = self.is_business_hours(&context.time);
            if code.contains("deny if not") {
                return Ok(is_business_hours);
            }
        }

        // Rule: "allow if identity has role:admin"
        if code.contains("identity has") {
            if let Some(attr_part) = code.split("identity has").nth(1) {
                let attr_part = attr_part.trim().trim_matches('"');
                if let Some((key, value)) = attr_part.split_once(':') {
                    if let Some(actual_value) = context.identity.get(key) {
                        return Ok(actual_value == value);
                    }
                    return Ok(false);
                }
            }
        }

        // Default: allow
        Ok(true)
    }

    /// Check if path matches pattern (simple wildcard)
    fn path_matches(&self, path: &str, pattern: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }

    /// Check if time is within business hours (9 AM - 5 PM weekdays)
    fn is_business_hours(&self, time: &DateTime<Utc>) -> bool {
        let weekday = time.weekday().number_from_monday();
        let hour = time.hour();

        weekday <= 5 && (9..17).contains(&hour)
    }
}

impl Default for SentinelEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advisory_policy() {
        let engine = SentinelEngine::new();

        let policy = SentinelPolicy {
            name: "test-advisory".to_string(),
            version: 1,
            enforcement_level: EnforcementLevel::Advisory,
            policy_code: "allow if path matches secret/*".to_string(),
            description: Some("Test policy".to_string()),
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        engine.create_policy(policy).await.unwrap();

        let context = EvaluationContext {
            path: "secret/foo".to_string(),
            operation: "read".to_string(),
            identity: HashMap::new(),
            request_data: HashMap::new(),
            time: Utc::now(),
            metadata: HashMap::new(),
        };

        let result = engine.evaluate("test-advisory", &context).await.unwrap();
        assert!(result.passed);
        assert!(!result.should_block());
    }

    #[tokio::test]
    async fn test_hard_mandatory_policy() {
        let engine = SentinelEngine::new();

        let policy = SentinelPolicy {
            name: "require-admin".to_string(),
            version: 1,
            enforcement_level: EnforcementLevel::HardMandatory,
            policy_code: "allow if identity has role:admin".to_string(),
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        engine.create_policy(policy).await.unwrap();

        // Context without admin role
        let mut identity = HashMap::new();
        identity.insert("role".to_string(), "user".to_string());

        let context = EvaluationContext {
            path: "secret/sensitive".to_string(),
            operation: "write".to_string(),
            identity,
            request_data: HashMap::new(),
            time: Utc::now(),
            metadata: HashMap::new(),
        };

        let result = engine.evaluate("require-admin", &context).await.unwrap();
        assert!(!result.passed);
        assert!(result.should_block());
    }

    #[tokio::test]
    async fn test_business_hours_policy() {
        let engine = SentinelEngine::new();

        let policy = SentinelPolicy {
            name: "business-hours".to_string(),
            version: 1,
            enforcement_level: EnforcementLevel::SoftMandatory,
            policy_code: "deny if not business_hours".to_string(),
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        engine.create_policy(policy).await.unwrap();

        let context = EvaluationContext {
            path: "secret/data".to_string(),
            operation: "read".to_string(),
            identity: HashMap::new(),
            request_data: HashMap::new(),
            time: Utc::now(),
            metadata: HashMap::new(),
        };

        let result = engine.evaluate("business-hours", &context).await.unwrap();
        // Result depends on current time
        assert_eq!(result.enforcement_level, EnforcementLevel::SoftMandatory);
    }

    #[tokio::test]
    async fn test_multiple_policies() {
        let engine = SentinelEngine::new();

        let policy1 = SentinelPolicy {
            name: "path-check".to_string(),
            version: 1,
            enforcement_level: EnforcementLevel::Advisory,
            policy_code: "allow if path matches secret/*".to_string(),
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        let policy2 = SentinelPolicy {
            name: "identity-check".to_string(),
            version: 1,
            enforcement_level: EnforcementLevel::HardMandatory,
            policy_code: "allow if identity has role:admin".to_string(),
            description: None,
            created_at: Utc::now(),
            modified_at: Utc::now(),
        };

        engine.create_policy(policy1).await.unwrap();
        engine.create_policy(policy2).await.unwrap();

        let mut identity = HashMap::new();
        identity.insert("role".to_string(), "admin".to_string());

        let context = EvaluationContext {
            path: "secret/test".to_string(),
            operation: "read".to_string(),
            identity,
            request_data: HashMap::new(),
            time: Utc::now(),
            metadata: HashMap::new(),
        };

        let policies = vec!["path-check".to_string(), "identity-check".to_string()];
        let allowed = engine.check_allowed(&policies, &context).await.unwrap();
        assert!(allowed);
    }
}
