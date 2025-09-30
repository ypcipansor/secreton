/// Sentinel Policy Framework for Secreton

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

/// Sentinel policy enforcement level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnforcementLevel {
    /// Advisory - policy failure is logged but not enforced
    Advisory,
    /// Soft-mandatory - policy failure prevents operation but can be overridden
    SoftMandatory,
    /// Hard-mandatory - policy failure prevents operation, cannot be overridden
    HardMandatory,
}

/// Sentinel policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentinelPolicy {
    /// Policy name
    pub name: String,
    /// Policy description
    pub description: String,
    /// Policy code (in Sentinel language or Rust-based DSL)
    pub code: String,
    /// Enforcement level
    pub enforcement_level: EnforcementLevel,
    /// Policy paths (which paths this policy applies to)
    pub paths: Vec<String>,
    /// Policy metadata
    pub metadata: HashMap<String, String>,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Updated timestamp
    pub updated_at: DateTime<Utc>,
}

/// Policy evaluation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyContext {
    /// Request path
    pub path: String,
    /// Request operation (read, write, delete, list)
    pub operation: String,
    /// Request data
    pub data: serde_json::Value,
    /// User identity
    pub identity: UserIdentity,
    /// Request metadata
    pub metadata: HashMap<String, String>,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

/// User identity information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserIdentity {
    /// User ID
    pub user_id: String,
    /// Username
    pub username: String,
    /// User groups
    pub groups: Vec<String>,
    /// User policies
    pub policies: Vec<String>,
    /// User metadata
    pub metadata: HashMap<String, String>,
}

/// Policy evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Policy name
    pub policy_name: String,
    /// Whether policy passed
    pub passed: bool,
    /// Enforcement level
    pub enforcement_level: EnforcementLevel,
    /// Evaluation message
    pub message: String,
    /// Detailed traces
    pub traces: Vec<String>,
    /// Evaluation duration in milliseconds
    pub duration_ms: u64,
}

/// Sentinel policy engine
pub struct SentinelEngine {
    /// Registered policies
    policies: HashMap<String, SentinelPolicy>,
    /// Policy evaluation cache
    cache: HashMap<String, PolicyResult>,
}

impl SentinelEngine {
    /// Create new Sentinel engine
    pub fn new() -> Self {
        Self {
            policies: HashMap::new(),
            cache: HashMap::new(),
        }
    }

    /// Register a new policy
    pub fn register_policy(&mut self, policy: SentinelPolicy) -> Result<(), String> {
        // Validate policy
        self.validate_policy(&policy)?;
        
        self.policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    /// Unregister a policy
    pub fn unregister_policy(&mut self, name: &str) -> Result<(), String> {
        self.policies.remove(name)
            .ok_or_else(|| format!("Policy '{}' not found", name))?;
        Ok(())
    }

    /// Get a policy
    pub fn get_policy(&self, name: &str) -> Option<&SentinelPolicy> {
        self.policies.get(name)
    }

    /// List all policies
    pub fn list_policies(&self) -> Vec<&SentinelPolicy> {
        self.policies.values().collect()
    }

    /// Evaluate policies for a given context
    pub fn evaluate(&self, context: &PolicyContext) -> Vec<PolicyResult> {
        let start = std::time::Instant::now();
        let mut results = Vec::new();

        // Find applicable policies
        let applicable_policies: Vec<&SentinelPolicy> = self.policies.values()
            .filter(|p| self.is_policy_applicable(p, &context.path))
            .collect();

        for policy in applicable_policies {
            let policy_start = std::time::Instant::now();
            let result = self.evaluate_policy(policy, context);
            let duration = policy_start.elapsed().as_millis() as u64;

            results.push(PolicyResult {
                policy_name: policy.name.clone(),
                passed: result.0,
                enforcement_level: policy.enforcement_level,
                message: result.1,
                traces: result.2,
                duration_ms: duration,
            });
        }

        results
    }

    /// Check if operation is allowed based on policy results
    pub fn is_allowed(&self, results: &[PolicyResult]) -> (bool, Vec<String>) {
        let mut allowed = true;
        let mut messages = Vec::new();

        for result in results {
            if !result.passed {
                match result.enforcement_level {
                    EnforcementLevel::Advisory => {
                        messages.push(format!("[ADVISORY] {}: {}", result.policy_name, result.message));
                    }
                    EnforcementLevel::SoftMandatory => {
                        messages.push(format!("[SOFT-MANDATORY] {}: {}", result.policy_name, result.message));
                        // Soft-mandatory can be overridden with proper authorization
                    }
                    EnforcementLevel::HardMandatory => {
                        allowed = false;
                        messages.push(format!("[HARD-MANDATORY] {}: {}", result.policy_name, result.message));
                    }
                }
            }
        }

        (allowed, messages)
    }

    /// Validate policy syntax and structure
    fn validate_policy(&self, policy: &SentinelPolicy) -> Result<(), String> {
        if policy.name.is_empty() {
            return Err("Policy name cannot be empty".to_string());
        }

        if policy.code.is_empty() {
            return Err("Policy code cannot be empty".to_string());
        }

        if policy.paths.is_empty() {
            return Err("Policy must have at least one path".to_string());
        }

        // Additional validation can be added here
        Ok(())
    }

    /// Check if policy applies to given path
    fn is_policy_applicable(&self, policy: &SentinelPolicy, path: &str) -> bool {
        for policy_path in &policy.paths {
            if path.starts_with(policy_path) || policy_path == "*" {
                return true;
            }
        }
        false
    }

    /// Evaluate a single policy
    fn evaluate_policy(&self, policy: &SentinelPolicy, context: &PolicyContext) -> (bool, String, Vec<String>) {
        let mut traces = Vec::new();
        traces.push(format!("Evaluating policy: {}", policy.name));
        traces.push(format!("Path: {}", context.path));
        traces.push(format!("Operation: {}", context.operation));

        // Parse and evaluate policy code
        // This is a simplified implementation - in production, you'd use a proper policy language parser
        let result = self.evaluate_policy_code(&policy.code, context, &mut traces);

        let message = if result {
            format!("Policy '{}' passed", policy.name)
        } else {
            format!("Policy '{}' failed", policy.name)
        };

        (result, message, traces)
    }

    /// Evaluate policy code (simplified implementation)
    fn evaluate_policy_code(&self, code: &str, context: &PolicyContext, traces: &mut Vec<String>) -> bool {
        // This is a simplified rule-based evaluation
        // In production, you'd implement a full policy language parser/interpreter

        traces.push("Parsing policy rules...".to_string());

        // Example rules:
        // - "require_mfa" - requires MFA
        // - "allow_read_only" - only allows read operations
        // - "require_approval" - requires approval
        // - "time_window:09:00-17:00" - only allows during business hours
        // - "ip_whitelist:10.0.0.0/8" - only allows from specific IPs

        for line in code.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line == "require_mfa" {
                traces.push("Checking MFA requirement...".to_string());
                if !context.metadata.contains_key("mfa_verified") {
                    traces.push("MFA not verified".to_string());
                    return false;
                }
            } else if line == "allow_read_only" {
                traces.push("Checking read-only restriction...".to_string());
                if context.operation != "read" && context.operation != "list" {
                    traces.push(format!("Operation '{}' not allowed (read-only)", context.operation));
                    return false;
                }
            } else if line.starts_with("require_group:") {
                let required_group = line.strip_prefix("require_group:").unwrap().trim();
                traces.push(format!("Checking group membership: {}", required_group));
                if !context.identity.groups.contains(&required_group.to_string()) {
                    traces.push(format!("User not in required group: {}", required_group));
                    return false;
                }
            } else if line.starts_with("deny_path:") {
                let denied_path = line.strip_prefix("deny_path:").unwrap().trim();
                traces.push(format!("Checking denied path: {}", denied_path));
                if context.path.starts_with(denied_path) {
                    traces.push(format!("Path '{}' is denied", context.path));
                    return false;
                }
            }
        }

        traces.push("All policy rules passed".to_string());
        true
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

    #[test]
    fn test_sentinel_engine_creation() {
        let engine = SentinelEngine::new();
        assert_eq!(engine.list_policies().len(), 0);
    }

    #[test]
    fn test_register_policy() {
        let mut engine = SentinelEngine::new();
        
        let policy = SentinelPolicy {
            name: "test-policy".to_string(),
            description: "Test policy".to_string(),
            code: "require_mfa".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            paths: vec!["secret/*".to_string()],
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(engine.register_policy(policy).is_ok());
        assert_eq!(engine.list_policies().len(), 1);
    }

    #[test]
    fn test_policy_validation() {
        let mut engine = SentinelEngine::new();
        
        let invalid_policy = SentinelPolicy {
            name: "".to_string(),
            description: "Invalid".to_string(),
            code: "test".to_string(),
            enforcement_level: EnforcementLevel::Advisory,
            paths: vec!["*".to_string()],
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        assert!(engine.register_policy(invalid_policy).is_err());
    }

    #[test]
    fn test_enforcement_levels() {
        assert_eq!(EnforcementLevel::Advisory, EnforcementLevel::Advisory);
        assert_ne!(EnforcementLevel::Advisory, EnforcementLevel::HardMandatory);
    }

    #[test]
    fn test_policy_evaluation() {
        let mut engine = SentinelEngine::new();
        
        let policy = SentinelPolicy {
            name: "mfa-policy".to_string(),
            description: "Requires MFA".to_string(),
            code: "require_mfa".to_string(),
            enforcement_level: EnforcementLevel::HardMandatory,
            paths: vec!["secret/*".to_string()],
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        engine.register_policy(policy).unwrap();

        let context = PolicyContext {
            path: "secret/data".to_string(),
            operation: "read".to_string(),
            data: serde_json::json!({}),
            identity: UserIdentity {
                user_id: "user1".to_string(),
                username: "testuser".to_string(),
                groups: vec![],
                policies: vec![],
                metadata: HashMap::new(),
            },
            metadata: HashMap::new(),
            timestamp: Utc::now(),
        };

        let results = engine.evaluate(&context);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed); // Should fail because MFA not verified
    }
}
