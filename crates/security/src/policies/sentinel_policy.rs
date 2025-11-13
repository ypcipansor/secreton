// Sentinel Policy Engine - Policy-as-code enforcement
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Policy error: {0}")]
    PolicyError(String),
    #[error("Evaluation error: {0}")]
    EvaluationError(String),
    #[error("Enforcement error: {0}")]
    EnforcementError(String),
}

pub type Result<T> = std::result::Result<T, PolicyError>;

/// Enforcement level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementLevel {
    Advisory,      // Log violations but allow
    SoftMandatory, // Require override to proceed
    HardMandatory, // Block operation
}

/// Policy decision
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Decision {
    Allow,
    Deny,
}

/// Policy violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    pub rule: String,
    pub message: String,
    pub severity: String, // warning, error, critical
}

/// Sentinel policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub name: String,
    pub code: String, // Sentinel policy code
    pub enforcement_level: EnforcementLevel,
    pub description: String,
    pub created_at: DateTime<Utc>,
}

/// Evaluation context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationContext {
    pub request_path: String,
    pub operation: String, // read, write, delete
    pub entity_id: String,
    pub metadata: HashMap<String, String>,
}

/// Evaluation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub policy_name: String,
    pub decision: Decision,
    pub allowed: bool,
    pub violations: Vec<Violation>,
    pub enforcement_level: EnforcementLevel,
    pub evaluated_at: DateTime<Utc>,
    pub metadata: HashMap<String, String>,
}

/// Audit record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub audit_id: String,
    pub policy_name: String,
    pub context: EvaluationContext,
    pub result: EvaluationResult,
    pub override_applied: bool,
    pub override_reason: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Sentinel Policy Engine
pub struct SentinelEngine {
    policies: Arc<RwLock<HashMap<String, Policy>>>,
    audit_log: Arc<RwLock<Vec<AuditRecord>>>,
}

impl SentinelEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            audit_log: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Register policy
    pub async fn register_policy(&self, policy: Policy) -> Result<()> {
        if policy.code.is_empty() {
            return Err(PolicyError::PolicyError(
                "Policy code cannot be empty".to_string(),
            ));
        }

        let mut policies = self.policies.write().await;
        policies.insert(policy.name.clone(), policy);

        Ok(())
    }

    /// Evaluate request
    pub async fn evaluate_request(
        &self,
        context: EvaluationContext,
    ) -> Result<Vec<EvaluationResult>> {
        let policies = self.policies.read().await;
        let mut results = Vec::new();

        for (_, policy) in policies.iter() {
            let result = self.evaluate_policy(policy, &context).await?;
            results.push(result);
        }

        Ok(results)
    }

    /// Evaluate single policy
    async fn evaluate_policy(
        &self,
        policy: &Policy,
        context: &EvaluationContext,
    ) -> Result<EvaluationResult> {
        // Simple JSON-based Sentinel policy evaluation
        let violations = self.check_policy_rules(policy, context);

        let decision = if violations.is_empty() {
            Decision::Allow
        } else {
            Decision::Deny
        };

        let allowed = match policy.enforcement_level {
            EnforcementLevel::Advisory => true,
            EnforcementLevel::SoftMandatory => violations.is_empty(),
            EnforcementLevel::HardMandatory => violations.is_empty(),
        };

        let mut metadata = HashMap::new();
        metadata.insert("policy_version".to_string(), "1.0".to_string());
        metadata.insert("engine".to_string(), "sentinel".to_string());

        Ok(EvaluationResult {
            policy_name: policy.name.clone(),
            decision,
            allowed,
            violations,
            enforcement_level: policy.enforcement_level.clone(),
            evaluated_at: Utc::now(),
            metadata,
        })
    }

    /// Check policy rules using JSON-based evaluation
    fn check_policy_rules(&self, policy: &Policy, context: &EvaluationContext) -> Vec<Violation> {
        let mut violations = Vec::new();

        // Try to parse policy code as JSON
        if let Ok(rules) = serde_json::from_str::<serde_json::Value>(&policy.code) {
            if let Some(obj) = rules.as_object() {
                for (rule_name, rule_config) in obj {
                    self.evaluate_rule(rule_name, rule_config, context, &mut violations);
                }
            }
        } else {
            // Fallback to keyword-based rules for backward compatibility
            if policy.code.contains("require_mfa") && !context.metadata.contains_key("mfa_verified")
            {
                violations.push(Violation {
                    rule: "require_mfa".to_string(),
                    message: "MFA verification required".to_string(),
                    severity: "error".to_string(),
                });
            }

            if policy.code.contains("block_production")
                && context.request_path.contains("production")
            {
                violations.push(Violation {
                    rule: "block_production".to_string(),
                    message: "Production access blocked by policy".to_string(),
                    severity: "critical".to_string(),
                });
            }

            if policy.code.contains("working_hours") {
                let hour = Utc::now().hour();
                if !(8..=18).contains(&hour) {
                    violations.push(Violation {
                        rule: "working_hours".to_string(),
                        message: "Access only allowed during working hours (8AM-6PM)".to_string(),
                        severity: "warning".to_string(),
                    });
                }
            }

            if policy.code.contains("max_ttl")
                && let Some(ttl) = context.metadata.get("ttl")
                    && let Ok(ttl_value) = ttl.parse::<i64>()
                        && ttl_value > 86400 {
                            violations.push(Violation {
                                rule: "max_ttl".to_string(),
                                message: "TTL exceeds maximum of 24 hours".to_string(),
                                severity: "error".to_string(),
                            });
                        }
        }

        violations
    }

    /// Evaluate a single rule
    fn evaluate_rule(
        &self,
        rule_name: &str,
        rule_config: &serde_json::Value,
        context: &EvaluationContext,
        violations: &mut Vec<Violation>,
    ) {
        match rule_name {
            "require_mfa" => {
                if let Some(required) = rule_config.as_bool()
                    && required && !context.metadata.contains_key("mfa_verified") {
                        violations.push(Violation {
                            rule: rule_name.to_string(),
                            message: "MFA verification required".to_string(),
                            severity: "error".to_string(),
                        });
                    }
            }
            "block_production" => {
                if let Some(block) = rule_config.as_bool()
                    && block && context.request_path.contains("production") {
                        violations.push(Violation {
                            rule: rule_name.to_string(),
                            message: "Production access blocked by policy".to_string(),
                            severity: "critical".to_string(),
                        });
                    }
            }
            "working_hours" => {
                if let Some(hours) = rule_config.as_object()
                    && let (Some(start), Some(end)) = (hours.get("start"), hours.get("end"))
                        && let (Some(start_hour), Some(end_hour)) = (start.as_u64(), end.as_u64()) {
                            let current_hour = Utc::now().hour() as u64;
                            if current_hour < start_hour || current_hour > end_hour {
                                violations.push(Violation {
                                    rule: rule_name.to_string(),
                                    message: format!(
                                        "Access only allowed during working hours ({}AM-{}PM)",
                                        start_hour, end_hour
                                    ),
                                    severity: "warning".to_string(),
                                });
                            }
                        }
            }
            "max_ttl" => {
                if let Some(max_ttl) = rule_config.as_u64()
                    && let Some(ttl) = context.metadata.get("ttl")
                        && let Ok(ttl_value) = ttl.parse::<u64>()
                            && ttl_value > max_ttl {
                                violations.push(Violation {
                                    rule: rule_name.to_string(),
                                    message: format!("TTL exceeds maximum of {} seconds", max_ttl),
                                    severity: "error".to_string(),
                                });
                            }
            }
            "ip_whitelist" => {
                if let Some(ips) = rule_config.as_array() {
                    if let Some(client_ip) = context.metadata.get("client_ip") {
                        let allowed = ips.iter().any(|ip| {
                            if let Some(ip_str) = ip.as_str() {
                                ip_str == client_ip
                            } else {
                                false
                            }
                        });
                        if !allowed {
                            violations.push(Violation {
                                rule: rule_name.to_string(),
                                message: "Client IP not in whitelist".to_string(),
                                severity: "error".to_string(),
                            });
                        }
                    } else {
                        violations.push(Violation {
                            rule: rule_name.to_string(),
                            message: "Client IP required but not provided".to_string(),
                            severity: "error".to_string(),
                        });
                    }
                }
            }
            _ => {
                // Unknown rule, ignore or log
            }
        }
    }

    /// Check authorization with policies
    pub async fn check_authorization(&self, context: EvaluationContext) -> Result<bool> {
        let results = self.evaluate_request(context.clone()).await?;

        // Log to audit
        for result in &results {
            self.audit_decision(context.clone(), result.clone(), false, None)
                .await?;
        }

        // Deny if any hard-mandatory policy denies
        for result in &results {
            if result.enforcement_level == EnforcementLevel::HardMandatory && !result.allowed {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Apply override
    pub async fn apply_override(
        &self,
        context: EvaluationContext,
        policy_name: &str,
        reason: String,
    ) -> Result<()> {
        let policies = self.policies.read().await;
        let policy = policies
            .get(policy_name)
            .ok_or_else(|| PolicyError::PolicyError("Policy not found".to_string()))?;

        if policy.enforcement_level == EnforcementLevel::HardMandatory {
            return Err(PolicyError::EnforcementError(
                "Cannot override hard-mandatory policy".to_string(),
            ));
        }

        let result = self.evaluate_policy(policy, &context).await?;
        self.audit_decision(context, result, true, Some(reason))
            .await?;

        Ok(())
    }

    /// Audit decision
    async fn audit_decision(
        &self,
        context: EvaluationContext,
        result: EvaluationResult,
        override_applied: bool,
        override_reason: Option<String>,
    ) -> Result<()> {
        let record = AuditRecord {
            audit_id: uuid::Uuid::new_v4().to_string(),
            policy_name: result.policy_name.clone(),
            context,
            result,
            override_applied,
            override_reason,
            timestamp: Utc::now(),
        };

        let mut audit_log = self.audit_log.write().await;
        audit_log.push(record);

        Ok(())
    }

    /// List policies
    pub async fn list_policies(&self) -> Vec<String> {
        let policies = self.policies.read().await;
        policies.keys().cloned().collect()
    }

    /// Get policy
    pub async fn get_policy(&self, name: &str) -> Option<Policy> {
        let policies = self.policies.read().await;
        policies.get(name).cloned()
    }

    /// Delete policy
    pub async fn delete_policy(&self, name: &str) -> Result<()> {
        let mut policies = self.policies.write().await;
        policies
            .remove(name)
            .ok_or_else(|| PolicyError::PolicyError("Policy not found".to_string()))?;

        Ok(())
    }

    /// Get audit log
    pub async fn get_audit_log(&self, policy_name: Option<&str>) -> Vec<AuditRecord> {
        let audit_log = self.audit_log.read().await;

        if let Some(name) = policy_name {
            audit_log
                .iter()
                .filter(|r| r.policy_name == name)
                .cloned()
                .collect()
        } else {
            audit_log.clone()
        }
    }

    /// Get violations count
    pub async fn get_violations_count(&self, policy_name: &str) -> usize {
        let audit_log = self.audit_log.read().await;
        audit_log
            .iter()
            .filter(|r| r.policy_name == policy_name && !r.result.violations.is_empty())
            .count()
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

    fn create_test_policy(name: &str, enforcement: EnforcementLevel) -> Policy {
        Policy {
            name: name.to_string(),
            code: "rule \"require_mfa\" { mfa_verified == true }".to_string(),
            enforcement_level: enforcement,
            description: "Test policy".to_string(),
            created_at: Utc::now(),
        }
    }

    fn create_test_context() -> EvaluationContext {
        let mut metadata = HashMap::new();
        metadata.insert("mfa_verified".to_string(), "true".to_string());

        EvaluationContext {
            request_path: "/secret/data/app".to_string(),
            operation: "read".to_string(),
            entity_id: "user123".to_string(),
            metadata,
        }
    }

    #[tokio::test]
    async fn test_register_policy() {
        let engine = SentinelEngine::new();
        let policy = create_test_policy("mfa-required", EnforcementLevel::HardMandatory);

        engine.register_policy(policy).await.unwrap();

        let policies = engine.list_policies().await;
        assert_eq!(policies.len(), 1);
        assert_eq!(policies[0], "mfa-required");
    }

    #[tokio::test]
    async fn test_evaluate_allow() {
        let engine = SentinelEngine::new();
        let policy = create_test_policy("mfa-required", EnforcementLevel::HardMandatory);

        engine.register_policy(policy).await.unwrap();

        let context = create_test_context();
        let results = engine.evaluate_request(context).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Decision::Allow);
        assert!(results[0].allowed);
        assert!(results[0].violations.is_empty());
    }

    #[tokio::test]
    async fn test_evaluate_deny() {
        let engine = SentinelEngine::new();
        let policy = create_test_policy("mfa-required", EnforcementLevel::HardMandatory);

        engine.register_policy(policy).await.unwrap();

        // Context without MFA
        let context = EvaluationContext {
            request_path: "/secret/data/app".to_string(),
            operation: "read".to_string(),
            entity_id: "user123".to_string(),
            metadata: HashMap::new(),
        };

        let results = engine.evaluate_request(context).await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Decision::Deny);
        assert!(!results[0].allowed);
        assert!(!results[0].violations.is_empty());
    }

    #[tokio::test]
    async fn test_enforcement_levels() {
        let engine = SentinelEngine::new();

        // Advisory - allows even with violations
        let advisory_policy = Policy {
            name: "advisory".to_string(),
            code: "rule \"require_mfa\" { mfa_verified == true }".to_string(),
            enforcement_level: EnforcementLevel::Advisory,
            description: "Advisory policy".to_string(),
            created_at: Utc::now(),
        };

        engine.register_policy(advisory_policy).await.unwrap();

        let context = EvaluationContext {
            request_path: "/secret/data/app".to_string(),
            operation: "read".to_string(),
            entity_id: "user123".to_string(),
            metadata: HashMap::new(),
        };

        let results = engine.evaluate_request(context).await.unwrap();
        assert!(results[0].allowed); // Advisory allows despite violations
    }

    #[tokio::test]
    async fn test_audit_logging() {
        let engine = SentinelEngine::new();
        let policy = create_test_policy("mfa-required", EnforcementLevel::HardMandatory);

        engine.register_policy(policy).await.unwrap();

        let context = create_test_context();
        engine.check_authorization(context).await.unwrap();

        let audit_log = engine.get_audit_log(Some("mfa-required")).await;
        assert_eq!(audit_log.len(), 1);
        assert_eq!(audit_log[0].policy_name, "mfa-required");
        assert!(!audit_log[0].override_applied);
    }

    #[tokio::test]
    async fn test_policy_override() {
        let engine = SentinelEngine::new();

        // Soft-mandatory can be overridden
        let policy = Policy {
            name: "soft-policy".to_string(),
            code: "rule \"require_mfa\" { mfa_verified == true }".to_string(),
            enforcement_level: EnforcementLevel::SoftMandatory,
            description: "Soft policy".to_string(),
            created_at: Utc::now(),
        };

        engine.register_policy(policy).await.unwrap();

        let context = EvaluationContext {
            request_path: "/secret/data/app".to_string(),
            operation: "read".to_string(),
            entity_id: "user123".to_string(),
            metadata: HashMap::new(),
        };

        engine
            .apply_override(context, "soft-policy", "Emergency access".to_string())
            .await
            .unwrap();

        let audit_log = engine.get_audit_log(Some("soft-policy")).await;
        assert!(audit_log[0].override_applied);
        assert_eq!(
            audit_log[0].override_reason.as_ref().unwrap(),
            "Emergency access"
        );
    }
}
