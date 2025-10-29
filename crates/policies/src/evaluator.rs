//! Policy evaluation logic

use std::collections::HashMap;
use regex::Regex;
use uuid::Uuid;
use chrono::Utc;

use super::model::{EvaluationContext, EvaluationResult, PolicyEffect, ConditionOperator};
use super::engine::{PolicyEngine, CompiledPolicy, CompiledRule, CompiledCondition};
use super::error::PolicyResult;

/// Policy evaluator for access control decisions
pub struct PolicyEvaluator {
    engine: PolicyEngine,
}

impl PolicyEvaluator {
    /// Create a new policy evaluator
    pub fn new(engine: PolicyEngine) -> Self {
        Self { engine }
    }

    /// Evaluate access request against all applicable policies
    pub fn evaluate(&self, context: &EvaluationContext, subject_roles: &[Uuid]) -> PolicyResult<EvaluationResult> {
        let mut evaluated_policies = Vec::new();
        let _evaluated_roles = subject_roles.to_vec();
        let mut allow_count = 0;
        let mut deny_count = 0;
        let mut reasons = Vec::new();

        // Get all roles in hierarchy
        let all_roles = self.get_role_hierarchy(subject_roles);

        // Evaluate policies for each role
        for role_id in &all_roles {
            if let Some(policies) = self.get_policies_for_role(role_id) {
                for policy_id in policies {
                    if let Some(policy) = self.engine.policies.get(&policy_id) {
                        let result = self.evaluate_policy(policy, context)?;
                        evaluated_policies.push(policy_id);

                        match result {
                            PolicyEvaluation::Allow => {
                                allow_count += 1;
                                reasons.push(format!("Policy {} allows access", policy_id));
                            }
                            PolicyEvaluation::Deny => {
                                deny_count += 1;
                                reasons.push(format!("Policy {} denies access", policy_id));
                            }
                            PolicyEvaluation::NotApplicable => {
                                // Policy doesn't apply to this request
                            }
                        }
                    }
                }
            }
        }

        // Determine final decision based on policy effects
        // Deny takes precedence over allow (default deny)
        let allowed = deny_count == 0 && allow_count > 0;
        let reason = if allowed {
            "Access granted by applicable policies".to_string()
        } else if deny_count > 0 {
            "Access denied by applicable policies".to_string()
        } else {
            "No applicable policies found".to_string()
        };

        Ok(EvaluationResult {
            allowed,
            reason,
            evaluated_policies,
            evaluated_roles: all_roles,
            timestamp: Utc::now(),
        })
    }

    /// Evaluate a single compiled policy
    fn evaluate_policy(&self, policy: &CompiledPolicy, context: &EvaluationContext) -> PolicyResult<PolicyEvaluation> {
        let mut rule_results = Vec::new();

        // Evaluate each rule in the policy
        for rule in &policy.rules {
            let rule_result = self.evaluate_rule(rule, context)?;

            // For ABAC-style policies, if any rule matches, the policy applies
            if matches!(rule_result, RuleEvaluation::Match) {
                return match policy.effect {
                    PolicyEffect::Allow => Ok(PolicyEvaluation::Allow),
                    PolicyEffect::Deny => Ok(PolicyEvaluation::Deny),
                };
            }

            rule_results.push(rule_result);
        }

        // No rules matched
        Ok(PolicyEvaluation::NotApplicable)
    }

    /// Evaluate a single rule
    fn evaluate_rule(&self, rule: &CompiledRule, context: &EvaluationContext) -> PolicyResult<RuleEvaluation> {
        // Check if action matches
        if !rule.actions.is_empty() && !rule.actions.contains(&context.action) {
            return Ok(RuleEvaluation::NoMatch);
        }

        // Check if resource matches (simplified - could be glob patterns)
        if !rule.resources.is_empty() && !self.resource_matches(&rule.resources, context) {
            return Ok(RuleEvaluation::NoMatch);
        }

        // Evaluate all conditions
        for condition in &rule.conditions {
            if !self.evaluate_condition(condition, context)? {
                return Ok(RuleEvaluation::NoMatch);
            }
        }

        Ok(RuleEvaluation::Match)
    }

    /// Evaluate a single condition
    fn evaluate_condition(&self, condition: &CompiledCondition, context: &EvaluationContext) -> PolicyResult<bool> {
        let attribute_value = self.get_attribute_value(&condition.attribute, context);

        if attribute_value.is_none() && !condition.values.is_empty() {
            // Attribute not present and we have values to compare against
            return Ok(false);
        }

        match condition.operator {
            ConditionOperator::Equals => {
                Ok(attribute_value.as_ref() == Some(&condition.values[0]))
            }
            ConditionOperator::NotEquals => {
                Ok(attribute_value.as_ref() != Some(&condition.values[0]))
            }
            ConditionOperator::Contains => {
                if let Some(value) = &attribute_value {
                    Ok(condition.values.iter().any(|v| value.contains(v)))
                } else {
                    Ok(false)
                }
            }
            ConditionOperator::NotContains => {
                if let Some(value) = &attribute_value {
                    Ok(!condition.values.iter().any(|v| value.contains(v)))
                } else {
                    Ok(true)
                }
            }
            ConditionOperator::In => {
                if let Some(value) = &attribute_value {
                    Ok(condition.values.contains(value))
                } else {
                    Ok(false)
                }
            }
            ConditionOperator::NotIn => {
                if let Some(value) = &attribute_value {
                    Ok(!condition.values.contains(value))
                } else {
                    Ok(true)
                }
            }
            ConditionOperator::GreaterThan => {
                if let (Some(attr_val), Some(cond_val)) = (&attribute_value, condition.values.first()) {
                    if let (Ok(attr_num), Ok(cond_num)) = (attr_val.parse::<f64>(), cond_val.parse::<f64>()) {
                        Ok(attr_num > cond_num)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            ConditionOperator::LessThan => {
                if let (Some(attr_val), Some(cond_val)) = (&attribute_value, condition.values.first()) {
                    if let (Ok(attr_num), Ok(cond_num)) = (attr_val.parse::<f64>(), cond_val.parse::<f64>()) {
                        Ok(attr_num < cond_num)
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
            ConditionOperator::Regex => {
                if let (Some(attr_val), Some(pattern)) = (&attribute_value, condition.values.first()) {
                    if let Ok(regex) = Regex::new(pattern) {
                        Ok(regex.is_match(attr_val))
                    } else {
                        Ok(false)
                    }
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Get attribute value from evaluation context
    fn get_attribute_value(&self, attribute: &str, context: &EvaluationContext) -> Option<String> {
        // Parse attribute path (e.g., "user.role", "resource.type")
        let parts: Vec<&str> = attribute.split('.').collect();

        if parts.len() < 2 {
            return None;
        }

        let scope = parts[0];
        let attr_path = &parts[1..];

        match scope {
            "subject" | "user" => self.get_nested_value(&context.subject, attr_path),
            "resource" => self.get_nested_value(&context.resource, attr_path),
            "environment" | "env" => self.get_nested_value(&context.environment, attr_path),
            "action" => {
                if attr_path.len() == 1 && attr_path[0] == "name" {
                    Some(context.action.clone())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    /// Get nested value from attribute map
    fn get_nested_value(&self, attributes: &HashMap<String, String>, path: &[&str]) -> Option<String> {
        if path.is_empty() {
            return None;
        }

        let mut current = attributes.get(path[0])?;

        for &part in &path[1..] {
            // For nested structures, we'd need JSON parsing here
            // For now, assume flat structure with dotted keys
            let key = format!("{}.{}", current, part);
            current = attributes.get(&key)?;
        }

        Some(current.clone())
    }

    /// Check if resource matches any of the rule resources
    fn resource_matches(&self, rule_resources: &[String], context: &EvaluationContext) -> bool {
        // Simple string matching - could be enhanced with glob patterns
        for rule_resource in rule_resources {
            if self.resource_pattern_matches(rule_resource, &context.resource) {
                return true;
            }
        }
        false
    }

    /// Check if resource pattern matches (supports wildcards)
    fn resource_pattern_matches(&self, pattern: &str, resource_attrs: &HashMap<String, String>) -> bool {
        // Simple implementation - check if any resource attribute contains the pattern
        for value in resource_attrs.values() {
            if value.contains(pattern) {
                return true;
            }
        }
        false
    }

    /// Get all roles in hierarchy including parents
    fn get_role_hierarchy(&self, roles: &[Uuid]) -> Vec<Uuid> {
        let mut all_roles = roles.to_vec();
        let mut to_process = roles.to_vec();

        while let Some(role_id) = to_process.pop() {
            if let Some(parents) = self.engine.role_hierarchy.get(&role_id) {
                for parent in parents {
                    if !all_roles.contains(parent) {
                        all_roles.push(*parent);
                        to_process.push(*parent);
                    }
                }
            }
        }

        all_roles
    }

    /// Get policies for a role
    fn get_policies_for_role(&self, _role_id: &Uuid) -> Option<Vec<Uuid>> {
        // This would typically query a database or cache
        // For now, return None - policies are evaluated directly
        None
    }
}

/// Result of policy evaluation
#[derive(Debug, Clone, PartialEq)]
enum PolicyEvaluation {
    Allow,
    Deny,
    NotApplicable,
}

/// Result of rule evaluation
#[derive(Debug, Clone, PartialEq)]
enum RuleEvaluation {
    Match,
    NoMatch,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_basic_evaluation() {
        let engine = PolicyEngine::new();
        let evaluator = PolicyEvaluator::new(engine);

        let context = EvaluationContext {
            subject: {
                let mut map = HashMap::new();
                map.insert("role".to_string(), "admin".to_string());
                map
            },
            resource: {
                let mut map = HashMap::new();
                map.insert("type".to_string(), "secret".to_string());
                map
            },
            action: "read".to_string(),
            environment: HashMap::new(),
        };

        // Test with no policies - should deny
        let result = evaluator.evaluate(&context, &[]).unwrap();
        assert!(!result.allowed);
        assert_eq!(result.reason, "No applicable policies found");
    }
}