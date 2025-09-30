use crate::namespace::{Namespace, NamespaceId, NamespaceTree, NamespaceError};
use crate::policy::{Policy, PolicyRule, ResolvedPolicy};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors that can occur in policy inheritance operations
#[derive(Error, Debug)]
pub enum PolicyInheritanceError {
    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    #[error("Policy not found: {0}")]
    PolicyNotFound(String),

    #[error("Circular reference detected in namespace hierarchy")]
    CircularReference,

    #[error("Invalid policy rule: {0}")]
    InvalidPolicyRule(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

/// Policy inheritance engine for resolving policies across namespace hierarchy
pub struct PolicyInheritanceEngine {
    namespace_tree: Arc<NamespaceTree>,
}

/// Resolved policy with inheritance information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedPolicy {
    pub namespace_id: NamespaceId,
    pub policy: Policy,
    pub inherited_from: Vec<NamespaceId>,
    pub effective_rules: Vec<EffectivePolicyRule>,
}

/// Effective policy rule after inheritance resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectivePolicyRule {
    pub rule: PolicyRule,
    pub source_namespace: NamespaceId,
    pub inheritance_level: usize,
}

impl PolicyInheritanceEngine {
    pub fn new(namespace_tree: Arc<NamespaceTree>) -> Self {
        Self { namespace_tree }
    }

    /// Resolve all policies for a given namespace including inheritance
    pub async fn resolve_policies(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Vec<ResolvedPolicy>, PolicyInheritanceError> {
        let mut resolved_policies = Vec::new();

        // Get the full namespace hierarchy (root to leaf)
        let hierarchy = self.get_namespace_hierarchy(namespace_id).await?;

        // Resolve policies for each namespace in hierarchy
        for namespace in &hierarchy {
            let resolved_policy = self.resolve_namespace_policies(namespace).await?;
            resolved_policies.push(resolved_policy);
        }

        Ok(resolved_policies)
    }

    /// Resolve policies for a specific namespace
    async fn resolve_namespace_policies(
        &self,
        namespace: &Namespace,
    ) -> Result<ResolvedPolicy, PolicyInheritanceError> {
        let mut effective_rules = Vec::new();
        let mut inherited_from = Vec::new();

        // Get hierarchy for this namespace (excluding itself for inheritance calculation)
        let hierarchy = self.get_namespace_hierarchy(&namespace.id).await?;
        let namespace_index = hierarchy.iter()
            .position(|ns| ns.id == namespace.id)
            .unwrap_or(0);

        // Process policies from root to current namespace
        for (level, ancestor_namespace) in hierarchy.into_iter().enumerate() {
            for policy in &ancestor_namespace.policies {
                let policy_rules = self.resolve_policy_rules(policy, &ancestor_namespace.id, level).await?;
                effective_rules.extend(policy_rules);

                if ancestor_namespace.id != namespace.id {
                    inherited_from.push(ancestor_namespace.id);
                }
            }
        }

        // Remove duplicate rules (child policies override parent policies)
        effective_rules = self.deduplicate_rules(effective_rules);

        let resolved_policy = ResolvedPolicy {
            namespace_id: namespace.id,
            policy: Policy {
                id: namespace.id, // Use namespace ID as policy ID for simplicity
                name: format!("{}_resolved", namespace.path),
                description: format!("Resolved policies for namespace {}", namespace.path),
                rules: Vec::new(), // Rules are in effective_rules
                created_at: namespace.created_at,
                updated_at: namespace.updated_at,
            },
            inherited_from,
            effective_rules,
        };

        Ok(resolved_policy)
    }

    /// Resolve individual policy rules with inheritance context
    async fn resolve_policy_rules(
        &self,
        policy: &Policy,
        source_namespace_id: &NamespaceId,
        inheritance_level: usize,
    ) -> Result<Vec<EffectivePolicyRule>, PolicyInheritanceError> {
        let mut effective_rules = Vec::new();

        for rule in &policy.rules {
            // Validate rule
            self.validate_policy_rule(rule)?;

            let effective_rule = EffectivePolicyRule {
                rule: rule.clone(),
                source_namespace: *source_namespace_id,
                inheritance_level,
            };

            effective_rules.push(effective_rule);
        }

        Ok(effective_rules)
    }

    /// Remove duplicate rules, keeping the most specific (lowest inheritance level) ones
    fn deduplicate_rules(&self, rules: Vec<EffectivePolicyRule>) -> Vec<EffectivePolicyRule> {
        let mut rule_map: HashMap<String, EffectivePolicyRule> = HashMap::new();

        for rule in rules {
            let key = self.get_rule_key(&rule.rule);

            // Keep rule with lowest inheritance level (most specific)
            if let Some(existing_rule) = rule_map.get(&key) {
                if rule.inheritance_level < existing_rule.inheritance_level {
                    rule_map.insert(key.clone(), rule);
                }
            } else {
                rule_map.insert(key, rule);
            }
        }

        rule_map.into_values().collect()
    }

    /// Generate a unique key for a policy rule for deduplication
    fn get_rule_key(&self, rule: &PolicyRule) -> String {
        format!("{}:{}", rule.path, rule.capabilities.join(","))
    }

    /// Validate a policy rule for correctness
    fn validate_policy_rule(&self, rule: &PolicyRule) -> Result<(), PolicyInheritanceError> {
        // Validate path pattern
        if rule.path.is_empty() {
            return Err(PolicyInheritanceError::InvalidPolicyRule("Rule path cannot be empty".to_string()));
        }

        // Validate capabilities
        let valid_capabilities = ["read", "write", "delete", "list", "create", "update"];
        for capability in &rule.capabilities {
            if !valid_capabilities.contains(&capability.as_str()) {
                return Err(PolicyInheritanceError::InvalidPolicyRule(
                    format!("Invalid capability: {}", capability)
                ));
            }
        }

        // Validate conditions format if present
        if let Some(conditions) = &rule.conditions {
            for (key, value) in conditions {
                if key.is_empty() || value.is_empty() {
                    return Err(PolicyInheritanceError::InvalidPolicyRule(
                        "Condition keys and values cannot be empty".to_string()
                    ));
                }
            }
        }

        Ok(())
    }

    /// Get the complete namespace hierarchy for a given namespace
    async fn get_namespace_hierarchy(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<Vec<Namespace>, PolicyInheritanceError> {
        let mut hierarchy = Vec::new();
        let mut visited = HashSet::new();
        let mut current_id = Some(*namespace_id);

        while let Some(id) = current_id {
            if visited.contains(&id) {
                return Err(PolicyInheritanceError::CircularReference);
            }

            visited.insert(id);

            match self.namespace_tree.get_namespace(&id).await {
                Ok(Some(namespace)) => {
                    hierarchy.push(namespace.clone());
                    current_id = namespace.parent;
                }
                Ok(None) => {
                    return Err(PolicyInheritanceError::NamespaceNotFound(id.to_string()));
                }
                Err(e) => {
                    return Err(PolicyInheritanceError::NamespaceNotFound(format!("Error: {}", e)));
                }
            }
        }

        hierarchy.reverse(); // Root first
        Ok(hierarchy)
    }

    /// Check if a user has specific capabilities on a path within a namespace
    pub async fn check_capabilities(
        &self,
        namespace_id: &NamespaceId,
        user_id: &str,
        path: &str,
        required_capabilities: &[&str],
    ) -> Result<bool, PolicyInheritanceError> {
        let resolved_policies = self.resolve_policies(namespace_id).await?;

        for policy in resolved_policies {
            if self.evaluate_capabilities(&policy, user_id, path, required_capabilities)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Evaluate capabilities against a resolved policy
    fn evaluate_capabilities(
        &self,
        policy: &ResolvedPolicy,
        user_id: &str,
        path: &str,
        required_capabilities: &[&str],
    ) -> Result<bool, PolicyInheritanceError> {
        for rule in &policy.effective_rules {
            if self.path_matches(&rule.rule.path, path) {
                // Check if user has all required capabilities
                let has_all_capabilities = required_capabilities.iter()
                    .all(|cap| rule.rule.capabilities.contains(&cap.to_string()));

                if has_all_capabilities {
                    // TODO: Evaluate conditions if present
                    // For now, assume no conditions means always allowed
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    /// Check if a path pattern matches a requested path
    fn path_matches(&self, pattern: &str, path: &str) -> bool {
        // Simple glob matching implementation
        // TODO: Implement proper glob pattern matching

        if pattern == "*" {
            return true;
        }

        if pattern == path {
            return true;
        }

        // Handle prefix matching (e.g., "secret/*" matches "secret/database")
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len() - 2];
            return path.starts_with(prefix);
        }

        // Handle suffix matching (e.g., "*/database" matches "secret/database")
        if pattern.starts_with("*/") {
            let suffix = &pattern[2..];
            return path.ends_with(suffix);
        }

        false
    }

    /// Get all policies that apply to a specific path across the namespace hierarchy
    pub async fn get_applicable_policies(
        &self,
        namespace_id: &NamespaceId,
        path: &str,
    ) -> Result<Vec<ResolvedPolicy>, PolicyInheritanceError> {
        let resolved_policies = self.resolve_policies(namespace_id).await?;

        // Filter policies that have rules matching the path
        let applicable_policies: Vec<ResolvedPolicy> = resolved_policies.into_iter()
            .filter(|policy| {
                policy.effective_rules.iter().any(|rule| self.path_matches(&rule.rule.path, path))
            })
            .collect();

        Ok(applicable_policies)
    }

    /// Create a policy inheritance report for debugging
    pub async fn create_inheritance_report(
        &self,
        namespace_id: &NamespaceId,
    ) -> Result<PolicyInheritanceReport, PolicyInheritanceError> {
        let resolved_policies = self.resolve_policies(namespace_id).await?;
        let hierarchy = self.get_namespace_hierarchy(namespace_id).await?;

        Ok(PolicyInheritanceReport {
            namespace_id: *namespace_id,
            hierarchy: hierarchy.iter().map(|ns| ns.path.clone()).collect(),
            resolved_policies,
        })
    }
}

/// Report showing policy inheritance for debugging
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyInheritanceReport {
    pub namespace_id: NamespaceId,
    pub hierarchy: Vec<String>,
    pub resolved_policies: Vec<ResolvedPolicy>,
}

impl Default for PolicyInheritanceEngine {
    fn default() -> Self {
        Self::new(Arc::new(NamespaceTree::new()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::namespace::{NamespaceTree, Namespace};
    use chrono::Utc;
    use std::sync::Arc;

    async fn create_test_namespace_tree() -> (Arc<NamespaceTree>, NamespaceId, NamespaceId) {
        let tree = Arc::new(NamespaceTree::new());

        // Create root namespace
        let root_id = tree.create_namespace(
            "org".to_string(),
            "Organization".to_string(),
            "Root organization".to_string(),
            None,
        ).await.unwrap();

        // Create child namespace
        let child_id = tree.create_namespace(
            "org/team".to_string(),
            "Team".to_string(),
            "Development team".to_string(),
            Some(root_id),
        ).await.unwrap();

        (tree, root_id, child_id)
    }

    #[tokio::test]
    async fn test_policy_inheritance_basic() {
        let (tree, root_id, child_id) = create_test_namespace_tree();
        let engine = PolicyInheritanceEngine::new(tree);

        // Test policy resolution
        let policies = engine.resolve_policies(&child_id).await.unwrap();
        assert_eq!(policies.len(), 2); // Root + child namespace

        // Root should be first
        assert_eq!(policies[0].namespace_id, root_id);
        assert_eq!(policies[1].namespace_id, child_id);
    }

    #[tokio::test]
    async fn test_path_matching() {
        let engine = PolicyInheritanceEngine::new(Arc::new(NamespaceTree::new()));

        // Test exact match
        assert!(engine.path_matches("secret", "secret"));
        assert!(!engine.path_matches("secret", "other"));

        // Test wildcard match
        assert!(engine.path_matches("*", "secret"));
        assert!(engine.path_matches("*", "any/path"));

        // Test prefix match
        assert!(engine.path_matches("secret/*", "secret/database"));
        assert!(engine.path_matches("secret/*", "secret/api"));
        assert!(!engine.path_matches("secret/*", "other/database"));
    }

    #[tokio::test]
    async fn test_policy_rule_validation() {
        let engine = PolicyInheritanceEngine::new(Arc::new(NamespaceTree::new()));

        // Valid rule
        let valid_rule = PolicyRule {
            path: "secret/*".to_string(),
            capabilities: vec!["read".to_string(), "write".to_string()],
            conditions: None,
        };
        assert!(engine.validate_policy_rule(&valid_rule).is_ok());

        // Invalid capability
        let invalid_rule = PolicyRule {
            path: "secret/*".to_string(),
            capabilities: vec!["invalid_cap".to_string()],
            conditions: None,
        };
        assert!(engine.validate_policy_rule(&invalid_rule).is_err());
    }
}
