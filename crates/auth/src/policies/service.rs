//! Policy service layer

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::engine::PolicyEngine;
use super::error::{PolicyResult, ValidationErrors};
use super::evaluator::PolicyEvaluator;
use super::model::{EvaluationContext, EvaluationResult, Policy, Role};
use secreton_domain::SecretonError;
use secreton_domain::ServiceHealth;

/// Policy service for managing policies and roles
pub struct PolicyService {
    /// Policy engine
    engine: Arc<RwLock<PolicyEngine>>,
    /// Policy storage (in-memory for now)
    policies: Arc<RwLock<HashMap<Uuid, Policy>>>,
    /// Role storage
    roles: Arc<RwLock<HashMap<Uuid, Role>>>,
    /// Service start time
    start_time: std::sync::Mutex<Option<std::time::Instant>>,
    /// Service name
    service_name: String,
    /// Service version
    service_version: String,
}

impl PolicyService {
    /// Create a new policy service
    pub fn new() -> Self {
        let engine = Arc::new(RwLock::new(PolicyEngine::new()));

        Self {
            engine,
            policies: Arc::new(RwLock::new(HashMap::new())),
            roles: Arc::new(RwLock::new(HashMap::new())),
            start_time: std::sync::Mutex::new(None),
            service_name: "PolicyService".to_string(),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// Create a new policy
    pub async fn create_policy(&self, mut policy: Policy) -> PolicyResult<Policy> {
        // Validate policy
        self.validate_policy(&policy).await?;

        // Set timestamps
        let now = Utc::now();
        policy.created_at = now;
        policy.updated_at = now;
        policy.id = Uuid::new_v4();

        // Store policy
        {
            let mut policies = self.policies.write().await;
            policies.insert(policy.id, policy.clone());
        }

        // Add to engine
        {
            let mut engine = self.engine.write().await;
            engine.add_policy(&policy)?;
        }

        Ok(policy)
    }

    /// Get policy by ID
    pub async fn get_policy(&self, policy_id: &Uuid) -> PolicyResult<Policy> {
        let policies = self.policies.read().await;
        policies
            .get(policy_id)
            .cloned()
            .ok_or_else(|| SecretonError::PolicyNotFound {
                policy_id: policy_id.to_string(),
            })
    }

    /// Update policy
    pub async fn update_policy(&self, policy_id: &Uuid, updates: Policy) -> PolicyResult<Policy> {
        let mut policies = self.policies.write().await;

        let existing =
            policies
                .get_mut(policy_id)
                .ok_or_else(|| SecretonError::PolicyNotFound {
                    policy_id: policy_id.to_string(),
                })?;

        // Validate updates
        self.validate_policy(&updates).await?;

        // Update fields
        existing.name = updates.name;
        existing.policy_type = updates.policy_type;
        existing.effect = updates.effect;
        existing.rules = updates.rules;
        existing.metadata = updates.metadata;
        existing.updated_at = Utc::now();
        existing.enabled = updates.enabled;

        let updated_policy = existing.clone();

        // Update engine
        {
            let mut engine = self.engine.write().await;
            engine.add_policy(&updated_policy)?;
        }

        Ok(updated_policy)
    }

    /// Delete policy
    pub async fn delete_policy(&self, policy_id: &Uuid) -> PolicyResult<()> {
        // Remove from storage
        {
            let mut policies = self.policies.write().await;
            policies.remove(policy_id);
        }

        // Remove from engine
        {
            let mut engine = self.engine.write().await;
            engine.remove_policy(policy_id)?;
        }

        Ok(())
    }

    /// List all policies
    pub async fn list_policies(&self) -> Vec<Policy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// Get role ID by name
    pub async fn get_role_id_by_name(&self, name: &str) -> Option<Uuid> {
        let roles = self.roles.read().await;
        roles.values().find(|r| r.name == name).map(|r| r.id)
    }

    /// Get policy ID by name
    pub async fn get_policy_id_by_name(&self, name: &str) -> Option<Uuid> {
        let policies = self.policies.read().await;
        policies.values().find(|p| p.name == name).map(|p| p.id)
    }

    /// Create a new role
    pub async fn create_role(&self, mut role: Role) -> PolicyResult<Role> {
        // Validate role
        self.validate_role(&role).await?;

        // Set timestamps
        let now = Utc::now();
        role.created_at = now;
        role.updated_at = now;
        role.id = Uuid::new_v4();

        // Check for circular dependencies
        self.check_circular_dependencies(&role).await?;

        // Store role
        {
            let mut roles = self.roles.write().await;
            roles.insert(role.id, role.clone());
        }

        // Update role hierarchy in engine
        if let Some(parent_id) = role.parent_role {
            let mut engine = self.engine.write().await;
            engine.add_role_relationship(role.id, parent_id);
        }

        Ok(role)
    }

    /// Get role by ID
    pub async fn get_role(&self, role_id: &Uuid) -> PolicyResult<Role> {
        let roles = self.roles.read().await;
        roles
            .get(role_id)
            .cloned()
            .ok_or_else(|| SecretonError::RoleNotFound {
                role_id: role_id.to_string(),
            })
    }

    /// Update role
    pub async fn update_role(&self, role_id: &Uuid, mut updates: Role) -> PolicyResult<Role> {
        let mut roles = self.roles.write().await;

        let existing = roles
            .get_mut(role_id)
            .ok_or_else(|| SecretonError::RoleNotFound {
                role_id: role_id.to_string(),
            })?;

        // Validate updates
        self.validate_role(&updates).await?;

        // Check for circular dependencies
        updates.id = *role_id; // Ensure ID consistency
        self.check_circular_dependencies(&updates).await?;

        // Update fields
        existing.name = updates.name;
        existing.description = updates.description;
        existing.parent_role = updates.parent_role;
        existing.policies = updates.policies;
        existing.metadata = updates.metadata;
        existing.updated_at = Utc::now();

        let updated_role = existing.clone();

        // Update role hierarchy in engine
        {
            let mut engine = self.engine.write().await;
            // Remove old relationship
            if let Some(_old_parent) = existing.parent_role {
                // Note: Engine doesn't have remove_relationship, this is a simplification
            }
            // Add new relationship
            if let Some(new_parent) = updated_role.parent_role {
                engine.add_role_relationship(updated_role.id, new_parent);
            }
        }

        Ok(updated_role)
    }

    /// Delete role
    pub async fn delete_role(&self, role_id: &Uuid) -> PolicyResult<()> {
        let mut roles = self.roles.write().await;
        roles.remove(role_id);
        Ok(())
    }

    /// List all roles
    pub async fn list_roles(&self) -> Vec<Role> {
        let roles = self.roles.read().await;
        roles.values().cloned().collect()
    }

    /// Assign policy to role
    pub async fn assign_policy_to_role(
        &self,
        role_id: &Uuid,
        policy_id: &Uuid,
    ) -> PolicyResult<()> {
        let mut roles = self.roles.write().await;
        let role = roles
            .get_mut(role_id)
            .ok_or_else(|| SecretonError::RoleNotFound {
                role_id: role_id.to_string(),
            })?;

        // Check if policy exists
        {
            let policies = self.policies.read().await;
            if !policies.contains_key(policy_id) {
                return Err(SecretonError::PolicyNotFound {
                    policy_id: policy_id.to_string(),
                });
            }
        }

        // Add policy if not already assigned
        if !role.policies.contains(policy_id) {
            role.policies.push(*policy_id);
            role.updated_at = Utc::now();
        }

        Ok(())
    }

    /// Remove policy from role
    pub async fn remove_policy_from_role(
        &self,
        role_id: &Uuid,
        policy_id: &Uuid,
    ) -> PolicyResult<()> {
        let mut roles = self.roles.write().await;
        let role = roles
            .get_mut(role_id)
            .ok_or_else(|| SecretonError::RoleNotFound {
                role_id: role_id.to_string(),
            })?;

        role.policies.retain(|&id| id != *policy_id);
        role.updated_at = Utc::now();

        Ok(())
    }

    /// Evaluate access request
    pub async fn evaluate_access(
        &self,
        context: &EvaluationContext,
        subject_roles: &[Uuid],
        subject_policies: &[Uuid],
    ) -> PolicyResult<EvaluationResult> {
        let engine_guard = self.engine.read().await;
        let roles_guard = self.roles.read().await;

        let evaluator = PolicyEvaluator::new(&engine_guard, &roles_guard);
        evaluator.evaluate(context, subject_roles, subject_policies)
    }

    /// Parse policy from string
    pub async fn parse_policy_from_string(&self, policy_text: &str) -> PolicyResult<Policy> {
        let engine = self.engine.read().await;
        engine.parse_policy(policy_text)
    }

    /// Validate policy
    async fn validate_policy(&self, policy: &Policy) -> PolicyResult<()> {
        let mut errors = ValidationErrors::new();

        if policy.name.trim().is_empty() {
            errors.add("name", "Policy name cannot be empty");
        }

        if policy.rules.is_empty() {
            errors.add("rules", "Policy must have at least one rule");
        }

        // Validate each rule
        for (i, rule) in policy.rules.iter().enumerate() {
            if rule.actions.is_empty() && rule.resources.is_empty() {
                errors.add(
                    format!("rules[{}]", i),
                    "Rule must have actions or resources",
                );
            }

            for (j, condition) in rule.conditions.iter().enumerate() {
                if condition.attribute.trim().is_empty() {
                    errors.add(
                        format!("rules[{}].conditions[{}].attribute", i, j),
                        "Attribute cannot be empty",
                    );
                }

                if condition.values.is_empty() {
                    errors.add(
                        format!("rules[{}].conditions[{}].values", i, j),
                        "Condition must have at least one value",
                    );
                }
            }
        }

        if !errors.is_empty() {
            return Err(SecretonError::InvalidPolicySyntax {
                details: errors.to_string(),
            });
        }

        Ok(())
    }

    /// Validate role
    async fn validate_role(&self, role: &Role) -> PolicyResult<()> {
        let mut errors = ValidationErrors::new();

        if role.name.trim().is_empty() {
            errors.add("name", "Role name cannot be empty");
        }

        // Check for duplicate role name
        {
            let roles = self.roles.read().await;
            if roles
                .values()
                .any(|r| r.name == role.name && r.id != role.id)
            {
                errors.add("name", "Role name already exists");
            }
        }

        if !errors.is_empty() {
            return Err(SecretonError::InvalidPolicySyntax {
                details: errors.to_string(),
            });
        }

        Ok(())
    }

    /// Check for circular dependencies in role hierarchy
    async fn check_circular_dependencies(&self, role: &Role) -> PolicyResult<()> {
        if let Some(parent_id) = role.parent_role {
            let mut visited = std::collections::HashSet::new();
            let mut current = parent_id;

            while let Some(parent_role) = {
                let roles = self.roles.read().await;
                roles.get(&current).and_then(|r| r.parent_role)
            } {
                if visited.contains(&parent_role) {
                    return Err(SecretonError::CircularRoleDependency {
                        role_chain: vec![
                            role.id.to_string(),
                            current.to_string(),
                            parent_role.to_string(),
                        ],
                    });
                }

                if parent_role == role.id {
                    return Err(SecretonError::CircularRoleDependency {
                        role_chain: vec![role.id.to_string()],
                    });
                }

                visited.insert(current);
                current = parent_role;
            }
        }

        Ok(())
    }
}

impl Default for PolicyService {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyService {
    pub async fn start(&self) -> Result<(), SecretonError> {
        let mut start_time = self.start_time.lock().expect("start_time mutex poisoned");
        *start_time = Some(std::time::Instant::now());
        tracing::info!("PolicyService started");
        Ok(())
    }

    pub async fn stop(&self) -> Result<(), SecretonError> {
        tracing::info!("PolicyService stopped");
        Ok(())
    }

    pub async fn health(&self) -> Result<ServiceHealth, SecretonError> {
        // Basic health check - check if storage is accessible
        let policies_result = self.policies.try_read();
        let roles_result = self.roles.try_read();

        match (policies_result, roles_result) {
            (Ok(_), Ok(_)) => Ok(ServiceHealth::Healthy),
            _ => Ok(ServiceHealth::Unhealthy(
                "Storage lock contention".to_string(),
            )),
        }
    }

    pub fn name(&self) -> &str {
        &self.service_name
    }

    pub fn version(&self) -> &str {
        &self.service_version
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.start_time
            .lock()
            .unwrap()
            .map(|start| start.elapsed().as_secs())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::{PolicyEffect, PolicyType};
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_create_policy() {
        let service = PolicyService::new();

        let policy = Policy {
            id: Uuid::new_v4(),
            name: "test_policy".to_string(),
            policy_type: PolicyType::ABAC,
            effect: PolicyEffect::Allow,
            rules: vec![], // Empty rules should fail validation
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            enabled: true,
        };

        let result = service.create_policy(policy).await;
        assert!(result.is_err()); // Should fail due to empty rules
    }

    #[tokio::test]
    async fn test_create_role() {
        let service = PolicyService::new();

        let role = Role {
            id: Uuid::new_v4(),
            name: "test_role".to_string(),
            description: Some("Test role".to_string()),
            parent_role: None,
            policies: vec![],
            metadata: HashMap::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let result = service.create_role(role).await;
        assert!(result.is_ok());

        let created_role = result.unwrap();
        assert_eq!(created_role.name, "test_role");
    }
}
