//! Secret Governance Engine
//!
//! Provides comprehensive governance with ownership policies, multi-stage approval
//! workflows, compliance tracking, policy exceptions, and governance analytics.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("Policy not found: {0}")]
    PolicyNotFound(String),
    #[error("Workflow not found: {0}")]
    WorkflowNotFound(String),
    #[error("Approval required: {0}")]
    ApprovalRequired(String),
    #[error("Policy violation: {0}")]
    PolicyViolation(String),
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

pub type Result<T> = std::result::Result<T, GovernanceError>;

/// Governance policy type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PolicyType {
    Ownership,
    Approval,
    Review,
    Retention,
    AccessControl,
}

/// Enforcement level
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EnforcementLevel {
    Advisory,
    Warning,
    Blocking,
}

/// Governance policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernancePolicy {
    pub policy_id: String,
    pub name: String,
    pub policy_type: PolicyType,
    pub enforcement_level: EnforcementLevel,
    pub conditions: Vec<PolicyCondition>,
    pub actions: Vec<String>,
    pub enabled: bool,
}

/// Policy condition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: String,
    pub value: String,
}

/// Approval workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalWorkflow {
    pub workflow_id: String,
    pub name: String,
    pub stages: Vec<ApprovalStage>,
    pub current_stage: usize,
    pub status: WorkflowStatus,
    pub created_at: DateTime<Utc>,
}

/// Approval stage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalStage {
    pub stage_id: String,
    pub name: String,
    pub approvers: Vec<String>,
    pub required_approvals: usize,
    pub current_approvals: Vec<Approval>,
    pub timeout: Option<Duration>,
}

/// Approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    pub approver: String,
    pub decision: ApprovalDecision,
    pub comment: Option<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalDecision {
    Approved,
    Rejected,
    Pending,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowStatus {
    Pending,
    InProgress,
    Approved,
    Rejected,
    Cancelled,
}

/// Policy exception
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyException {
    pub exception_id: String,
    pub policy_id: String,
    pub resource_id: String,
    pub reason: String,
    pub granted_by: String,
    pub granted_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Governance violation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceViolation {
    pub violation_id: String,
    pub policy_id: String,
    pub resource_id: String,
    pub violation_type: String,
    pub detected_at: DateTime<Utc>,
    pub resolved: bool,
    pub resolution: Option<String>,
}

/// Governance analytics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceAnalytics {
    pub total_policies: usize,
    pub active_policies: usize,
    pub total_violations: usize,
    pub resolved_violations: usize,
    pub pending_approvals: usize,
    pub approval_rate: f64,
}

/// Secret Governance Engine
pub struct GovernanceEngine {
    policies: Arc<RwLock<HashMap<String, GovernancePolicy>>>,
    workflows: Arc<RwLock<HashMap<String, ApprovalWorkflow>>>,
    exceptions: Arc<RwLock<HashMap<String, PolicyException>>>,
    violations: Arc<RwLock<HashMap<String, GovernanceViolation>>>,
}

impl GovernanceEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            workflows: Arc::new(RwLock::new(HashMap::new())),
            exceptions: Arc::new(RwLock::new(HashMap::new())),
            violations: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create policy
    pub async fn create_policy(&self, policy: GovernancePolicy) -> Result<String> {
        let mut policies = self.policies.write().await;
        let policy_id = policy.policy_id.clone();
        policies.insert(policy_id.clone(), policy);
        Ok(policy_id)
    }

    /// Check compliance
    pub async fn check_compliance(&self, resource_id: &str, context: &HashMap<String, String>) -> Result<()> {
        let policies = self.policies.read().await;
        let exceptions = self.exceptions.read().await;

        for policy in policies.values() {
            if !policy.enabled {
                continue;
            }

            // Check if exception exists
            let has_exception = exceptions.values().any(|e| {
                e.resource_id == resource_id
                    && e.policy_id == policy.policy_id
                    && !e.revoked
                    && Utc::now() < e.expires_at
            });

            if has_exception {
                continue;
            }

            // Check policy conditions
            let mut all_conditions_met = true;
            for condition in &policy.conditions {
                if let Some(value) = context.get(&condition.field) {
                    let condition_met = match condition.operator.as_str() {
                        "==" => value == &condition.value,
                        "!=" => value != &condition.value,
                        "contains" => value.contains(&condition.value),
                        _ => false,
                    };

                    if !condition_met {
                        all_conditions_met = false;
                        break;
                    }
                }
            }

            if all_conditions_met {
                match policy.enforcement_level {
                    EnforcementLevel::Blocking => {
                        self.record_violation(resource_id, &policy.policy_id).await?;
                        return Err(GovernanceError::PolicyViolation(policy.name.clone()));
                    }
                    EnforcementLevel::Warning => {
                        self.record_violation(resource_id, &policy.policy_id).await?;
                    }
                    EnforcementLevel::Advisory => {
                        // Just log
                    }
                }
            }
        }

        Ok(())
    }

    async fn record_violation(&self, resource_id: &str, policy_id: &str) -> Result<()> {
        let mut violations = self.violations.write().await;
        
        let violation = GovernanceViolation {
            violation_id: Uuid::new_v4().to_string(),
            policy_id: policy_id.to_string(),
            resource_id: resource_id.to_string(),
            violation_type: "policy_violation".to_string(),
            detected_at: Utc::now(),
            resolved: false,
            resolution: None,
        };

        violations.insert(violation.violation_id.clone(), violation);
        Ok(())
    }

    /// Create approval workflow
    pub async fn create_approval_workflow(&self, workflow: ApprovalWorkflow) -> Result<String> {
        let mut workflows = self.workflows.write().await;
        let workflow_id = workflow.workflow_id.clone();
        workflows.insert(workflow_id.clone(), workflow);
        Ok(workflow_id)
    }

    /// Submit approval
    pub async fn submit_approval(&self, workflow_id: &str, approver: &str, decision: ApprovalDecision, comment: Option<String>) -> Result<()> {
        let mut workflows = self.workflows.write().await;
        
        let workflow = workflows
            .get_mut(workflow_id)
            .ok_or_else(|| GovernanceError::WorkflowNotFound(workflow_id.to_string()))?;

        if workflow.status != WorkflowStatus::Pending && workflow.status != WorkflowStatus::InProgress {
            return Err(GovernanceError::InvalidState("Workflow not pending approval".to_string()));
        }

        let current_stage = &mut workflow.stages[workflow.current_stage];
        
        // Check if approver is authorized
        if !current_stage.approvers.contains(&approver.to_string()) {
            return Err(GovernanceError::ApprovalRequired("Not an authorized approver".to_string()));
        }

        // Add approval
        let approval = Approval {
            approver: approver.to_string(),
            decision: decision.clone(),
            comment,
            timestamp: Utc::now(),
        };

        current_stage.current_approvals.push(approval);

        // Check if stage is complete
        let approvals_count = current_stage
            .current_approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Approved)
            .count();

        let rejections_count = current_stage
            .current_approvals
            .iter()
            .filter(|a| a.decision == ApprovalDecision::Rejected)
            .count();

        if rejections_count > 0 {
            workflow.status = WorkflowStatus::Rejected;
        } else if approvals_count >= current_stage.required_approvals {
            // Move to next stage
            workflow.current_stage += 1;
            
            if workflow.current_stage >= workflow.stages.len() {
                workflow.status = WorkflowStatus::Approved;
            } else {
                workflow.status = WorkflowStatus::InProgress;
            }
        }

        Ok(())
    }

    /// Grant exception
    pub async fn grant_exception(&self, exception: PolicyException) -> Result<String> {
        let mut exceptions = self.exceptions.write().await;
        let exception_id = exception.exception_id.clone();
        exceptions.insert(exception_id.clone(), exception);
        Ok(exception_id)
    }

    /// Revoke exception
    pub async fn revoke_exception(&self, exception_id: &str) -> Result<()> {
        let mut exceptions = self.exceptions.write().await;
        
        let exception = exceptions
            .get_mut(exception_id)
            .ok_or_else(|| GovernanceError::PolicyNotFound(exception_id.to_string()))?;

        exception.revoked = true;
        Ok(())
    }

    /// Get violations
    pub async fn get_violations(&self, resource_id: Option<&str>) -> Vec<GovernanceViolation> {
        let violations = self.violations.read().await;
        
        violations
            .values()
            .filter(|v| {
                if let Some(rid) = resource_id {
                    v.resource_id == rid
                } else {
                    true
                }
            })
            .cloned()
            .collect()
    }

    /// Resolve violation
    pub async fn resolve_violation(&self, violation_id: &str, resolution: String) -> Result<()> {
        let mut violations = self.violations.write().await;
        
        let violation = violations
            .get_mut(violation_id)
            .ok_or_else(|| GovernanceError::PolicyNotFound(violation_id.to_string()))?;

        violation.resolved = true;
        violation.resolution = Some(resolution);
        Ok(())
    }

    /// Get analytics
    pub async fn get_analytics(&self) -> GovernanceAnalytics {
        let policies = self.policies.read().await;
        let workflows = self.workflows.read().await;
        let violations = self.violations.read().await;

        let total_policies = policies.len();
        let active_policies = policies.values().filter(|p| p.enabled).count();

        let total_violations = violations.len();
        let resolved_violations = violations.values().filter(|v| v.resolved).count();

        let pending_approvals = workflows
            .values()
            .filter(|w| w.status == WorkflowStatus::Pending || w.status == WorkflowStatus::InProgress)
            .count();

        let approved = workflows.values().filter(|w| w.status == WorkflowStatus::Approved).count();
        let total_workflows = workflows.len();
        let approval_rate = if total_workflows > 0 {
            approved as f64 / total_workflows as f64
        } else {
            0.0
        };

        GovernanceAnalytics {
            total_policies,
            active_policies,
            total_violations,
            resolved_violations,
            pending_approvals,
            approval_rate,
        }
    }

    /// List policies
    pub async fn list_policies(&self) -> Vec<GovernancePolicy> {
        let policies = self.policies.read().await;
        policies.values().cloned().collect()
    }

    /// List workflows
    pub async fn list_workflows(&self) -> Vec<ApprovalWorkflow> {
        let workflows = self.workflows.read().await;
        workflows.values().cloned().collect()
    }
}

impl Default for GovernanceEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_policy() {
        let engine = GovernanceEngine::new();
        
        let policy = GovernancePolicy {
            policy_id: "pol1".to_string(),
            name: "Require Approval".to_string(),
            policy_type: PolicyType::Approval,
            enforcement_level: EnforcementLevel::Blocking,
            conditions: vec![],
            actions: vec!["require_approval".to_string()],
            enabled: true,
        };

        let policy_id = engine.create_policy(policy).await.unwrap();
        assert_eq!(policy_id, "pol1");
    }

    #[tokio::test]
    async fn test_check_compliance() {
        let engine = GovernanceEngine::new();
        
        let policy = GovernancePolicy {
            policy_id: "pol1".to_string(),
            name: "Environment Check".to_string(),
            policy_type: PolicyType::AccessControl,
            enforcement_level: EnforcementLevel::Blocking,
            conditions: vec![PolicyCondition {
                field: "environment".to_string(),
                operator: "==".to_string(),
                value: "production".to_string(),
            }],
            actions: vec![],
            enabled: true,
        };

        engine.create_policy(policy).await.unwrap();

        let mut context = HashMap::new();
        context.insert("environment".to_string(), "production".to_string());

        let result = engine.check_compliance("resource1", &context).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_approval_workflow() {
        let engine = GovernanceEngine::new();
        
        let workflow = ApprovalWorkflow {
            workflow_id: "wf1".to_string(),
            name: "Secret Approval".to_string(),
            stages: vec![ApprovalStage {
                stage_id: "stage1".to_string(),
                name: "Security Review".to_string(),
                approvers: vec!["alice".to_string(), "bob".to_string()],
                required_approvals: 1,
                current_approvals: vec![],
                timeout: None,
            }],
            current_stage: 0,
            status: WorkflowStatus::Pending,
            created_at: Utc::now(),
        };

        engine.create_approval_workflow(workflow).await.unwrap();

        engine.submit_approval("wf1", "alice", ApprovalDecision::Approved, None).await.unwrap();

        let workflows = engine.list_workflows().await;
        assert_eq!(workflows[0].status, WorkflowStatus::Approved);
    }

    #[tokio::test]
    async fn test_grant_exception() {
        let engine = GovernanceEngine::new();
        
        let exception = PolicyException {
            exception_id: "exc1".to_string(),
            policy_id: "pol1".to_string(),
            resource_id: "res1".to_string(),
            reason: "Emergency access".to_string(),
            granted_by: "admin".to_string(),
            granted_at: Utc::now(),
            expires_at: Utc::now() + Duration::hours(24),
            revoked: false,
        };

        let exc_id = engine.grant_exception(exception).await.unwrap();
        assert_eq!(exc_id, "exc1");
    }

    #[tokio::test]
    async fn test_resolve_violation() {
        let engine = GovernanceEngine::new();
        
        let policy = GovernancePolicy {
            policy_id: "pol1".to_string(),
            name: "Test Policy".to_string(),
            policy_type: PolicyType::Ownership,
            enforcement_level: EnforcementLevel::Warning,
            conditions: vec![PolicyCondition {
                field: "owner".to_string(),
                operator: "==".to_string(),
                value: "none".to_string(),
            }],
            actions: vec![],
            enabled: true,
        };

        engine.create_policy(policy).await.unwrap();

        let mut context = HashMap::new();
        context.insert("owner".to_string(), "none".to_string());

        let _ = engine.check_compliance("res1", &context).await;

        let violations = engine.get_violations(Some("res1")).await;
        assert_eq!(violations.len(), 1);

        let violation_id = violations[0].violation_id.clone();
        engine.resolve_violation(&violation_id, "Owner assigned".to_string()).await.unwrap();

        let violations = engine.get_violations(Some("res1")).await;
        assert!(violations[0].resolved);
    }

    #[tokio::test]
    async fn test_get_analytics() {
        let engine = GovernanceEngine::new();
        
        let policy = GovernancePolicy {
            policy_id: "pol1".to_string(),
            name: "Test".to_string(),
            policy_type: PolicyType::Approval,
            enforcement_level: EnforcementLevel::Advisory,
            conditions: vec![],
            actions: vec![],
            enabled: true,
        };

        engine.create_policy(policy).await.unwrap();

        let analytics = engine.get_analytics().await;
        assert_eq!(analytics.total_policies, 1);
        assert_eq!(analytics.active_policies, 1);
    }
}
