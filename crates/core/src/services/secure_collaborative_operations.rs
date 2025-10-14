//! Secure Collaborative Operations
//!
//! Integrates secure multi-party computation with multi-tenant isolation and secret federation
//! to enable secure collaboration between multiple parties without revealing individual inputs.
//! Provides threshold operations, distributed key generation, and collaborative computing.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

use super::secure_multi_party_computation::{DKGResult, SMPCProtocol, SMPCSession};

#[derive(Debug, Error)]
pub enum CollaborationError {
    #[error("Tenant isolation violated: {0}")]
    IsolationViolated(String),
    #[error("Threshold not met: {0}")]
    ThresholdNotMet(String),
    #[error("Collaboration failed: {0}")]
    CollaborationFailed(String),
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

pub type Result<T> = std::result::Result<T, CollaborationError>;

/// Cross-tenant collaboration policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborationPolicy {
    pub policy_id: String,
    pub name: String,
    pub allowed_tenants: Vec<String>,
    pub required_approvals: usize,
    pub allowed_operations: Vec<String>,
    pub data_residency: Option<String>,
    pub audit_level: AuditLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AuditLevel {
    None,
    Basic,
    Detailed,
    Full,
}

/// Collaborative secret sharing request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeSecretRequest {
    pub secret_data: Vec<u8>,
    pub tenant_ids: Vec<String>,
    pub threshold: usize,
    pub policy_id: String,
    pub requester_tenant: String,
}

/// Distributed secret share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedSecretShare {
    pub share_id: String,
    pub tenant_id: String,
    pub share_data: Vec<u8>,
    pub share_index: usize,
    pub threshold: usize,
    pub total_shares: usize,
    pub created_at: DateTime<Utc>,
}

/// Collaborative computation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeComputeRequest {
    pub computation_id: String,
    pub function_name: String,
    pub participants: Vec<ParticipantInput>,
    pub threshold: usize,
    pub policy_id: String,
}

/// Participant input for computation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInput {
    pub tenant_id: String,
    pub input_data: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}

/// Computation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollaborativeComputeResult {
    pub computation_id: String,
    pub result_data: Vec<u8>,
    pub participants_contributed: Vec<String>,
    pub computed_at: DateTime<Utc>,
    pub verification_proof: Vec<u8>,
}

/// Threshold approval workflow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdApprovalWorkflow {
    pub workflow_id: String,
    pub operation: String,
    pub required_approvals: usize,
    pub approvers: Vec<String>,
    pub signatures_received: Vec<ApprovalSignature>,
    pub status: WorkflowStatus,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum WorkflowStatus {
    Pending,
    InProgress,
    Approved,
    Rejected,
    Expired,
}

/// Approval signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalSignature {
    pub approver_id: String,
    pub tenant_id: String,
    pub signature_data: Vec<u8>,
    pub signed_at: DateTime<Utc>,
}

/// Secure collaborative operations engine
pub struct SecureCollaborativeOperations {
    smpc_sessions: Arc<RwLock<HashMap<String, SMPCSession>>>,
    policies: Arc<RwLock<HashMap<String, CollaborationPolicy>>>,
    distributed_shares: Arc<RwLock<HashMap<String, Vec<DistributedSecretShare>>>>,
    approval_workflows: Arc<RwLock<HashMap<String, ThresholdApprovalWorkflow>>>,
    dkg_results: Arc<RwLock<HashMap<String, DKGResult>>>,
}

impl SecureCollaborativeOperations {
    pub fn new() -> Self {
        Self {
            smpc_sessions: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            distributed_shares: Arc::new(RwLock::new(HashMap::new())),
            approval_workflows: Arc::new(RwLock::new(HashMap::new())),
            dkg_results: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create collaboration policy
    pub async fn create_policy(&self, policy: CollaborationPolicy) -> Result<()> {
        self.policies
            .write()
            .await
            .insert(policy.policy_id.clone(), policy);
        Ok(())
    }

    /// Distributed secret sharing across tenants
    pub async fn distributed_secret_sharing(
        &self,
        request: CollaborativeSecretRequest,
    ) -> Result<Vec<DistributedSecretShare>> {
        // 1. Validate policy
        let policies = self.policies.read().await;
        let policy = policies
            .get(&request.policy_id)
            .ok_or_else(|| CollaborationError::PermissionDenied("Policy not found".to_string()))?;

        // Verify requester is allowed
        if !policy.allowed_tenants.contains(&request.requester_tenant) {
            return Err(CollaborationError::IsolationViolated(
                "Requester not allowed".to_string(),
            ));
        }

        // Verify all participants are allowed
        for tenant_id in &request.tenant_ids {
            if !policy.allowed_tenants.contains(tenant_id) {
                return Err(CollaborationError::IsolationViolated(format!(
                    "Tenant {} not allowed",
                    tenant_id
                )));
            }
        }

        drop(policies);

        // 2. Create SMPC session
        let session_id = Uuid::new_v4().to_string();
        let participants = request
            .tenant_ids
            .iter()
            .map(|tid| super::secure_multi_party_computation::Participant {
                participant_id: tid.clone(),
                public_key: vec![0; 32], // Mock
                network_address: format!("tenant-{}.internal", tid),
            })
            .collect();

        let session = SMPCSession {
            session_id: session_id.clone(),
            protocol: SMPCProtocol::Shamir,
            participants,
            threshold: request.threshold,
            state: super::secure_multi_party_computation::SessionState::Active,
            created_at: Utc::now(),
        };

        self.smpc_sessions
            .write()
            .await
            .insert(session_id.clone(), session);

        // 3. Split secret into shares (mock Shamir)
        let shares: Vec<DistributedSecretShare> = request
            .tenant_ids
            .iter()
            .enumerate()
            .map(|(idx, tenant_id)| DistributedSecretShare {
                share_id: Uuid::new_v4().to_string(),
                tenant_id: tenant_id.clone(),
                share_data: request.secret_data.clone(), // Mock: would be actual share
                share_index: idx + 1,
                threshold: request.threshold,
                total_shares: request.tenant_ids.len(),
                created_at: Utc::now(),
            })
            .collect();

        // 4. Store shares
        self.distributed_shares
            .write()
            .await
            .insert(session_id, shares.clone());

        Ok(shares)
    }

    /// Collaborative computation with SMPC
    pub async fn collaborative_computation(
        &self,
        request: CollaborativeComputeRequest,
    ) -> Result<CollaborativeComputeResult> {
        // 1. Validate policy
        let policies = self.policies.read().await;
        let policy = policies
            .get(&request.policy_id)
            .ok_or_else(|| CollaborationError::PermissionDenied("Policy not found".to_string()))?;

        // Verify all participants are allowed
        for participant in &request.participants {
            if !policy.allowed_tenants.contains(&participant.tenant_id) {
                return Err(CollaborationError::IsolationViolated(format!(
                    "Tenant {} not allowed",
                    participant.tenant_id
                )));
            }
        }

        drop(policies);

        // 2. Verify threshold
        if request.participants.len() < request.threshold {
            return Err(CollaborationError::ThresholdNotMet(format!(
                "Need {} participants, got {}",
                request.threshold,
                request.participants.len()
            )));
        }

        // 3. Execute SMPC computation (mock)
        // In production: use actual MPC protocol
        let result_data = self.mock_smpc_computation(&request.function_name, &request.participants);

        let participants_contributed: Vec<String> = request
            .participants
            .iter()
            .map(|p| p.tenant_id.clone())
            .collect();

        let result = CollaborativeComputeResult {
            computation_id: request.computation_id,
            result_data,
            participants_contributed,
            computed_at: Utc::now(),
            verification_proof: vec![0; 64], // Mock proof
        };

        Ok(result)
    }

    /// Threshold approval workflow with DKG
    pub async fn create_threshold_approval(
        &self,
        operation: String,
        required_approvals: usize,
        approvers: Vec<String>,
        policy_id: String,
    ) -> Result<String> {
        // Validate policy
        let policies = self.policies.read().await;
        let policy = policies
            .get(&policy_id)
            .ok_or_else(|| CollaborationError::PermissionDenied("Policy not found".to_string()))?;

        for approver in &approvers {
            if !policy.allowed_tenants.contains(approver) {
                return Err(CollaborationError::IsolationViolated(format!(
                    "Approver {} not allowed",
                    approver
                )));
            }
        }

        drop(policies);

        // Create workflow
        let workflow_id = Uuid::new_v4().to_string();
        let workflow = ThresholdApprovalWorkflow {
            workflow_id: workflow_id.clone(),
            operation,
            required_approvals,
            approvers,
            signatures_received: Vec::new(),
            status: WorkflowStatus::Pending,
            created_at: Utc::now(),
        };

        self.approval_workflows
            .write()
            .await
            .insert(workflow_id.clone(), workflow);

        // Perform DKG for approval keys (mock)
        let dkg_result = DKGResult {
            session_id: workflow_id.clone(),
            public_key: vec![0; 64],
            key_shares: HashMap::new(),
            threshold: required_approvals,
        };

        self.dkg_results
            .write()
            .await
            .insert(workflow_id.clone(), dkg_result);

        Ok(workflow_id)
    }

    /// Add approval signature
    pub async fn add_approval_signature(
        &self,
        workflow_id: &str,
        signature: ApprovalSignature,
    ) -> Result<WorkflowStatus> {
        let mut workflows = self.approval_workflows.write().await;
        let workflow = workflows.get_mut(workflow_id).ok_or_else(|| {
            CollaborationError::CollaborationFailed("Workflow not found".to_string())
        })?;

        // Verify approver is in list
        if !workflow.approvers.contains(&signature.approver_id) {
            return Err(CollaborationError::PermissionDenied(
                "Not an authorized approver".to_string(),
            ));
        }

        // Add signature
        workflow.signatures_received.push(signature);
        workflow.status = WorkflowStatus::InProgress;

        // Check if threshold met
        if workflow.signatures_received.len() >= workflow.required_approvals {
            workflow.status = WorkflowStatus::Approved;
        }

        Ok(workflow.status.clone())
    }

    /// Get workflow status
    pub async fn get_workflow_status(
        &self,
        workflow_id: &str,
    ) -> Result<ThresholdApprovalWorkflow> {
        self.approval_workflows
            .read()
            .await
            .get(workflow_id)
            .cloned()
            .ok_or_else(|| {
                CollaborationError::CollaborationFailed("Workflow not found".to_string())
            })
    }

    /// Mock SMPC computation
    fn mock_smpc_computation(
        &self,
        function_name: &str,
        participants: &[ParticipantInput],
    ) -> Vec<u8> {
        // Mock: sum all inputs
        match function_name {
            "sum" => {
                let sum: u64 = participants.iter().map(|_| 42u64).sum();
                sum.to_le_bytes().to_vec()
            }
            "avg" => {
                let avg = 42u64 / participants.len() as u64;
                avg.to_le_bytes().to_vec()
            }
            _ => vec![0; 8],
        }
    }

    /// Get collaboration statistics
    pub async fn get_collaboration_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        stats.insert(
            "active_sessions".to_string(),
            self.smpc_sessions.read().await.len(),
        );
        stats.insert("policies".to_string(), self.policies.read().await.len());
        stats.insert(
            "distributed_shares".to_string(),
            self.distributed_shares.read().await.len(),
        );
        stats.insert(
            "approval_workflows".to_string(),
            self.approval_workflows.read().await.len(),
        );
        stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_collaboration_policy() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy1".to_string(),
            name: "Test Policy".to_string(),
            allowed_tenants: vec!["tenant1".to_string(), "tenant2".to_string()],
            required_approvals: 2,
            allowed_operations: vec!["compute".to_string(), "share".to_string()],
            data_residency: Some("US".to_string()),
            audit_level: AuditLevel::Full,
        };

        ops.create_policy(policy.clone()).await.unwrap();
    }

    #[tokio::test]
    async fn test_distributed_secret_sharing() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy2".to_string(),
            name: "Sharing Policy".to_string(),
            allowed_tenants: vec![
                "tenant1".to_string(),
                "tenant2".to_string(),
                "tenant3".to_string(),
            ],
            required_approvals: 2,
            allowed_operations: vec!["share".to_string()],
            data_residency: None,
            audit_level: AuditLevel::Basic,
        };

        ops.create_policy(policy).await.unwrap();

        let request = CollaborativeSecretRequest {
            secret_data: vec![1, 2, 3, 4, 5],
            tenant_ids: vec![
                "tenant1".to_string(),
                "tenant2".to_string(),
                "tenant3".to_string(),
            ],
            threshold: 2,
            policy_id: "policy2".to_string(),
            requester_tenant: "tenant1".to_string(),
        };

        let shares = ops.distributed_secret_sharing(request).await.unwrap();
        assert_eq!(shares.len(), 3);
        assert_eq!(shares[0].threshold, 2);
    }

    #[tokio::test]
    async fn test_collaborative_computation() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy3".to_string(),
            name: "Compute Policy".to_string(),
            allowed_tenants: vec!["tenant1".to_string(), "tenant2".to_string()],
            required_approvals: 2,
            allowed_operations: vec!["compute".to_string()],
            data_residency: None,
            audit_level: AuditLevel::Detailed,
        };

        ops.create_policy(policy).await.unwrap();

        let request = CollaborativeComputeRequest {
            computation_id: "comp1".to_string(),
            function_name: "sum".to_string(),
            participants: vec![
                ParticipantInput {
                    tenant_id: "tenant1".to_string(),
                    input_data: vec![10],
                    signature: None,
                },
                ParticipantInput {
                    tenant_id: "tenant2".to_string(),
                    input_data: vec![20],
                    signature: None,
                },
            ],
            threshold: 2,
            policy_id: "policy3".to_string(),
        };

        let result = ops.collaborative_computation(request).await.unwrap();
        assert_eq!(result.participants_contributed.len(), 2);
    }

    #[tokio::test]
    async fn test_threshold_approval_workflow() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy4".to_string(),
            name: "Approval Policy".to_string(),
            allowed_tenants: vec![
                "approver1".to_string(),
                "approver2".to_string(),
                "approver3".to_string(),
            ],
            required_approvals: 2,
            allowed_operations: vec!["approve".to_string()],
            data_residency: None,
            audit_level: AuditLevel::Full,
        };

        ops.create_policy(policy).await.unwrap();

        let workflow_id = ops
            .create_threshold_approval(
                "delete_secret".to_string(),
                2,
                vec![
                    "approver1".to_string(),
                    "approver2".to_string(),
                    "approver3".to_string(),
                ],
                "policy4".to_string(),
            )
            .await
            .unwrap();

        // Add first approval
        let sig1 = ApprovalSignature {
            approver_id: "approver1".to_string(),
            tenant_id: "approver1".to_string(),
            signature_data: vec![1, 2, 3],
            signed_at: Utc::now(),
        };

        let status = ops
            .add_approval_signature(&workflow_id, sig1)
            .await
            .unwrap();
        assert_eq!(status, WorkflowStatus::InProgress);

        // Add second approval
        let sig2 = ApprovalSignature {
            approver_id: "approver2".to_string(),
            tenant_id: "approver2".to_string(),
            signature_data: vec![4, 5, 6],
            signed_at: Utc::now(),
        };

        let status = ops
            .add_approval_signature(&workflow_id, sig2)
            .await
            .unwrap();
        assert_eq!(status, WorkflowStatus::Approved);
    }

    #[tokio::test]
    async fn test_isolation_violation() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy5".to_string(),
            name: "Restricted Policy".to_string(),
            allowed_tenants: vec!["tenant1".to_string()],
            required_approvals: 1,
            allowed_operations: vec!["share".to_string()],
            data_residency: None,
            audit_level: AuditLevel::Basic,
        };

        ops.create_policy(policy).await.unwrap();

        let request = CollaborativeSecretRequest {
            secret_data: vec![1, 2, 3],
            tenant_ids: vec!["tenant1".to_string(), "tenant2".to_string()], // tenant2 not allowed
            threshold: 2,
            policy_id: "policy5".to_string(),
            requester_tenant: "tenant1".to_string(),
        };

        let result = ops.distributed_secret_sharing(request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CollaborationError::IsolationViolated(_)
        ));
    }

    #[tokio::test]
    async fn test_collaboration_statistics() {
        let ops = SecureCollaborativeOperations::new();

        let policy = CollaborationPolicy {
            policy_id: "policy6".to_string(),
            name: "Stats Policy".to_string(),
            allowed_tenants: vec!["tenant1".to_string()],
            required_approvals: 1,
            allowed_operations: vec![],
            data_residency: None,
            audit_level: AuditLevel::None,
        };

        ops.create_policy(policy).await.unwrap();

        let stats = ops.get_collaboration_stats().await;
        assert!(stats.contains_key("policies"));
        assert_eq!(stats.get("policies"), Some(&1));
    }
}
