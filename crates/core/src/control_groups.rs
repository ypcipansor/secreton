//! Control Groups - Multi-person Authorization
//!
//! This module provides control groups functionality for multi-person authorization workflows,
//! similar to HashiCorp Vault's control groups feature. Control groups allow organizations
//! to require multiple users to approve sensitive operations.
//!
//! Key features:
//! - Multi-person authorization workflows
//! - Configurable approval requirements (2+ approvers)
//! - Request expiration with TTL management
//! - Complete status tracking and audit trail
//! - Integration with existing authentication systems

use crate::error::{CryptoResult, CryptoError};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Control group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupConfig {
    /// Control group name
    pub name: String,
    /// Required number of approvals
    pub required_approvals: u32,
    /// Maximum time to live for authorization requests (in seconds)
    pub max_ttl_seconds: u64,
    /// List of authorized approvers (user IDs)
    pub authorized_approvers: Vec<String>,
    /// Description of the control group
    pub description: String,
    /// Whether the control group is enabled
    pub enabled: bool,
}

impl Default for ControlGroupConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            required_approvals: 2,
            max_ttl_seconds: 3600, // 1 hour
            authorized_approvers: Vec::new(),
            description: "Default control group requiring 2 approvals".to_string(),
            enabled: true,
        }
    }
}

/// Authorization request status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthorizationStatus {
    /// Request is pending approval
    Pending,
    /// Request has been approved by required number of users
    Approved,
    /// Request has been rejected
    Rejected,
    /// Request has expired
    Expired,
    /// Request was cancelled
    Cancelled,
}

/// Authorization request for multi-person approval
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// Unique request identifier
    pub request_id: String,
    /// Control group name
    pub control_group: String,
    /// User who initiated the request
    pub requester_id: String,
    /// Operation being requested
    pub operation: String,
    /// Resource/path being accessed
    pub resource: String,
    /// Additional context/parameters
    pub context: HashMap<String, String>,
    /// Current status
    pub status: AuthorizationStatus,
    /// Number of approvals received
    pub approvals_received: u32,
    /// Required number of approvals
    pub required_approvals: u32,
    /// List of approvers and their decisions
    pub approver_decisions: HashMap<String, ApprovalDecision>,
    /// Request creation time
    pub created_at: DateTime<Utc>,
    /// Request expiration time
    pub expires_at: DateTime<Utc>,
    /// Request completion time (if completed)
    pub completed_at: Option<DateTime<Utc>>,
}

impl AuthorizationRequest {
    /// Create a new authorization request
    pub fn new(
        control_group: String,
        requester_id: String,
        operation: String,
        resource: String,
        context: HashMap<String, String>,
        max_ttl_seconds: u64,
    ) -> Self {
        let now = Utc::now();
        Self {
            request_id: Uuid::new_v4().to_string(),
            control_group,
            requester_id,
            operation,
            resource,
            context,
            status: AuthorizationStatus::Pending,
            approvals_received: 0,
            required_approvals: 0, // Will be set by control group
            approver_decisions: HashMap::new(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(max_ttl_seconds as i64),
            completed_at: None,
        }
    }

    /// Check if request is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if request is completed
    pub fn is_completed(&self) -> bool {
        matches!(
            self.status,
            AuthorizationStatus::Approved | AuthorizationStatus::Rejected | AuthorizationStatus::Expired
        )
    }

    /// Add an approval decision
    pub fn add_approval(&mut self, approver_id: String, decision: ApprovalDecision) {
        if self.is_completed() {
            return; // Don't allow changes to completed requests
        }

        self.approver_decisions.insert(approver_id.clone(), decision);

        match decision {
            ApprovalDecision::Approve => {
                self.approvals_received += 1;
                if self.approvals_received >= self.required_approvals {
                    self.status = AuthorizationStatus::Approved;
                    self.completed_at = Some(Utc::now());
                }
            }
            ApprovalDecision::Reject => {
                self.status = AuthorizationStatus::Rejected;
                self.completed_at = Some(Utc::now());
            }
            ApprovalDecision::Escalate => {
                // For now, treat escalation as rejection
                self.status = AuthorizationStatus::Rejected;
                self.completed_at = Some(Utc::now());
            }
        }
    }
}

/// Approval decision types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// Approve the request
    Approve,
    /// Reject the request
    Reject,
    /// Escalate to higher authority
    Escalate,
}

/// Control groups manager for handling multi-person authorization
#[derive(Debug)]
pub struct ControlGroupsManager {
    /// Control group configurations
    control_groups: Arc<RwLock<HashMap<String, ControlGroupConfig>>>,
    /// Active authorization requests
    requests: Arc<RwLock<HashMap<String, AuthorizationRequest>>>,
}

impl ControlGroupsManager {
    /// Create a new control groups manager
    pub fn new() -> Self {
        Self {
            control_groups: Arc::new(RwLock::new(HashMap::new())),
            requests: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new control group
    pub async fn create_control_group(&self, config: ControlGroupConfig) -> CryptoResult<()> {
        if config.authorized_approvers.is_empty() {
            return Err(CryptoError::InvalidParameter("Control group must have at least one authorized approver".to_string()));
        }

        if config.required_approvals == 0 || config.required_approvals > config.authorized_approvers.len() as u32 {
            return Err(CryptoError::InvalidParameter("Required approvals must be between 1 and number of authorized approvers".to_string()));
        }

        let mut groups = self.control_groups.write().await;
        groups.insert(config.name.clone(), config);

        Ok(())
    }

    /// Get control group configuration
    pub async fn get_control_group(&self, name: &str) -> Option<ControlGroupConfig> {
        let groups = self.control_groups.read().await;
        groups.get(name).cloned()
    }

    /// List all control groups
    pub async fn list_control_groups(&self) -> Vec<String> {
        let groups = self.control_groups.read().await;
        groups.keys().cloned().collect()
    }

    /// Delete a control group
    pub async fn delete_control_group(&self, name: &str) -> CryptoResult<()> {
        let mut groups = self.control_groups.write().await;
        groups.remove(name)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Control group '{}' not found", name)))?;

        Ok(())
    }

    /// Create an authorization request
    pub async fn create_authorization_request(
        &self,
        control_group: &str,
        requester_id: String,
        operation: String,
        resource: String,
        context: HashMap<String, String>,
    ) -> CryptoResult<String> {
        let groups = self.control_groups.read().await;
        let config = groups.get(control_group)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Control group '{}' not found", control_group)))?;

        if !config.enabled {
            return Err(CryptoError::InvalidParameter(format!("Control group '{}' is disabled", control_group)));
        }

        let mut request = AuthorizationRequest::new(
            control_group.to_string(),
            requester_id,
            operation,
            resource,
            context,
            config.max_ttl_seconds,
        );

        request.required_approvals = config.required_approvals;

        let mut requests = self.requests.write().await;
        let request_id = request.request_id.clone();
        requests.insert(request_id.clone(), request);

        Ok(request_id)
    }

    /// Get authorization request status
    pub async fn get_authorization_request(&self, request_id: &str) -> Option<AuthorizationRequest> {
        let requests = self.requests.read().await;
        requests.get(request_id).cloned()
    }

    /// Approve an authorization request
    pub async fn approve_request(&self, request_id: &str, approver_id: String) -> CryptoResult<()> {
        let mut requests = self.requests.write().await;
        let request = requests.get_mut(request_id)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Request '{}' not found", request_id)))?;

        if request.is_completed() {
            return Err(CryptoError::InvalidParameter(format!("Request '{}' is already completed", request_id)));
        }

        if request.is_expired() {
            request.status = AuthorizationStatus::Expired;
            request.completed_at = Some(Utc::now());
            return Err(CryptoError::InvalidParameter(format!("Request '{}' has expired", request_id)));
        }

        // Check if approver is authorized
        let groups = self.control_groups.read().await;
        let config = groups.get(&request.control_group)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Control group '{}' not found", request.control_group)))?;

        if !config.authorized_approvers.contains(&approver_id) {
            return Err(CryptoError::InvalidParameter(format!("User '{}' is not authorized to approve this request", approver_id)));
        }

        // Check if user already approved
        if request.approver_decisions.contains_key(&approver_id) {
            return Err(CryptoError::InvalidParameter(format!("User '{}' has already voted on this request", approver_id)));
        }

        request.add_approval(approver_id, ApprovalDecision::Approve);

        Ok(())
    }

    /// Reject an authorization request
    pub async fn reject_request(&self, request_id: &str, approver_id: String) -> CryptoResult<()> {
        let mut requests = self.requests.write().await;
        let request = requests.get_mut(request_id)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Request '{}' not found", request_id)))?;

        if request.is_completed() {
            return Err(CryptoError::InvalidParameter(format!("Request '{}' is already completed", request_id)));
        }

        if request.is_expired() {
            request.status = AuthorizationStatus::Expired;
            request.completed_at = Some(Utc::now());
            return Err(CryptoError::InvalidParameter(format!("Request '{}' has expired", request_id)));
        }

        // Check if approver is authorized
        let groups = self.control_groups.read().await;
        let config = groups.get(&request.control_group)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Control group '{}' not found", request.control_group)))?;

        if !config.authorized_approvers.contains(&approver_id) {
            return Err(CryptoError::InvalidParameter(format!("User '{}' is not authorized to approve this request", approver_id)));
        }

        request.add_approval(approver_id, ApprovalDecision::Reject);

        Ok(())
    }

    /// Cancel an authorization request
    pub async fn cancel_request(&self, request_id: &str, requester_id: String) -> CryptoResult<()> {
        let mut requests = self.requests.write().await;
        let request = requests.get_mut(request_id)
            .ok_or_else(|| CryptoError::InvalidParameter(format!("Request '{}' not found", request_id)))?;

        if request.requester_id != requester_id {
            return Err(CryptoError::InvalidParameter("Only the requester can cancel the request".to_string()));
        }

        if request.is_completed() {
            return Err(CryptoError::InvalidParameter(format!("Request '{}' is already completed", request_id)));
        }

        request.status = AuthorizationStatus::Cancelled;
        request.completed_at = Some(Utc::now());

        Ok(())
    }

    /// Clean up expired requests
    pub async fn cleanup_expired_requests(&self) {
        let mut requests = self.requests.write().await;
        let mut expired_ids = Vec::new();

        for (id, request) in requests.iter() {
            if request.is_expired() && !request.is_completed() {
                expired_ids.push(id.clone());
            }
        }

        for id in expired_ids {
            if let Some(request) = requests.get_mut(&id) {
                request.status = AuthorizationStatus::Expired;
                request.completed_at = Some(Utc::now());
            }
        }
    }

    /// Get pending requests for an approver
    pub async fn get_pending_requests_for_approver(&self, approver_id: &str) -> Vec<AuthorizationRequest> {
        let requests = self.requests.read().await;

        requests
            .values()
            .filter(|request| {
                request.status == AuthorizationStatus::Pending
                    && !request.is_expired()
                    && request.approver_decisions.get(approver_id).is_none()
            })
            .cloned()
            .collect()
    }

    /// Get active requests for a control group
    pub async fn get_active_requests_for_group(&self, control_group: &str) -> Vec<AuthorizationRequest> {
        let requests = self.requests.read().await;

        requests
            .values()
            .filter(|request| {
                request.control_group == control_group
                    && request.status == AuthorizationStatus::Pending
                    && !request.is_expired()
            })
            .cloned()
            .collect()
    }
}

impl Default for ControlGroupsManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Control group request for API
#[derive(Debug, Deserialize)]
pub struct CreateControlGroupRequest {
    pub name: String,
    pub required_approvals: u32,
    pub max_ttl_seconds: u64,
    pub authorized_approvers: Vec<String>,
    pub description: String,
}

/// Control group response for API
#[derive(Debug, Serialize)]
pub struct CreateControlGroupResponse {
    pub success: bool,
    pub message: String,
}

/// Authorization request for API
#[derive(Debug, Deserialize)]
pub struct CreateAuthorizationRequest {
    pub control_group: String,
    pub operation: String,
    pub resource: String,
    pub context: Option<HashMap<String, String>>,
}

/// Authorization response for API
#[derive(Debug, Serialize)]
pub struct CreateAuthorizationResponse {
    pub request_id: String,
    pub status: String,
    pub expires_at: String,
}

/// Approval request for API
#[derive(Debug, Deserialize)]
pub struct ApprovalRequest {
    pub decision: String, // "approve" or "reject"
}

/// Approval response for API
#[derive(Debug, Serialize)]
pub struct ApprovalResponse {
    pub success: bool,
    pub message: String,
    pub new_status: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_control_group_creation() {
        let manager = ControlGroupsManager::new();
        let config = ControlGroupConfig {
            name: "test-group".to_string(),
            required_approvals: 2,
            max_ttl_seconds: 3600,
            authorized_approvers: vec!["user1".to_string(), "user2".to_string(), "user3".to_string()],
            description: "Test control group".to_string(),
            enabled: true,
        };

        manager.create_control_group(config).await.unwrap();
        let retrieved = manager.get_control_group("test-group").await.unwrap();

        assert_eq!(retrieved.name, "test-group");
        assert_eq!(retrieved.required_approvals, 2);
        assert_eq!(retrieved.authorized_approvers.len(), 3);
    }

    #[tokio::test]
    async fn test_authorization_workflow() {
        let manager = ControlGroupsManager::new();

        // Create control group
        let config = ControlGroupConfig {
            name: "test-group".to_string(),
            required_approvals: 2,
            max_ttl_seconds: 3600,
            authorized_approvers: vec!["approver1".to_string(), "approver2".to_string()],
            description: "Test control group".to_string(),
            enabled: true,
        };
        manager.create_control_group(config).await.unwrap();

        // Create authorization request
        let request_id = manager
            .create_authorization_request(
                "test-group",
                "requester1".to_string(),
                "encrypt".to_string(),
                "secret/data/app".to_string(),
                HashMap::new(),
            )
            .await
            .unwrap();

        // First approval
        manager.approve_request(&request_id, "approver1".to_string()).await.unwrap();

        // Check status - should still be pending
        let request = manager.get_authorization_request(&request_id).await.unwrap();
        assert!(matches!(request.status, AuthorizationStatus::Pending));
        assert_eq!(request.approvals_received, 1);

        // Second approval - should complete the request
        manager.approve_request(&request_id, "approver2".to_string()).await.unwrap();

        let request = manager.get_authorization_request(&request_id).await.unwrap();
        assert!(matches!(request.status, AuthorizationStatus::Approved));
        assert_eq!(request.approvals_received, 2);
    }

    #[tokio::test]
    async fn test_request_rejection() {
        let manager = ControlGroupsManager::new();

        // Create control group
        let config = ControlGroupConfig {
            name: "test-group".to_string(),
            required_approvals: 2,
            max_ttl_seconds: 3600,
            authorized_approvers: vec!["approver1".to_string(), "approver2".to_string()],
            description: "Test control group".to_string(),
            enabled: true,
        };
        manager.create_control_group(config).await.unwrap();

        // Create authorization request
        let request_id = manager
            .create_authorization_request(
                "test-group",
                "requester1".to_string(),
                "encrypt".to_string(),
                "secret/data/app".to_string(),
                HashMap::new(),
            )
            .await
            .unwrap();

        // Reject the request
        manager.reject_request(&request_id, "approver1".to_string()).await.unwrap();

        let request = manager.get_authorization_request(&request_id).await.unwrap();
        assert!(matches!(request.status, AuthorizationStatus::Rejected));
    }

    #[tokio::test]
    async fn test_unauthorized_approver() {
        let manager = ControlGroupsManager::new();

        // Create control group
        let config = ControlGroupConfig {
            name: "test-group".to_string(),
            required_approvals: 2,
            max_ttl_seconds: 3600,
            authorized_approvers: vec!["approver1".to_string(), "approver2".to_string()],
            description: "Test control group".to_string(),
            enabled: true,
        };
        manager.create_control_group(config).await.unwrap();

        // Create authorization request
        let request_id = manager
            .create_authorization_request(
                "test-group",
                "requester1".to_string(),
                "encrypt".to_string(),
                "secret/data/app".to_string(),
                HashMap::new(),
            )
            .await
            .unwrap();

        // Try to approve with unauthorized user
        let result = manager.approve_request(&request_id, "unauthorized_user".to_string()).await;
        assert!(result.is_err());
    }
}
