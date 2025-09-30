/// Control Groups - Multi-Person Authorization
/// 
/// Implements approval workflows and multi-person authorization for sensitive operations

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use uuid::Uuid;

/// Control group authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupRequest {
    /// Unique request ID
    pub id: Uuid,
    /// Request path
    pub path: String,
    /// Operation being requested
    pub operation: String,
    /// Request data
    pub data: serde_json::Value,
    /// Requester identity
    pub requester: String,
    /// Required number of approvals
    pub required_approvals: usize,
    /// Current approvals
    pub approvals: Vec<Approval>,
    /// Request status
    pub status: RequestStatus,
    /// Created timestamp
    pub created_at: DateTime<Utc>,
    /// Expires at timestamp
    pub expires_at: DateTime<Utc>,
    /// Metadata
    pub metadata: HashMap<String, String>,
}

/// Approval from an authorizer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Approval {
    /// Approver identity
    pub approver: String,
    /// Approval timestamp
    pub approved_at: DateTime<Utc>,
    /// Optional comment
    pub comment: Option<String>,
}

/// Request status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestStatus {
    /// Pending approval
    Pending,
    /// Approved and ready to execute
    Approved,
    /// Rejected
    Rejected,
    /// Expired
    Expired,
    /// Executed
    Executed,
}

/// Control group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupConfig {
    /// Path patterns that require control group
    pub paths: Vec<String>,
    /// Required number of approvals
    pub required_approvals: usize,
    /// Authorized approvers
    pub authorizers: Vec<String>,
    /// Request TTL in seconds
    pub ttl_seconds: i64,
}

impl Default for ControlGroupConfig {
    fn default() -> Self {
        Self {
            paths: vec!["secret/*".to_string()],
            required_approvals: 2,
            authorizers: vec![],
            ttl_seconds: 3600, // 1 hour
        }
    }
}

/// Control group manager
pub struct ControlGroupManager {
    /// Active requests
    requests: HashMap<Uuid, ControlGroupRequest>,
    /// Control group configurations by path
    configs: HashMap<String, ControlGroupConfig>,
}

impl ControlGroupManager {
    /// Create new control group manager
    pub fn new() -> Self {
        Self {
            requests: HashMap::new(),
            configs: HashMap::new(),
        }
    }

    /// Register a control group configuration
    pub fn register_config(&mut self, path: String, config: ControlGroupConfig) {
        self.configs.insert(path, config);
    }

    /// Check if path requires control group
    pub fn requires_control_group(&self, path: &str) -> Option<&ControlGroupConfig> {
        for (pattern, config) in &self.configs {
            if self.path_matches(path, pattern) {
                return Some(config);
            }
        }
        None
    }

    /// Create a new control group request
    pub fn create_request(
        &mut self,
        path: String,
        operation: String,
        data: serde_json::Value,
        requester: String,
    ) -> Result<Uuid, String> {
        let config = self.requires_control_group(&path)
            .ok_or_else(|| "Path does not require control group".to_string())?;

        let id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + Duration::seconds(config.ttl_seconds);

        let request = ControlGroupRequest {
            id,
            path,
            operation,
            data,
            requester,
            required_approvals: config.required_approvals,
            approvals: Vec::new(),
            status: RequestStatus::Pending,
            created_at: now,
            expires_at,
            metadata: HashMap::new(),
        };

        self.requests.insert(id, request);
        Ok(id)
    }

    /// Approve a request
    pub fn approve_request(
        &mut self,
        request_id: Uuid,
        approver: String,
        comment: Option<String>,
    ) -> Result<RequestStatus, String> {
        let request = self.requests.get_mut(&request_id)
            .ok_or_else(|| "Request not found".to_string())?;

        // Check if expired
        if Utc::now() > request.expires_at {
            request.status = RequestStatus::Expired;
            return Err("Request has expired".to_string());
        }

        // Check if already approved/rejected
        if request.status != RequestStatus::Pending {
            return Err(format!("Request is already {:?}", request.status));
        }

        // Check if approver already approved
        if request.approvals.iter().any(|a| a.approver == approver) {
            return Err("Approver has already approved this request".to_string());
        }

        // Check if approver is authorized
        if let Some(config) = self.requires_control_group(&request.path) {
            if !config.authorizers.is_empty() && !config.authorizers.contains(&approver) {
                return Err("Approver is not authorized".to_string());
            }
        }

        // Add approval
        let approval = Approval {
            approver,
            approved_at: Utc::now(),
            comment,
        };
        request.approvals.push(approval);

        // Check if enough approvals
        if request.approvals.len() >= request.required_approvals {
            request.status = RequestStatus::Approved;
        }

        Ok(request.status)
    }

    /// Reject a request
    pub fn reject_request(
        &mut self,
        request_id: Uuid,
        rejector: String,
    ) -> Result<(), String> {
        let request = self.requests.get_mut(&request_id)
            .ok_or_else(|| "Request not found".to_string())?;

        if request.status != RequestStatus::Pending {
            return Err(format!("Request is already {:?}", request.status));
        }

        request.status = RequestStatus::Rejected;
        Ok(())
    }

    /// Get request status
    pub fn get_request(&self, request_id: Uuid) -> Option<&ControlGroupRequest> {
        self.requests.get(&request_id)
    }

    /// List pending requests
    pub fn list_pending_requests(&self) -> Vec<&ControlGroupRequest> {
        self.requests.values()
            .filter(|r| r.status == RequestStatus::Pending && Utc::now() <= r.expires_at)
            .collect()
    }

    /// Mark request as executed
    pub fn mark_executed(&mut self, request_id: Uuid) -> Result<(), String> {
        let request = self.requests.get_mut(&request_id)
            .ok_or_else(|| "Request not found".to_string())?;

        if request.status != RequestStatus::Approved {
            return Err("Request is not approved".to_string());
        }

        request.status = RequestStatus::Executed;
        Ok(())
    }

    /// Clean up expired requests
    pub fn cleanup_expired(&mut self) {
        let now = Utc::now();
        self.requests.retain(|_, request| {
            if now > request.expires_at && request.status == RequestStatus::Pending {
                false
            } else {
                true
            }
        });
    }

    /// Check if path matches pattern
    fn path_matches(&self, path: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.ends_with("/*") {
            let prefix = pattern.trim_end_matches("/*");
            return path.starts_with(prefix);
        }
        
        path == pattern
    }
}

impl Default for ControlGroupManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_group_manager_creation() {
        let manager = ControlGroupManager::new();
        assert_eq!(manager.requests.len(), 0);
        assert_eq!(manager.configs.len(), 0);
    }

    #[test]
    fn test_register_config() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig {
            paths: vec!["secret/*".to_string()],
            required_approvals: 2,
            authorizers: vec!["admin1".to_string(), "admin2".to_string()],
            ttl_seconds: 3600,
        };

        manager.register_config("secret/*".to_string(), config);
        assert!(manager.requires_control_group("secret/data").is_some());
    }

    #[test]
    fn test_create_request() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig::default();
        manager.register_config("secret/*".to_string(), config);

        let result = manager.create_request(
            "secret/data".to_string(),
            "write".to_string(),
            serde_json::json!({"key": "value"}),
            "user1".to_string(),
        );

        assert!(result.is_ok());
        let request_id = result.unwrap();
        let request = manager.get_request(request_id).unwrap();
        assert_eq!(request.status, RequestStatus::Pending);
        assert_eq!(request.required_approvals, 2);
    }

    #[test]
    fn test_approve_request() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig {
            required_approvals: 2,
            authorizers: vec!["admin1".to_string(), "admin2".to_string()],
            ..Default::default()
        };
        manager.register_config("secret/*".to_string(), config);

        let request_id = manager.create_request(
            "secret/data".to_string(),
            "write".to_string(),
            serde_json::json!({}),
            "user1".to_string(),
        ).unwrap();

        // First approval
        let status = manager.approve_request(
            request_id,
            "admin1".to_string(),
            Some("Approved".to_string()),
        ).unwrap();
        assert_eq!(status, RequestStatus::Pending);

        // Second approval
        let status = manager.approve_request(
            request_id,
            "admin2".to_string(),
            None,
        ).unwrap();
        assert_eq!(status, RequestStatus::Approved);
    }

    #[test]
    fn test_reject_request() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig::default();
        manager.register_config("secret/*".to_string(), config);

        let request_id = manager.create_request(
            "secret/data".to_string(),
            "write".to_string(),
            serde_json::json!({}),
            "user1".to_string(),
        ).unwrap();

        let result = manager.reject_request(request_id, "admin1".to_string());
        assert!(result.is_ok());

        let request = manager.get_request(request_id).unwrap();
        assert_eq!(request.status, RequestStatus::Rejected);
    }

    #[test]
    fn test_duplicate_approval() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig::default();
        manager.register_config("secret/*".to_string(), config);

        let request_id = manager.create_request(
            "secret/data".to_string(),
            "write".to_string(),
            serde_json::json!({}),
            "user1".to_string(),
        ).unwrap();

        manager.approve_request(request_id, "admin1".to_string(), None).unwrap();
        
        // Try to approve again with same approver
        let result = manager.approve_request(request_id, "admin1".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_list_pending_requests() {
        let mut manager = ControlGroupManager::new();
        let config = ControlGroupConfig::default();
        manager.register_config("secret/*".to_string(), config);

        manager.create_request(
            "secret/data1".to_string(),
            "write".to_string(),
            serde_json::json!({}),
            "user1".to_string(),
        ).unwrap();

        manager.create_request(
            "secret/data2".to_string(),
            "write".to_string(),
            serde_json::json!({}),
            "user2".to_string(),
        ).unwrap();

        let pending = manager.list_pending_requests();
        assert_eq!(pending.len(), 2);
    }
}
