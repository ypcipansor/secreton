//! Control Groups
//!
//! Workflow approval system requiring N-of-M authorizations for sensitive operations.

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Control group errors
#[derive(Debug, thiserror::Error)]
pub enum ControlGroupError {
    #[error("Control group not found: {0}")]
    NotFound(String),

    #[error("Already authorized by this identity")]
    AlreadyAuthorized,

    #[error("Control group expired")]
    Expired,

    #[error("Not enough authorizations: {0}/{1}")]
    InsufficientAuthorizations(usize, usize),

    #[error("Invalid policy configuration: {0}")]
    InvalidPolicy(String),
}

/// Authorization record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    /// Identity who authorized
    pub identity: String,

    /// Timestamp
    pub timestamp: DateTime<Utc>,

    /// Approved or denied
    pub approved: bool,

    /// Comment
    pub comment: Option<String>,
}

/// Control group request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    /// Request ID
    pub id: String,

    /// Request path
    pub request_path: String,

    /// Request operation (read, write, delete)
    pub operation: String,

    /// Request data
    pub request_data: HashMap<String, serde_json::Value>,

    /// Required number of authorizations
    pub required_authorizations: usize,

    /// Authorizations received
    pub authorizations: Vec<Authorization>,

    /// Created by
    pub created_by: String,

    /// Created at
    pub created_at: DateTime<Utc>,

    /// Expires at
    pub expires_at: DateTime<Utc>,

    /// Status
    pub status: ControlGroupStatus,
}

impl ControlGroup {
    /// Check if control group is approved
    pub fn is_approved(&self) -> bool {
        let approved_count = self
            .authorizations
            .iter()
            .filter(|auth| auth.approved)
            .count();

        approved_count >= self.required_authorizations
    }

    /// Check if control group is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_at
    }

    /// Check if identity has already authorized
    pub fn has_authorized(&self, identity: &str) -> bool {
        self.authorizations
            .iter()
            .any(|auth| auth.identity == identity)
    }
}

/// Control group status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlGroupStatus {
    /// Pending authorizations
    Pending,

    /// Approved and ready
    Approved,

    /// Expired
    Expired,

    /// Denied
    Denied,
}

/// Control group policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupPolicy {
    /// Policy name
    pub name: String,

    /// Paths that require control group
    pub paths: Vec<String>,

    /// Required authorizations count
    pub required_count: usize,

    /// TTL for control group (seconds)
    pub ttl: u64,

    /// Authorized identities (roles, groups, users)
    pub authorized_identities: Vec<String>,
}

/// Control group service
pub struct ControlGroupService {
    control_groups: Arc<RwLock<HashMap<String, ControlGroup>>>,
    policies: Arc<RwLock<HashMap<String, ControlGroupPolicy>>>,
}

impl ControlGroupService {
    /// Create new control group service
    pub fn new() -> Self {
        Self {
            control_groups: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create control group policy
    pub async fn create_policy(&self, policy: ControlGroupPolicy) -> Result<(), ControlGroupError> {
        if policy.required_count == 0 {
            return Err(ControlGroupError::InvalidPolicy(
                "Required count must be greater than 0".to_string(),
            ));
        }

        let mut policies = self.policies.write().await;
        policies.insert(policy.name.clone(), policy);
        Ok(())
    }

    /// Get policy
    pub async fn get_policy(&self, name: &str) -> Option<ControlGroupPolicy> {
        let policies = self.policies.read().await;
        policies.get(name).cloned()
    }

    /// Find policy for path
    pub async fn find_policy_for_path(&self, path: &str) -> Option<ControlGroupPolicy> {
        let policies = self.policies.read().await;

        for policy in policies.values() {
            for policy_path in &policy.paths {
                if self.path_matches(path, policy_path) {
                    return Some(policy.clone());
                }
            }
        }

        None
    }

    /// Create control group request
    pub async fn create_request(
        &self,
        request_path: String,
        operation: String,
        request_data: HashMap<String, serde_json::Value>,
        created_by: String,
        required_authorizations: usize,
        ttl: u64,
    ) -> Result<String, ControlGroupError> {
        let id = uuid::Uuid::new_v4().to_string();

        let control_group = ControlGroup {
            id: id.clone(),
            request_path,
            operation,
            request_data,
            required_authorizations,
            authorizations: Vec::new(),
            created_by,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(ttl as i64),
            status: ControlGroupStatus::Pending,
        };

        let mut control_groups = self.control_groups.write().await;
        control_groups.insert(id.clone(), control_group);

        Ok(id)
    }

    /// Authorize control group request
    pub async fn authorize(
        &self,
        id: &str,
        identity: String,
        approved: bool,
        comment: Option<String>,
    ) -> Result<ControlGroup, ControlGroupError> {
        let mut control_groups = self.control_groups.write().await;

        let control_group = control_groups
            .get_mut(id)
            .ok_or_else(|| ControlGroupError::NotFound(id.to_string()))?;

        // Check expiration
        if control_group.is_expired() {
            control_group.status = ControlGroupStatus::Expired;
            return Err(ControlGroupError::Expired);
        }

        // Check duplicate authorization
        if control_group.has_authorized(&identity) {
            return Err(ControlGroupError::AlreadyAuthorized);
        }

        // Add authorization
        let authorization = Authorization {
            identity,
            timestamp: Utc::now(),
            approved,
            comment,
        };

        control_group.authorizations.push(authorization);

        // Update status
        if !approved {
            control_group.status = ControlGroupStatus::Denied;
        } else if control_group.is_approved() {
            control_group.status = ControlGroupStatus::Approved;
        }

        Ok(control_group.clone())
    }

    /// Check if control group is approved
    pub async fn check_approved(&self, id: &str) -> Result<bool, ControlGroupError> {
        let control_groups = self.control_groups.read().await;

        let control_group = control_groups
            .get(id)
            .ok_or_else(|| ControlGroupError::NotFound(id.to_string()))?;

        if control_group.is_expired() {
            return Err(ControlGroupError::Expired);
        }

        Ok(control_group.is_approved())
    }

    /// Get control group
    pub async fn get(&self, id: &str) -> Option<ControlGroup> {
        let control_groups = self.control_groups.read().await;
        control_groups.get(id).cloned()
    }

    /// List pending control groups
    pub async fn list_pending(&self) -> Vec<ControlGroup> {
        let control_groups = self.control_groups.read().await;

        control_groups
            .values()
            .filter(|cg| cg.status == ControlGroupStatus::Pending && !cg.is_expired())
            .cloned()
            .collect()
    }

    /// List control groups for identity
    pub async fn list_for_identity(&self, identity: &str) -> Vec<ControlGroup> {
        let control_groups = self.control_groups.read().await;

        control_groups
            .values()
            .filter(|cg| {
                cg.status == ControlGroupStatus::Pending
                    && !cg.is_expired()
                    && !cg.has_authorized(identity)
            })
            .cloned()
            .collect()
    }

    /// Delete control group
    pub async fn delete(&self, id: &str) -> Result<(), ControlGroupError> {
        let mut control_groups = self.control_groups.write().await;
        control_groups
            .remove(id)
            .ok_or_else(|| ControlGroupError::NotFound(id.to_string()))?;
        Ok(())
    }

    /// Cleanup expired control groups
    pub async fn cleanup_expired(&self) -> usize {
        let mut control_groups = self.control_groups.write().await;

        let expired_ids: Vec<String> = control_groups
            .values()
            .filter(|cg| cg.is_expired())
            .map(|cg| cg.id.clone())
            .collect();

        let count = expired_ids.len();

        for id in expired_ids {
            control_groups.remove(&id);
        }

        count
    }

    /// Check if path matches pattern (simple wildcard)
    fn path_matches(&self, path: &str, pattern: &str) -> bool {
        if let Some(prefix) = pattern.strip_suffix('*') {
            path.starts_with(prefix)
        } else {
            path == pattern
        }
    }
}

impl Default for ControlGroupService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_control_group() {
        let service = ControlGroupService::new();

        let id = service
            .create_request(
                "secret/sensitive".to_string(),
                "write".to_string(),
                HashMap::new(),
                "user1".to_string(),
                2,
                3600,
            )
            .await
            .unwrap();

        let cg = service.get(&id).await.unwrap();
        assert_eq!(cg.request_path, "secret/sensitive");
        assert_eq!(cg.required_authorizations, 2);
        assert_eq!(cg.status, ControlGroupStatus::Pending);
    }

    #[tokio::test]
    async fn test_authorization_workflow() {
        let service = ControlGroupService::new();

        let id = service
            .create_request(
                "secret/critical".to_string(),
                "delete".to_string(),
                HashMap::new(),
                "user1".to_string(),
                3,
                3600,
            )
            .await
            .unwrap();

        // First authorization
        service
            .authorize(
                &id,
                "admin1".to_string(),
                true,
                Some("Approved".to_string()),
            )
            .await
            .unwrap();
        assert!(!service.check_approved(&id).await.unwrap());

        // Second authorization
        service
            .authorize(&id, "admin2".to_string(), true, None)
            .await
            .unwrap();
        assert!(!service.check_approved(&id).await.unwrap());

        // Third authorization - should approve
        service
            .authorize(&id, "admin3".to_string(), true, None)
            .await
            .unwrap();
        assert!(service.check_approved(&id).await.unwrap());

        let cg = service.get(&id).await.unwrap();
        assert_eq!(cg.status, ControlGroupStatus::Approved);
    }

    #[tokio::test]
    async fn test_denial() {
        let service = ControlGroupService::new();

        let id = service
            .create_request(
                "secret/data".to_string(),
                "write".to_string(),
                HashMap::new(),
                "user1".to_string(),
                2,
                3600,
            )
            .await
            .unwrap();

        service
            .authorize(&id, "admin1".to_string(), true, None)
            .await
            .unwrap();
        service
            .authorize(
                &id,
                "admin2".to_string(),
                false,
                Some("Rejected".to_string()),
            )
            .await
            .unwrap();

        let cg = service.get(&id).await.unwrap();
        assert_eq!(cg.status, ControlGroupStatus::Denied);
    }

    #[tokio::test]
    async fn test_list_pending() {
        let service = ControlGroupService::new();

        service
            .create_request(
                "secret/data1".to_string(),
                "write".to_string(),
                HashMap::new(),
                "user1".to_string(),
                2,
                3600,
            )
            .await
            .unwrap();

        service
            .create_request(
                "secret/data2".to_string(),
                "write".to_string(),
                HashMap::new(),
                "user2".to_string(),
                2,
                3600,
            )
            .await
            .unwrap();

        let pending = service.list_pending().await;
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_control_group_policy() {
        let service = ControlGroupService::new();

        let policy = ControlGroupPolicy {
            name: "sensitive-data".to_string(),
            paths: vec!["secret/sensitive/*".to_string()],
            required_count: 3,
            ttl: 1800,
            authorized_identities: vec!["admin-group".to_string()],
        };

        service.create_policy(policy).await.unwrap();

        let found = service.find_policy_for_path("secret/sensitive/key").await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().required_count, 3);
    }
}
