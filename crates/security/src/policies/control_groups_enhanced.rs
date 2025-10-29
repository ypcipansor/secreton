// Enhanced Control Groups - Dual authorization with workflow management
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum ControlGroupError {
    #[error("Control group error: {0}")]
    ControlGroupError(String),
    #[error("Authorization error: {0}")]
    AuthorizationError(String),
    #[error("Expired error: {0}")]
    ExpiredError(String),
}

pub type Result<T> = std::result::Result<T, ControlGroupError>;

/// Control group status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlGroupStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Operation type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OperationType {
    Read,
    Write,
    Delete,
    Admin,
}

/// Authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Authorization {
    pub user_id: String,
    pub authorized_at: DateTime<Utc>,
    pub signature: String,
    pub comment: Option<String>,
}

/// Control group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupConfig {
    pub required_authorizers: usize,
    pub timeout_seconds: i64,
    pub allowed_authorizers: Vec<String>, // Specific users who can authorize
    pub auto_approve_paths: Vec<String>,  // Paths that bypass control groups
}

/// Control group
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroup {
    pub group_id: String,
    pub request_path: String,
    pub operation: OperationType,
    pub requestor: String,
    pub required_authorizers: usize,
    pub current_authorizers: Vec<Authorization>,
    pub status: ControlGroupStatus,
    pub request_data: HashMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Enhanced Control Groups
pub struct EnhancedControlGroups {
    config: Arc<RwLock<ControlGroupConfig>>,
    control_groups: Arc<RwLock<HashMap<String, ControlGroup>>>,
}

impl EnhancedControlGroups {
    pub fn new(config: ControlGroupConfig) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            control_groups: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create control group
    pub async fn create_control_group(
        &self,
        request_path: String,
        operation: OperationType,
        requestor: String,
        request_data: HashMap<String, String>,
    ) -> Result<ControlGroup> {
        let config = self.config.read().await;

        // Check if path is auto-approved
        if config
            .auto_approve_paths
            .iter()
            .any(|p| request_path.starts_with(p))
        {
            return Err(ControlGroupError::ControlGroupError(
                "Path is auto-approved".to_string(),
            ));
        }

        let group_id = uuid::Uuid::new_v4().to_string();

        let control_group = ControlGroup {
            group_id: group_id.clone(),
            request_path,
            operation,
            requestor,
            required_authorizers: config.required_authorizers,
            current_authorizers: Vec::new(),
            status: ControlGroupStatus::Pending,
            request_data,
            created_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(config.timeout_seconds),
        };

        let mut groups = self.control_groups.write().await;
        groups.insert(group_id.clone(), control_group.clone());

        Ok(control_group)
    }

    /// Authorize control group
    pub async fn authorize(
        &self,
        group_id: &str,
        user_id: String,
        signature: String,
        comment: Option<String>,
    ) -> Result<()> {
        let mut groups = self.control_groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| ControlGroupError::ControlGroupError("Group not found".to_string()))?;

        // Check if expired
        if Utc::now() > group.expires_at {
            group.status = ControlGroupStatus::Expired;
            return Err(ControlGroupError::ExpiredError(
                "Control group expired".to_string(),
            ));
        }

        // Check if already authorized by this user
        if group
            .current_authorizers
            .iter()
            .any(|a| a.user_id == user_id)
        {
            return Err(ControlGroupError::AuthorizationError(
                "User already authorized".to_string(),
            ));
        }

        // Validate authorizer is allowed
        let config = self.config.read().await;
        if !config.allowed_authorizers.is_empty() && !config.allowed_authorizers.contains(&user_id)
        {
            return Err(ControlGroupError::AuthorizationError(
                "User not allowed to authorize".to_string(),
            ));
        }

        // Add authorization
        let auth = Authorization {
            user_id,
            authorized_at: Utc::now(),
            signature,
            comment,
        };

        group.current_authorizers.push(auth);

        // Check if quorum reached
        if group.current_authorizers.len() >= group.required_authorizers {
            group.status = ControlGroupStatus::Approved;
        }

        Ok(())
    }

    /// Deny control group
    pub async fn deny(&self, group_id: &str, user_id: String, reason: String) -> Result<()> {
        let mut groups = self.control_groups.write().await;
        let group = groups
            .get_mut(group_id)
            .ok_or_else(|| ControlGroupError::ControlGroupError("Group not found".to_string()))?;

        group.status = ControlGroupStatus::Denied;

        // Add authorization with denial
        let auth = Authorization {
            user_id,
            authorized_at: Utc::now(),
            signature: "DENIED".to_string(),
            comment: Some(reason),
        };

        group.current_authorizers.push(auth);

        Ok(())
    }

    /// Check authorization status
    pub async fn check_authorization(&self, group_id: &str) -> Result<ControlGroupStatus> {
        let groups = self.control_groups.read().await;
        let group = groups
            .get(group_id)
            .ok_or_else(|| ControlGroupError::ControlGroupError("Group not found".to_string()))?;

        // Check if expired
        if Utc::now() > group.expires_at && group.status == ControlGroupStatus::Pending {
            return Ok(ControlGroupStatus::Expired);
        }

        Ok(group.status.clone())
    }

    /// List pending control groups
    pub async fn list_pending(&self) -> Vec<ControlGroup> {
        let groups = self.control_groups.read().await;
        groups
            .values()
            .filter(|g| g.status == ControlGroupStatus::Pending && Utc::now() <= g.expires_at)
            .cloned()
            .collect()
    }

    /// List control groups for user
    pub async fn list_for_user(&self, user_id: &str) -> Vec<ControlGroup> {
        let groups = self.control_groups.read().await;
        groups
            .values()
            .filter(|g| g.requestor == user_id)
            .cloned()
            .collect()
    }

    /// Get control group
    pub async fn get_control_group(&self, group_id: &str) -> Option<ControlGroup> {
        let groups = self.control_groups.read().await;
        groups.get(group_id).cloned()
    }

    /// Expire old control groups
    pub async fn expire_old_groups(&self) -> usize {
        let mut groups = self.control_groups.write().await;
        let now = Utc::now();
        let mut expired_count = 0;

        for (_, group) in groups.iter_mut() {
            if group.status == ControlGroupStatus::Pending && now > group.expires_at {
                group.status = ControlGroupStatus::Expired;
                expired_count += 1;
            }
        }

        expired_count
    }

    /// Delete control group
    pub async fn delete_control_group(&self, group_id: &str) -> Result<()> {
        let mut groups = self.control_groups.write().await;
        groups
            .remove(group_id)
            .ok_or_else(|| ControlGroupError::ControlGroupError("Group not found".to_string()))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_config() -> ControlGroupConfig {
        ControlGroupConfig {
            required_authorizers: 2,
            timeout_seconds: 3600,
            allowed_authorizers: vec!["admin1".to_string(), "admin2".to_string()],
            auto_approve_paths: vec!["/public/".to_string()],
        }
    }

    #[tokio::test]
    async fn test_create_control_group() {
        let cg = EnhancedControlGroups::new(create_test_config());

        let mut request_data = HashMap::new();
        request_data.insert("secret".to_string(), "value".to_string());

        let group = cg
            .create_control_group(
                "/secret/data/production".to_string(),
                OperationType::Write,
                "user1".to_string(),
                request_data,
            )
            .await
            .unwrap();

        assert_eq!(group.status, ControlGroupStatus::Pending);
        assert_eq!(group.required_authorizers, 2);
        assert!(group.current_authorizers.is_empty());
    }

    #[tokio::test]
    async fn test_authorize_quorum() {
        let cg = EnhancedControlGroups::new(create_test_config());

        let group = cg
            .create_control_group(
                "/secret/data/production".to_string(),
                OperationType::Write,
                "user1".to_string(),
                HashMap::new(),
            )
            .await
            .unwrap();

        // First authorization
        cg.authorize(
            &group.group_id,
            "admin1".to_string(),
            "sig1".to_string(),
            None,
        )
        .await
        .unwrap();

        let status = cg.check_authorization(&group.group_id).await.unwrap();
        assert_eq!(status, ControlGroupStatus::Pending);

        // Second authorization (reaches quorum)
        cg.authorize(
            &group.group_id,
            "admin2".to_string(),
            "sig2".to_string(),
            None,
        )
        .await
        .unwrap();

        let status = cg.check_authorization(&group.group_id).await.unwrap();
        assert_eq!(status, ControlGroupStatus::Approved);
    }

    #[tokio::test]
    async fn test_deny() {
        let cg = EnhancedControlGroups::new(create_test_config());

        let group = cg
            .create_control_group(
                "/secret/data/production".to_string(),
                OperationType::Delete,
                "user1".to_string(),
                HashMap::new(),
            )
            .await
            .unwrap();

        cg.deny(
            &group.group_id,
            "admin1".to_string(),
            "Operation not allowed".to_string(),
        )
        .await
        .unwrap();

        let status = cg.check_authorization(&group.group_id).await.unwrap();
        assert_eq!(status, ControlGroupStatus::Denied);
    }

    #[tokio::test]
    async fn test_list_pending() {
        let cg = EnhancedControlGroups::new(create_test_config());

        cg.create_control_group(
            "/secret/data/prod1".to_string(),
            OperationType::Write,
            "user1".to_string(),
            HashMap::new(),
        )
        .await
        .unwrap();

        cg.create_control_group(
            "/secret/data/prod2".to_string(),
            OperationType::Write,
            "user2".to_string(),
            HashMap::new(),
        )
        .await
        .unwrap();

        let pending = cg.list_pending().await;
        assert_eq!(pending.len(), 2);
    }

    #[tokio::test]
    async fn test_expire_old_groups() {
        let mut config = create_test_config();
        config.timeout_seconds = 1; // 1 second expiry

        let cg = EnhancedControlGroups::new(config);

        cg.create_control_group(
            "/secret/data/production".to_string(),
            OperationType::Write,
            "user1".to_string(),
            HashMap::new(),
        )
        .await
        .unwrap();

        // Wait for expiry
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

        let expired_count = cg.expire_old_groups().await;
        assert_eq!(expired_count, 1);
    }
}
