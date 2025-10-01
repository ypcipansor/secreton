//! Control Groups Module - Multi-person authorization system
//!
//! Control Groups provide multi-person authorization for sensitive operations.
//! They allow requiring multiple users to approve certain operations before they can be executed.

use crate::{storage::StorageEngine, AppError};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Control Group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupConfig {
    /// Maximum time to live for control group requests
    pub max_ttl: Duration,
    /// Number of required authorizations
    pub required_authorizations: u32,
    /// Authorization timeout
    pub authorization_timeout: Duration,
    /// Allowed authorization methods
    pub allowed_methods: Vec<String>,
}

/// Control Group request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlGroupRequest {
    pub id: Uuid,
    /// The operation that requires authorization
    pub operation: String,
    /// Parameters for the operation
    pub parameters: Value,
    /// Users who can authorize this request
    pub authorized_users: Vec<String>,
    /// Users who have already authorized
    pub authorizing_users: Vec<String>,
    /// When the request was created
    pub created_at: DateTime<Utc>,
    /// When the request expires
    pub expires_at: DateTime<Utc>,
    /// Current status of the request
    pub status: ControlGroupStatus,
    /// Request metadata
    pub metadata: HashMap<String, String>,
}

/// Control Group status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ControlGroupStatus {
    /// Request is pending authorization
    Pending,
    /// Request has been authorized
    Authorized,
    /// Request has been denied
    Denied,
    /// Request has expired
    Expired,
    /// Request was cancelled
    Cancelled,
}

/// Authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    pub request_id: Uuid,
    pub authorizing_user: String,
    pub authorization_token: String,
    pub approved: bool,
    pub reason: Option<String>,
}

/// Authorization response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationResponse {
    pub request_id: Uuid,
    pub approved: bool,
    pub authorized: bool,
    pub reason: Option<String>,
    pub remaining_authorizations: u32,
}

/// Control Group Manager
pub struct ControlGroupManager {
    storage: Arc<dyn StorageEngine>,
    requests: Arc<RwLock<HashMap<Uuid, ControlGroupRequest>>>,
    config: ControlGroupConfig,
}

impl ControlGroupManager {
    pub fn new(storage: Arc<dyn StorageEngine>, config: ControlGroupConfig) -> Self {
        Self {
            storage,
            requests: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create a new control group request
    pub async fn create_request(
        &self,
        operation: String,
        parameters: Value,
        authorized_users: Vec<String>,
        metadata: HashMap<String, String>,
    ) -> Result<ControlGroupRequest, AppError> {
        let now = Utc::now();
        let expires_at = now + self.config.authorization_timeout;

        let request = ControlGroupRequest {
            id: Uuid::new_v4(),
            operation,
            parameters,
            authorized_users,
            authorizing_users: Vec::new(),
            created_at: now,
            expires_at,
            status: ControlGroupStatus::Pending,
            metadata,
        };

        // Store the request
        let mut requests = self.requests.write().await;
        requests.insert(request.id, request.clone());

        // Persist to storage
        let request_key = format!("control_groups/requests/{}", request.id);
        let request_data = serde_json::to_vec(&request)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize request: {}", e)))?;

        let entry = crate::storage::StorageEntry {
            key: request_key,
            value: request_data,
            metadata: HashMap::new(),
        };

        self.storage
            .put(entry)
            .await
            .map_err(|e| AppError::InternalError(format!("Failed to store request: {}", e)))?;

        Ok(request)
    }

    /// Authorize a control group request
    pub async fn authorize_request(
        &self,
        request_id: Uuid,
        authorizing_user: String,
        approved: bool,
        reason: Option<String>,
    ) -> Result<AuthorizationResponse, AppError> {
        let mut requests = self.requests.write().await;

        let request = requests
            .get_mut(&request_id)
            .ok_or_else(|| AppError::NotFound(format!("Request {} not found", request_id)))?;

        // Check if request is still valid
        if Utc::now() > request.expires_at {
            request.status = ControlGroupStatus::Expired;
            return Err(AppError::BadRequest("Request has expired".to_string()));
        }

        if request.status != ControlGroupStatus::Pending {
            return Err(AppError::BadRequest(format!(
                "Request is already {}",
                match request.status {
                    ControlGroupStatus::Authorized => "authorized",
                    ControlGroupStatus::Denied => "denied",
                    ControlGroupStatus::Expired => "expired",
                    ControlGroupStatus::Cancelled => "cancelled",
                    _ => "processed",
                }
            )));
        }

        // Check if user is authorized to approve this request
        if !request.authorized_users.contains(&authorizing_user) {
            return Err(AppError::PermissionDenied(
                "User is not authorized to approve this request".to_string(),
            ));
        }

        // Check if user has already authorized
        if request.authorizing_users.contains(&authorizing_user) {
            return Err(AppError::BadRequest(
                "User has already authorized this request".to_string(),
            ));
        }

        // Record the authorization
        request.authorizing_users.push(authorizing_user.clone());

        let remaining = self.config.required_authorizations - request.authorizing_users.len() as u32;

        if approved {
            if request.authorizing_users.len() >= self.config.required_authorizations as usize {
                request.status = ControlGroupStatus::Authorized;
            }
        } else {
            request.status = ControlGroupStatus::Denied;
        }

        // Update storage
        let request_key = format!("control_groups/requests/{}", request_id);
        let request_data = serde_json::to_vec(request)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize request: {}", e)))?;

        let entry = crate::storage::StorageEntry {
            key: request_key,
            value: request_data,
            metadata: HashMap::new(),
        };

        self.storage
            .put(entry)
            .await
            .map_err(|e| AppError::InternalError(format!("Failed to update request: {}", e)))?;

        Ok(AuthorizationResponse {
            request_id,
            approved,
            authorized: request.status == ControlGroupStatus::Authorized,
            reason,
            remaining_authorizations: remaining.max(0),
        })
    }

    /// Get a control group request by ID
    pub async fn get_request(&self, request_id: Uuid) -> Result<Option<ControlGroupRequest>, AppError> {
        let requests = self.requests.read().await;
        Ok(requests.get(&request_id).cloned())
    }

    /// List control group requests with optional filtering
    pub async fn list_requests(
        &self,
        status_filter: Option<ControlGroupStatus>,
        user_filter: Option<String>,
    ) -> Result<Vec<ControlGroupRequest>, AppError> {
        let requests = self.requests.read().await;
        let mut filtered_requests: Vec<ControlGroupRequest> = requests
            .values()
            .filter(|req| {
                // Filter by status if provided
                if let Some(status) = &status_filter {
                    if req.status != *status {
                        return false;
                    }
                }

                // Filter by user if provided
                if let Some(user) = &user_filter {
                    if !req.authorized_users.contains(user) && !req.authorizing_users.contains(user) {
                        return false;
                    }
                }

                true
            })
            .cloned()
            .collect();

        // Sort by creation time (newest first)
        filtered_requests.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        Ok(filtered_requests)
    }

    /// Cancel a control group request
    pub async fn cancel_request(&self, request_id: Uuid, user: String) -> Result<(), AppError> {
        let mut requests = self.requests.write().await;

        let request = requests
            .get_mut(&request_id)
            .ok_or_else(|| AppError::NotFound(format!("Request {} not found", request_id)))?;

        // Check if user is authorized to cancel
        if !request.authorized_users.contains(&user) {
            return Err(AppError::PermissionDenied(
                "User is not authorized to cancel this request".to_string(),
            ));
        }

        if request.status != ControlGroupStatus::Pending {
            return Err(AppError::BadRequest("Cannot cancel non-pending request".to_string()));
        }

        request.status = ControlGroupStatus::Cancelled;

        // Update storage
        let request_key = format!("control_groups/requests/{}", request_id);
        let request_data = serde_json::to_vec(request)
            .map_err(|e| AppError::InternalError(format!("Failed to serialize request: {}", e)))?;

        let entry = crate::storage::StorageEntry {
            key: request_key,
            value: request_data,
            metadata: HashMap::new(),
        };

        self.storage
            .put(entry)
            .await
            .map_err(|e| AppError::InternalError(format!("Failed to update request: {}", e)))?;

        Ok(())
    }

    /// Clean up expired requests
    pub async fn cleanup_expired_requests(&self) -> Result<usize, AppError> {
        let mut requests = self.requests.write().await;
        let now = Utc::now();
        let mut expired_count = 0;

        let expired_requests: Vec<Uuid> = requests
            .iter()
            .filter(|(_, req)| {
                req.status == ControlGroupStatus::Pending && now > req.expires_at
            })
            .map(|(id, _)| *id)
            .collect();

        for request_id in expired_requests {
            if let Some(request) = requests.get_mut(&request_id) {
                request.status = ControlGroupStatus::Expired;
                expired_count += 1;

                // Update storage
                let request_key = format!("control_groups/requests/{}", request_id);
                let request_data = serde_json::to_vec(request)
                    .map_err(|e| AppError::InternalError(format!("Failed to serialize request: {}", e)))?;

                let entry = crate::storage::StorageEntry {
                    key: request_key,
                    value: request_data,
                    metadata: HashMap::new(),
                };

                let _ = self.storage.put(entry).await; // Ignore errors for cleanup
            }
        }

        Ok(expired_count)
    }
}

/// Control Group middleware for protecting operations
pub struct ControlGroupMiddleware {
    manager: Arc<ControlGroupManager>,
}

impl ControlGroupMiddleware {
    pub fn new(manager: Arc<ControlGroupManager>) -> Self {
        Self { manager }
    }

    /// Check if an operation requires control group authorization
    pub async fn requires_authorization(
        &self,
        operation: &str,
        user: &str,
        parameters: Value,
    ) -> Result<Option<ControlGroupRequest>, AppError> {
        // In a real implementation, this would check policies to determine
        // if an operation requires control group authorization

        // For now, we'll implement a simple check - operations that affect
        // critical systems or high-value secrets require authorization

        let critical_operations = vec![
            "delete_secret",
            "rotate_key",
            "revoke_certificate",
            "create_backup",
            "restore_backup",
        ];

        if critical_operations.contains(&operation) {
            // Create a control group request
            let authorized_users = vec![
                "admin".to_string(),
                "security_officer".to_string(),
                "backup_admin".to_string(),
            ];

            let mut metadata = HashMap::new();
            metadata.insert("operation".to_string(), operation.to_string());
            metadata.insert("user".to_string(), user.to_string());

            let request = self.manager.create_request(
                operation.to_string(),
                parameters,
                authorized_users,
                metadata,
            ).await?;

            Ok(Some(request))
        } else {
            Ok(None)
        }
    }

    /// Execute an operation after control group authorization
    pub async fn execute_authorized_operation(
        &self,
        request_id: Uuid,
        operation: String,
        parameters: Value,
    ) -> Result<Value, AppError> {
        let request = self.manager.get_request(request_id).await?
            .ok_or_else(|| AppError::NotFound(format!("Request {} not found", request_id)))?;

        if request.status != ControlGroupStatus::Authorized {
            return Err(AppError::PermissionDenied(
                "Operation has not been authorized by control group".to_string(),
            ));
        }

        // Execute the operation (this would call the appropriate service)
        // For now, we'll just return a success message
        Ok(serde_json::json!({
            "status": "success",
            "operation": operation,
            "request_id": request_id,
            "authorized_by": request.authorizing_users,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::StorageEntry;

    #[derive(Debug)]
    struct TestStorageEngine {
        data: Arc<std::sync::RwLock<HashMap<String, StorageEntry>>>,
    }

    #[async_trait::async_trait]
    impl StorageEngine for TestStorageEngine {
        async fn get(&self, key: &str) -> Result<Option<StorageEntry>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data.get(key).cloned())
        }

        async fn put(&self, entry: StorageEntry) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.insert(entry.key.clone(), entry);
            Ok(())
        }

        async fn delete(&self, key: &str) -> Result<(), crate::error::CoreError> {
            let mut data = self.data.write().unwrap();
            data.remove(key);
            Ok(())
        }

        async fn list(&self, prefix: &str) -> Result<Vec<String>, crate::error::CoreError> {
            let data = self.data.read().unwrap();
            Ok(data
                .keys()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    async fn create_test_manager() -> ControlGroupManager {
        let storage: Arc<dyn StorageEngine> = Arc::new(TestStorageEngine {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
        });

        let config = ControlGroupConfig {
            max_ttl: Duration::from_secs(3600),
            required_authorizations: 2,
            authorization_timeout: Duration::from_secs(300),
            allowed_methods: vec!["approve".to_string(), "deny".to_string()],
        };

        ControlGroupManager::new(storage, config)
    }

    #[tokio::test]
    async fn test_create_control_group_request() {
        let manager = create_test_manager().await;

        let operation = "delete_secret".to_string();
        let parameters = serde_json::json!({"path": "/secret/critical"});
        let authorized_users = vec!["admin".to_string(), "security_officer".to_string()];
        let metadata = HashMap::new();

        let request = manager.create_request(operation, parameters, authorized_users, metadata).await.unwrap();

        assert_eq!(request.operation, "delete_secret");
        assert_eq!(request.authorized_users.len(), 2);
        assert_eq!(request.status, ControlGroupStatus::Pending);
    }

    #[tokio::test]
    async fn test_authorize_request() {
        let manager = create_test_manager().await;

        // Create a request
        let operation = "delete_secret".to_string();
        let parameters = serde_json::json!({"path": "/secret/critical"});
        let authorized_users = vec!["admin".to_string(), "security_officer".to_string()];
        let metadata = HashMap::new();

        let request = manager.create_request(operation, parameters, authorized_users, metadata).await.unwrap();

        // First authorization
        let response = manager.authorize_request(
            request.id,
            "admin".to_string(),
            true,
            Some("Approved for security audit".to_string()),
        ).await.unwrap();

        assert!(response.approved);
        assert!(!response.authorized); // Still needs one more authorization
        assert_eq!(response.remaining_authorizations, 1);

        // Second authorization
        let response = manager.authorize_request(
            request.id,
            "security_officer".to_string(),
            true,
            Some("Approved for compliance".to_string()),
        ).await.unwrap();

        assert!(response.approved);
        assert!(response.authorized); // Now fully authorized
        assert_eq!(response.remaining_authorizations, 0);
    }

    #[tokio::test]
    async fn test_deny_request() {
        let manager = create_test_manager().await;

        // Create a request
        let operation = "delete_secret".to_string();
        let parameters = serde_json::json!({"path": "/secret/critical"});
        let authorized_users = vec!["admin".to_string(), "security_officer".to_string()];
        let metadata = HashMap::new();

        let request = manager.create_request(operation, parameters, authorized_users, metadata).await.unwrap();

        // Deny the request
        let response = manager.authorize_request(
            request.id,
            "admin".to_string(),
            false,
            Some("Security risk too high".to_string()),
        ).await.unwrap();

        assert!(!response.approved);
        assert!(!response.authorized);
    }

    #[tokio::test]
    async fn test_unauthorized_user() {
        let manager = create_test_manager().await;

        // Create a request
        let operation = "delete_secret".to_string();
        let parameters = serde_json::json!({"path": "/secret/critical"});
        let authorized_users = vec!["admin".to_string()];
        let metadata = HashMap::new();

        let request = manager.create_request(operation, parameters, authorized_users, metadata).await.unwrap();

        // Try to authorize with unauthorized user
        let result = manager.authorize_request(
            request.id,
            "unauthorized_user".to_string(),
            true,
            None,
        ).await;

        assert!(result.is_err());
    }
}
