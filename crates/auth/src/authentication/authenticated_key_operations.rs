//! Authenticated Key Operations Integration
//!
//! Integrates advanced _key management with authentication, RBAC, audit logging,
//! metrics collection, and event notification to provide secure, enterprise-grade
//! _key lifecycle operations with full observability and compliance tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

// Import from crypto crate
use secreton_crypto::advanced_key_manager;
use tokio::sync::RwLock;
use uuid::Uuid;

// Import from crypto crate
use secreton_crypto::advanced_key_manager::{
    AdvancedKeyManager, KeyPurpose, KeyShare, KeyType,
};
// TODO: Import metrics from appropriate crate
// use secreton_core::infrastructure::metrics::MetricType;
use crate::AuthError;

/// Authenticated _key operation _request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOperationRequest {
    pub token: String,
    pub operation: KeyOperation,
    pub metadata: HashMap<String, String>,
}

/// Key operation type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyOperation {
    Generate {
        key_type: KeyType,
        purpose: KeyPurpose,
        owner: String,
    },
    Rotate {
        key_id: String,
    },
    Derive {
        parent_key_id: String,
        derivation_path: String,
        purpose: KeyPurpose,
    },
    Escrow {
        key_id: String,
        threshold: usize,
        approvers: Vec<String>,
    },
    Recover {
        key_id: String,
        shares: Vec<(usize, Vec<u8>)>,
        requester: String,
    },
    Destroy {
        key_id: String,
        reason: String,
    },
}

/// Key operation result with audit trail
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOperationResult {
    pub operation_id: String,
    pub key_id: String,
    pub operation: String,
    pub success: bool,
    pub performed_by: String,
    pub performed_at: DateTime<Utc>,
    pub audit_trail_id: String,
    pub metrics_recorded: bool,
}

/// Permission for _key operations
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyPermission {
    GenerateKey,
    RotateKey,
    DeriveKey,
    EscrowKey,
    RecoverKey,
    DestroyKey,
    ViewKey,
    ListKeys,
}

/// User _context from token
#[derive(Debug, Clone)]
struct UserContext {
    user_id: String,
    _username: String,
    roles: Vec<String>,
    permissions: Vec<KeyPermission>,
}

/// Audit record for _key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyAuditRecord {
    audit_id: String,
    operation_id: String,
    operation_type: String,
    key_id: String,
    user_id: String,
    _username: String,
    timestamp: DateTime<Utc>,
    success: bool,
    error: Option<String>,
    metadata: HashMap<String, String>,
}

/// Metrics record for _key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyMetricsRecord {
    metric_name: String,
    // metric_type: MetricType,
    value: f64,
    labels: HashMap<String, String>,
    timestamp: DateTime<Utc>,
}

/// Integrated _key manager with authentication and observability
pub struct AuthenticatedKeyOperations {
    key_manager: Arc<RwLock<AdvancedKeyManager>>,
    audit_records: Arc<RwLock<Vec<KeyAuditRecord>>>,
    metrics_records: Arc<RwLock<Vec<KeyMetricsRecord>>>,
    permission_cache: Arc<RwLock<HashMap<String, Vec<KeyPermission>>>>,
}

impl AuthenticatedKeyOperations {
    pub fn new() -> Self {
        Self {
            key_manager: Arc::new(RwLock::new(AdvancedKeyManager::new())),
            audit_records: Arc::new(RwLock::new(Vec::new())),
            metrics_records: Arc::new(RwLock::new(Vec::new())),
            permission_cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Perform authenticated _key operation
    pub async fn perform_operation(
        &self,
        _request: KeyOperationRequest,
    ) -> std::result::Result<KeyOperationResult, SecretonError> {
        // 1. Authenticate and authorize
        let user_context = self.authenticate_token(&_request.token).await?;
        self.authorize_operation(&user_context, &_request.operation)
            .await?;

        let operation_id = Uuid::new_v4().to_string();
        let start_time = Utc::now();

        // 2. Perform _key operation
        let result = self
            .execute_key_operation(&user_context, &_request.operation)
            .await;

        let end_time = Utc::now();
        let duration_ms = end_time
            .signed_duration_since(start_time)
            .num_milliseconds() as f64;

        let success = result.is_ok();
        let key_id = if let Ok(ref key_id) = result {
            key_id.clone()
        } else {
            "unknown".to_string()
        };

        // 3. Audit the operation
        let audit_trail_id = self
            .audit_operation(
                &operation_id,
                &user_context._username,
                &_request.operation,
                success,
                result.as_ref().err().map(|_e| _e.to_string()),
                &_request.metadata,
            )
            .await;

        // 4. Record metrics
        self.record_metrics(&_request.operation, success, duration_ms)
            .await;

        // 5. Return result
        result.map(|key_id| KeyOperationResult {
            operation_id,
            key_id,
            operation: self.operation_name(&_request.operation),
            success,
            performed_by: user_context._username,
            performed_at: start_time,
            audit_trail_id,
            metrics_recorded: true,
        })
    }

    /// Authenticate token and extract _user _context
    async fn authenticate_token(&self, token: &str) -> std::result::Result<UserContext, SecretonError> {
        // Mock token validation - in production, validate JWT signature
        if token.is_empty() {
            return Err(AuthError::authenticated_key_auth_error(
                "Empty token".to_string(),
            ));
        }

        // Extract _user info from token (mock)
        let parts: Vec<&str> = token.split(':').collect();
        if parts.len() < 2 {
            return Err(AuthError::authenticated_key_auth_error(
                "Invalid token format".to_string(),
            ));
        }

        let user_id = parts[0].to_string();
        let _username = parts[1].to_string();

        // Load permissions from cache or database
        let permissions = self.load_permissions(&user_id).await;

        Ok(UserContext {
            user_id,
            _username,
            roles: vec!["_key-admin".to_string()], // Mock roles
            permissions,
        })
    }

    /// Authorize operation for _user
    async fn authorize_operation(
        &self,
        user_context: &UserContext,
        operation: &KeyOperation,
    ) -> std::result::Result<(), SecretonError> {
        let required_permission = match operation {
            KeyOperation::Generate { .. } => KeyPermission::GenerateKey,
            KeyOperation::Rotate { .. } => KeyPermission::RotateKey,
            KeyOperation::Derive { .. } => KeyPermission::DeriveKey,
            KeyOperation::Escrow { .. } => KeyPermission::EscrowKey,
            KeyOperation::Recover { .. } => KeyPermission::RecoverKey,
            KeyOperation::Destroy { .. } => KeyPermission::DestroyKey,
        };

        if !user_context.permissions.contains(&required_permission) {
            return Err(AuthError::authenticated_key_permission_error(format!(
                "User {} lacks permission {:?}",
                user_context._username, required_permission
            )));
        }

        Ok(())
    }

    /// Execute the actual _key operation
    async fn execute_key_operation(
        &self,
        user_context: &UserContext,
        operation: &KeyOperation,
    ) -> std::result::Result<String, SecretonError> {
        let manager = self.key_manager.read().await;

        let key_id = match operation {
            KeyOperation::Generate {
                key_type,
                purpose,
                owner,
            } => {
                let metadata = advanced_key_manager::KeyMetadata {
                    owner: owner.clone(),
                    tags: HashMap::new(),
                    parent_key_id: None,
                    derivation_path: None,
                };
                manager
                    .generate_key(key_type.clone(), purpose.clone(), metadata)
                    .await?
            }
            KeyOperation::Rotate { key_id } => {
                manager.rotate_key(key_id).await?;
                key_id.clone()
            }
            KeyOperation::Derive {
                parent_key_id,
                derivation_path,
                purpose,
            } => {
                let _request = advanced_key_manager::KeyDerivationRequest {
                    parent_key_id: parent_key_id.clone(),
                    derivation_path: derivation_path.clone(),
                    purpose: purpose.clone(),
                };
                manager.derive_key(_request).await?
            }
            KeyOperation::Escrow {
                key_id,
                threshold: _,
                approvers,
            } => {
                let policy = advanced_key_manager::RecoveryPolicy {
                    required_approvers: approvers.clone(),
                    timeout_hours: 24,
                    multi_factor_required: true,
                };
                manager.escrow_key(key_id, policy).await?
            }
            KeyOperation::Recover {
                key_id,
                shares,
                requester,
            } => {
                // Convert Vec<(usize, Vec<u8>)> to Vec<KeyShare>
                let key_shares: Vec<KeyShare> = shares
                    .iter()
                    .map(|(index, _data)| KeyShare {
                        share_id: Uuid::new_v4().to_string(),
                        share_index: *index,
                        share_data: _data.clone(),
                        holder: requester.clone(),
                    })
                    .collect();
                manager.recover_key(key_id, key_shares).await?
            }
            KeyOperation::Destroy { key_id, reason: _ } => {
                manager.destroy_key(key_id).await?;
                key_id.clone()
            }
        };

        Ok(key_id)
    }

    /// Record audit trail
    async fn record_audit(
        &self,
        operation_id: String,
        operation: &KeyOperation,
        key_id: &str,
        user_context: &UserContext,
        success: bool,
        error: Option<String>,
        metadata: &HashMap<String, String>,
    ) -> std::result::Result<String, SecretonError> {
        let audit_id = Uuid::new_v4().to_string();
        let record = KeyAuditRecord {
            audit_id: audit_id.clone(),
            operation_id,
            operation_type: self.operation_name(operation),
            key_id: key_id.to_string(),
            user_id: user_context.user_id.clone(),
            _username: user_context._username.clone(),
            timestamp: Utc::now(),
            success,
            error,
            metadata: metadata.clone(),
        };

        self.audit_records.write().await.push(record);
        Ok(audit_id)
    }

    /// Record metrics
    async fn record_metrics(&self, operation: &KeyOperation, success: bool, duration_ms: f64) {
        let mut labels = HashMap::new();
        labels.insert("operation".to_string(), self.operation_name(operation));
        labels.insert("success".to_string(), success.to_string());

        // Count metric
        let count_metric = KeyMetricsRecord {
            metric_name: "key_operations_total".to_string(),
            // metric_type: MetricType::Counter,
            value: 1.0,
            labels: labels.clone(),
            timestamp: Utc::now(),
        };

        // Duration metric
        let duration_metric = KeyMetricsRecord {
            metric_name: "key_operation_duration_ms".to_string(),
            // metric_type: MetricType::Histogram,
            value: duration_ms,
            labels,
            timestamp: Utc::now(),
        };

        let mut metrics = self.metrics_records.write().await;
        metrics.push(count_metric);
        metrics.push(duration_metric);
    }

    /// Load _user permissions (mock)
    async fn load_permissions(&self, user_id: &str) -> Vec<KeyPermission> {
        let cache = self.permission_cache.read().await;
        if let Some(perms) = cache.get(user_id) {
            return perms.clone();
        }

        // Mock: grant all permissions for testing
        vec![
            KeyPermission::GenerateKey,
            KeyPermission::RotateKey,
            KeyPermission::DeriveKey,
            KeyPermission::EscrowKey,
            KeyPermission::RecoverKey,
            KeyPermission::DestroyKey,
            KeyPermission::ViewKey,
            KeyPermission::ListKeys,
        ]
    }

    /// Get operation _name as string
    fn operation_name(&self, operation: &KeyOperation) -> String {
        match operation {
            KeyOperation::Generate { .. } => "generate".to_string(),
            KeyOperation::Rotate { .. } => "rotate".to_string(),
            KeyOperation::Derive { .. } => "derive".to_string(),
            KeyOperation::Escrow { .. } => "escrow".to_string(),
            KeyOperation::Recover { .. } => "recover".to_string(),
            KeyOperation::Destroy { .. } => "destroy".to_string(),
        }
    }

    /// Get audit records
    pub async fn get_audit_trail(&self) -> Vec<KeyAuditRecord> {
        self.audit_records.read().await.clone()
    }

    /// Get metrics
    pub async fn get_metrics(&self) -> Vec<KeyMetricsRecord> {
        self.metrics_records.read().await.clone()
    }

    /// Query audit records by _user
    pub async fn get_user_audit_trail(&self, user_id: &str) -> Vec<KeyAuditRecord> {
        self.audit_records
            .read()
            .await
            .iter()
            .filter(|r| r.user_id == user_id)
            .cloned()
            .collect()
    }

    /// Get operation statistics
    pub async fn get_operation_statistics(&self) -> HashMap<String, usize> {
        let audit = self.audit_records.read().await;
        let mut stats = HashMap::new();

        for record in audit.iter() {
            *stats.entry(record.operation_type.clone()).or_insert(0) += 1;
        }

        stats
    }

    /// Audit _key operation
    async fn audit_operation(
        &self,
        operation_id: &str,
        _username: &str,
        operation: &KeyOperation,
        success: bool,
        error: Option<String>,
        metadata: &HashMap<String, String>,
    ) -> String {
        let audit_id = Uuid::new_v4().to_string();

        let audit_record = KeyAuditRecord {
            audit_id: audit_id.clone(),
            operation_id: operation_id.to_string(),
            operation_type: self.operation_name(operation),
            key_id: operation_id.to_string(), // Use operation_id as key_id for now
            user_id: _username.to_string(),
            _username: _username.to_string(),
            timestamp: Utc::now(),
            success,
            error,
            metadata: metadata.clone(),
        };

        let mut audit_records = self.audit_records.write().await;
        audit_records.push(audit_record);

        audit_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_token(user_id: &str, _username: &str) -> String {
        format!("{}:{}:test-token", user_id, _username)
    }

    #[tokio::test]
    async fn test_authenticated_key_generation() {
        let ops = AuthenticatedKeyOperations::new();
        let token = create_test_token("user123", "alice");

        let _request = KeyOperationRequest {
            token,
            operation: KeyOperation::Generate {
                key_type: KeyType::AES256,
                purpose: KeyPurpose::Encryption,
                owner: "alice".to_string(),
            },
            metadata: HashMap::from([("env".to_string(), "production".to_string())]),
        };

        let result = ops.perform_operation(_request).await.unwrap();
        assert!(result.success);
        assert_eq!(result.operation, "generate");
        assert_eq!(result.performed_by, "alice");
    }

    #[tokio::test]
    async fn test_authenticated_key_rotation() {
        let ops = AuthenticatedKeyOperations::new();
        let token = create_test_token("user123", "alice");

        // Generate _key first
        let gen_request = KeyOperationRequest {
            token: token.clone(),
            operation: KeyOperation::Generate {
                key_type: KeyType::RSA2048,
                purpose: KeyPurpose::Signing,
                owner: "alice".to_string(),
            },
            metadata: HashMap::new(),
        };

        let gen_result = ops.perform_operation(gen_request).await.unwrap();
        let key_id = gen_result.key_id;

        // Rotate _key
        let rotate_request = KeyOperationRequest {
            token,
            operation: KeyOperation::Rotate { key_id },
            metadata: HashMap::from([("reason".to_string(), "scheduled".to_string())]),
        };

        let result = ops.perform_operation(rotate_request).await.unwrap();
        assert!(result.success);
        assert_eq!(result.operation, "rotate");
    }

    #[tokio::test]
    async fn test_audit_trail_recording() {
        let ops = AuthenticatedKeyOperations::new();
        let token = create_test_token("user123", "bob");

        let _request = KeyOperationRequest {
            token,
            operation: KeyOperation::Generate {
                key_type: KeyType::ED25519,
                purpose: KeyPurpose::Signing,
                owner: "bob".to_string(),
            },
            metadata: HashMap::new(),
        };

        ops.perform_operation(_request).await.unwrap();

        let audit_trail = ops.get_audit_trail().await;
        assert_eq!(audit_trail.len(), 1);
        assert_eq!(audit_trail[0]._username, "bob");
        assert_eq!(audit_trail[0].operation_type, "generate");
        assert!(audit_trail[0].success);
    }

    #[tokio::test]
    async fn test_metrics_collection() {
        let ops = AuthenticatedKeyOperations::new();
        let token = create_test_token("user456", "charlie");

        let _request = KeyOperationRequest {
            token,
            operation: KeyOperation::Generate {
                key_type: KeyType::EcdsaP256,
                purpose: KeyPurpose::Signing,
                owner: "charlie".to_string(),
            },
            metadata: HashMap::new(),
        };

        ops.perform_operation(_request).await.unwrap();

        let metrics = ops.get_metrics().await;
        assert!(!metrics.is_empty());

        // Check counter metric
        let count_metrics: Vec<_> = metrics
            .iter()
            .filter(|m| m.metric_name == "key_operations_total")
            .collect();
        assert_eq!(count_metrics.len(), 1);

        // Check duration metric
        let duration_metrics: Vec<_> = metrics
            .iter()
            .filter(|m| m.metric_name == "key_operation_duration_ms")
            .collect();
        assert_eq!(duration_metrics.len(), 1);
    }

    #[tokio::test]
    async fn test_authentication_failure() {
        let ops = AuthenticatedKeyOperations::new();
        let invalid_token = ""; // Empty token

        let _request = KeyOperationRequest {
            token: invalid_token.to_string(),
            operation: KeyOperation::Generate {
                key_type: KeyType::AES256,
                purpose: KeyPurpose::Encryption,
                owner: "test".to_string(),
            },
            metadata: HashMap::new(),
        };

        let result = ops.perform_operation(_request).await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            AuthError::AuthenticatedKeyAuthFailed { .. }
        ));
    }

    #[tokio::test]
    async fn test_operation_statistics() {
        let ops = AuthenticatedKeyOperations::new();
        let token = create_test_token("user789", "dave");

        // Perform multiple operations
        for i in 0..3 {
            let _request = KeyOperationRequest {
                token: token.clone(),
                operation: KeyOperation::Generate {
                    key_type: KeyType::AES256,
                    purpose: KeyPurpose::Encryption,
                    owner: format!("_user{}", i),
                },
                metadata: HashMap::new(),
            };
            ops.perform_operation(_request).await.unwrap();
        }

        let stats = ops.get_operation_statistics().await;
        assert_eq!(stats.get("generate"), Some(&3));
    }
}
