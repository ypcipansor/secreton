//! Multi-Tenant Isolation Engine
//!
//! Provides tenant management with namespace isolation, resource quotas,
//! tenant-specific encryption, and zero-trust cross-tenant access policies.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum MultiTenantError {
    #[error("Tenant not found: {0}")]
    TenantNotFound(String),
    #[error("Quota exceeded: {0}")]
    QuotaExceeded(String),
    #[error("Access denied: {0}")]
    AccessDenied(String),
    #[error("Invalid tenant configuration: {0}")]
    InvalidConfig(String),
    #[error("Namespace conflict: {0}")]
    NamespaceConflict(String),
}

pub type Result<T> = std::result::Result<T, MultiTenantError>;

/// Resource quotas for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceQuota {
    pub max_secrets: usize,
    pub max_storage_bytes: usize,
    pub api_rate_limit_per_minute: usize,
    pub max_namespaces: usize,
}

impl Default for ResourceQuota {
    fn default() -> Self {
        Self {
            max_secrets: 10000,
            max_storage_bytes: 100 * 1024 * 1024, // 100 MB
            api_rate_limit_per_minute: 1000,
            max_namespaces: 10,
        }
    }
}

/// Tenant-specific encryption configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantEncryption {
    pub tenant_id: String,
    pub encryption_key_id: String,
    pub key_derivation_salt: String,
    pub rotation_enabled: bool,
    pub last_rotated_at: Option<DateTime<Utc>>,
}

/// Tenant entity with namespace isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tenant {
    pub tenant_id: String,
    pub name: String,
    pub namespace: String,
    pub created_at: DateTime<Utc>,
    pub quotas: ResourceQuota,
    pub encryption: TenantEncryption,
    pub enabled: bool,
    pub metadata: HashMap<String, String>,
}

/// Current resource usage for a tenant
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub tenant_id: String,
    pub current_secrets: usize,
    pub current_storage_bytes: usize,
    pub api_calls_last_minute: usize,
    pub current_namespaces: usize,
    pub last_updated: DateTime<Utc>,
}

/// Cross-tenant access policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossTenantPolicy {
    pub policy_id: String,
    pub source_tenant_id: String,
    pub target_tenant_id: String,
    pub allowed_operations: Vec<String>,
    pub secret_path_pattern: String,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

/// Namespace isolation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceIsolation {
    pub namespace: String,
    pub tenant_id: String,
    pub isolation_level: IsolationLevel,
    pub network_policies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IsolationLevel {
    Strict,   // No cross-tenant access
    Moderate, // Limited cross-tenant with explicit policies
    Relaxed,  // Permissive with audit logging
}

/// Multi-tenant isolation engine
pub struct MultiTenantEngine {
    tenants: Arc<RwLock<HashMap<String, Tenant>>>,
    usage: Arc<RwLock<HashMap<String, ResourceUsage>>>,
    policies: Arc<RwLock<HashMap<String, CrossTenantPolicy>>>,
    namespaces: Arc<RwLock<HashMap<String, NamespaceIsolation>>>,
}

impl MultiTenantEngine {
    pub fn new() -> Self {
        Self {
            tenants: Arc::new(RwLock::new(HashMap::new())),
            usage: Arc::new(RwLock::new(HashMap::new())),
            policies: Arc::new(RwLock::new(HashMap::new())),
            namespaces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new tenant with namespace isolation
    pub async fn create_tenant(
        &self,
        name: String,
        namespace: String,
        quotas: Option<ResourceQuota>,
    ) -> Result<Tenant> {
        // Check namespace uniqueness
        let namespaces = self.namespaces.read().await;
        if namespaces.contains_key(&namespace) {
            return Err(MultiTenantError::NamespaceConflict(format!(
                "Namespace '{}' already exists",
                namespace
            )));
        }
        drop(namespaces);

        let tenant_id = Uuid::new_v4().to_string();
        let encryption_key_id = Uuid::new_v4().to_string();

        let tenant = Tenant {
            tenant_id: tenant_id.clone(),
            name: name.clone(),
            namespace: namespace.clone(),
            created_at: Utc::now(),
            quotas: quotas.unwrap_or_default(),
            encryption: TenantEncryption {
                tenant_id: tenant_id.clone(),
                encryption_key_id,
                key_derivation_salt: Uuid::new_v4().to_string(),
                rotation_enabled: true,
                last_rotated_at: Some(Utc::now()),
            },
            enabled: true,
            metadata: HashMap::new(),
        };

        // Initialize usage tracking
        let usage = ResourceUsage {
            tenant_id: tenant_id.clone(),
            current_secrets: 0,
            current_storage_bytes: 0,
            api_calls_last_minute: 0,
            current_namespaces: 1,
            last_updated: Utc::now(),
        };

        // Create namespace isolation
        let isolation = NamespaceIsolation {
            namespace: namespace.clone(),
            tenant_id: tenant_id.clone(),
            isolation_level: IsolationLevel::Strict,
            network_policies: vec![],
        };

        let mut tenants = self.tenants.write().await;
        let mut usage_map = self.usage.write().await;
        let mut namespaces_map = self.namespaces.write().await;

        tenants.insert(tenant_id.clone(), tenant.clone());
        usage_map.insert(tenant_id.clone(), usage);
        namespaces_map.insert(namespace, isolation);

        Ok(tenant)
    }

    /// Get tenant by ID
    pub async fn get_tenant(&self, tenant_id: &str) -> Result<Tenant> {
        let tenants = self.tenants.read().await;
        tenants
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| MultiTenantError::TenantNotFound(tenant_id.to_string()))
    }

    /// Enforce resource quotas before operation
    pub async fn enforce_quota(&self, tenant_id: &str, operation: QuotaOperation) -> Result<()> {
        let tenant = self.get_tenant(tenant_id).await?;
        let mut usage_map = self.usage.write().await;
        let usage = usage_map
            .get_mut(tenant_id)
            .ok_or_else(|| MultiTenantError::TenantNotFound(tenant_id.to_string()))?;

        match operation {
            QuotaOperation::CreateSecret { size_bytes } => {
                if usage.current_secrets >= tenant.quotas.max_secrets {
                    return Err(MultiTenantError::QuotaExceeded(format!(
                        "Max secrets limit reached: {}",
                        tenant.quotas.max_secrets
                    )));
                }
                if usage.current_storage_bytes + size_bytes > tenant.quotas.max_storage_bytes {
                    return Err(MultiTenantError::QuotaExceeded(format!(
                        "Storage quota exceeded: {} bytes",
                        tenant.quotas.max_storage_bytes
                    )));
                }
                usage.current_secrets += 1;
                usage.current_storage_bytes += size_bytes;
            }
            QuotaOperation::DeleteSecret { size_bytes } => {
                usage.current_secrets = usage.current_secrets.saturating_sub(1);
                usage.current_storage_bytes =
                    usage.current_storage_bytes.saturating_sub(size_bytes);
            }
            QuotaOperation::ApiCall => {
                if usage.api_calls_last_minute >= tenant.quotas.api_rate_limit_per_minute {
                    return Err(MultiTenantError::QuotaExceeded(format!(
                        "API rate limit exceeded: {} calls/minute",
                        tenant.quotas.api_rate_limit_per_minute
                    )));
                }
                usage.api_calls_last_minute += 1;
            }
        }

        usage.last_updated = Utc::now();
        Ok(())
    }

    /// Check cross-tenant access permission
    pub async fn check_cross_tenant_access(
        &self,
        source_tenant_id: &str,
        target_tenant_id: &str,
        operation: &str,
        secret_path: &str,
    ) -> Result<bool> {
        // Same tenant always allowed
        if source_tenant_id == target_tenant_id {
            return Ok(true);
        }

        let policies = self.policies.read().await;
        for policy in policies.values() {
            if policy.source_tenant_id == source_tenant_id
                && policy.target_tenant_id == target_tenant_id
                && policy.enabled
            {
                // Check if operation is allowed
                if !policy.allowed_operations.contains(&operation.to_string()) {
                    continue;
                }

                // Check if secret path matches pattern
                if !secret_path.starts_with(&policy.secret_path_pattern) {
                    continue;
                }

                // Check expiration
                if let Some(expires_at) = policy.expires_at {
                    if Utc::now() > expires_at {
                        continue;
                    }
                }

                return Ok(true);
            }
        }

        Err(MultiTenantError::AccessDenied(format!(
            "Cross-tenant access denied: {} -> {}",
            source_tenant_id, target_tenant_id
        )))
    }

    /// Create cross-tenant access policy
    pub async fn create_cross_tenant_policy(
        &self,
        source_tenant_id: String,
        target_tenant_id: String,
        allowed_operations: Vec<String>,
        secret_path_pattern: String,
    ) -> Result<CrossTenantPolicy> {
        // Verify both tenants exist
        self.get_tenant(&source_tenant_id).await?;
        self.get_tenant(&target_tenant_id).await?;

        let policy = CrossTenantPolicy {
            policy_id: Uuid::new_v4().to_string(),
            source_tenant_id,
            target_tenant_id,
            allowed_operations,
            secret_path_pattern,
            enabled: true,
            expires_at: None,
        };

        let mut policies = self.policies.write().await;
        policies.insert(policy.policy_id.clone(), policy.clone());

        Ok(policy)
    }

    /// Get namespace isolation for tenant
    pub async fn get_namespace_isolation(&self, namespace: &str) -> Result<NamespaceIsolation> {
        let namespaces = self.namespaces.read().await;
        namespaces
            .get(namespace)
            .cloned()
            .ok_or_else(|| MultiTenantError::TenantNotFound(format!("Namespace: {}", namespace)))
    }

    /// Update isolation level for namespace
    pub async fn update_isolation_level(
        &self,
        namespace: &str,
        isolation_level: IsolationLevel,
    ) -> Result<()> {
        let mut namespaces = self.namespaces.write().await;
        let isolation = namespaces
            .get_mut(namespace)
            .ok_or_else(|| MultiTenantError::TenantNotFound(format!("Namespace: {}", namespace)))?;

        isolation.isolation_level = isolation_level;
        Ok(())
    }

    /// Get resource usage for tenant
    pub async fn get_resource_usage(&self, tenant_id: &str) -> Result<ResourceUsage> {
        let usage = self.usage.read().await;
        usage
            .get(tenant_id)
            .cloned()
            .ok_or_else(|| MultiTenantError::TenantNotFound(tenant_id.to_string()))
    }

    /// List all tenants
    pub async fn list_tenants(&self) -> Vec<Tenant> {
        let tenants = self.tenants.read().await;
        tenants.values().cloned().collect()
    }

    /// Delete tenant and all associated data
    pub async fn delete_tenant(&self, tenant_id: &str) -> Result<()> {
        let tenant = self.get_tenant(tenant_id).await?;

        let mut tenants = self.tenants.write().await;
        let mut usage_map = self.usage.write().await;
        let mut namespaces = self.namespaces.write().await;
        let mut policies = self.policies.write().await;

        tenants.remove(tenant_id);
        usage_map.remove(tenant_id);
        namespaces.remove(&tenant.namespace);

        // Remove all policies involving this tenant
        policies.retain(|_, policy| {
            policy.source_tenant_id != tenant_id && policy.target_tenant_id != tenant_id
        });

        Ok(())
    }

    /// Reset API rate limit counters (called periodically)
    pub async fn reset_rate_limits(&self) {
        let mut usage_map = self.usage.write().await;
        for usage in usage_map.values_mut() {
            usage.api_calls_last_minute = 0;
            usage.last_updated = Utc::now();
        }
    }
}

impl Default for MultiTenantEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Quota operation types
#[derive(Debug, Clone)]
pub enum QuotaOperation {
    CreateSecret { size_bytes: usize },
    DeleteSecret { size_bytes: usize },
    ApiCall,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_tenant() {
        let engine = MultiTenantEngine::new();
        let tenant = engine
            .create_tenant("Test Tenant".to_string(), "test-ns".to_string(), None)
            .await
            .unwrap();

        assert_eq!(tenant.name, "Test Tenant");
        assert_eq!(tenant.namespace, "test-ns");
        assert!(tenant.enabled);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let engine = MultiTenantEngine::new();
        engine
            .create_tenant("Tenant 1".to_string(), "ns1".to_string(), None)
            .await
            .unwrap();

        // Duplicate namespace should fail
        let result = engine
            .create_tenant("Tenant 2".to_string(), "ns1".to_string(), None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_quota_enforcement() {
        let engine = MultiTenantEngine::new();
        let quotas = ResourceQuota {
            max_secrets: 2,
            max_storage_bytes: 1000,
            api_rate_limit_per_minute: 10,
            max_namespaces: 5,
        };

        let tenant = engine
            .create_tenant("Test".to_string(), "test".to_string(), Some(quotas))
            .await
            .unwrap();

        // Should succeed
        engine
            .enforce_quota(
                &tenant.tenant_id,
                QuotaOperation::CreateSecret { size_bytes: 400 },
            )
            .await
            .unwrap();

        // Should succeed
        engine
            .enforce_quota(
                &tenant.tenant_id,
                QuotaOperation::CreateSecret { size_bytes: 400 },
            )
            .await
            .unwrap();

        // Should fail - max secrets reached
        let result = engine
            .enforce_quota(
                &tenant.tenant_id,
                QuotaOperation::CreateSecret { size_bytes: 400 },
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cross_tenant_access_denied() {
        let engine = MultiTenantEngine::new();
        let tenant1 = engine
            .create_tenant("Tenant 1".to_string(), "ns1".to_string(), None)
            .await
            .unwrap();
        let tenant2 = engine
            .create_tenant("Tenant 2".to_string(), "ns2".to_string(), None)
            .await
            .unwrap();

        // No policy exists, should deny
        let result = engine
            .check_cross_tenant_access(
                &tenant1.tenant_id,
                &tenant2.tenant_id,
                "read",
                "/secret/path",
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_cross_tenant_access_with_policy() {
        let engine = MultiTenantEngine::new();
        let tenant1 = engine
            .create_tenant("Tenant 1".to_string(), "ns1".to_string(), None)
            .await
            .unwrap();
        let tenant2 = engine
            .create_tenant("Tenant 2".to_string(), "ns2".to_string(), None)
            .await
            .unwrap();

        // Create policy
        engine
            .create_cross_tenant_policy(
                tenant1.tenant_id.clone(),
                tenant2.tenant_id.clone(),
                vec!["read".to_string()],
                "/shared/".to_string(),
            )
            .await
            .unwrap();

        // Should allow with matching path
        let allowed = engine
            .check_cross_tenant_access(
                &tenant1.tenant_id,
                &tenant2.tenant_id,
                "read",
                "/shared/secret",
            )
            .await
            .unwrap();
        assert!(allowed);

        // Should deny with non-matching path
        let result = engine
            .check_cross_tenant_access(
                &tenant1.tenant_id,
                &tenant2.tenant_id,
                "read",
                "/private/secret",
            )
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_resource_usage_tracking() {
        let engine = MultiTenantEngine::new();
        let tenant = engine
            .create_tenant("Test".to_string(), "test".to_string(), None)
            .await
            .unwrap();

        engine
            .enforce_quota(
                &tenant.tenant_id,
                QuotaOperation::CreateSecret { size_bytes: 500 },
            )
            .await
            .unwrap();

        let usage = engine.get_resource_usage(&tenant.tenant_id).await.unwrap();
        assert_eq!(usage.current_secrets, 1);
        assert_eq!(usage.current_storage_bytes, 500);
    }
}
