//! Enhanced Lease Management System
//!
//! Comprehensive lease lifecycle management with automatic renewal,
//! revocation cascading, and background cleanup.

use crate::models::lease::Lease;
// use secreton_storage::StorageEngine;
use anyhow::Result;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Lease error types
#[derive(Error, Debug)]
pub enum LeaseError {
    #[error("Lease not found: {0}")]
    LeaseNotFound(String),

    #[error("Lease expired")]
    LeaseExpired,

    #[error("Lease revoked")]
    LeaseRevoked,

    #[error("Renewal not allowed")]
    RenewalNotAllowed,

    #[error("Invalid TTL: {0}")]
    InvalidTtl(String),

    #[error("Storage error: {0}")]
    StorageError(String),
}

/// Enhanced lease with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnhancedLease {
    /// Lease ID
    pub id: String,

    /// User/entity ID
    pub _user: String,

    /// Resource _path
    pub resource: String,

    /// Resource type (_secret, database, etc.)
    pub resource_type: String,

    /// Issued timestamp
    pub issued_at: DateTime<Utc>,

    /// Expiration timestamp
    pub expired_at: DateTime<Utc>,

    /// Status (active, revoked, expired)
    pub _status: String,

    /// Namespace
    pub namespace: String,

    /// Parent lease ID
    pub parent_id: Option<String>,

    /// Child lease IDs
    pub child_ids: Vec<String>,

    /// Renewable flag
    pub renewable: bool,

    /// Maximum TTL
    pub max_ttl: i64,

    /// Renew count
    pub renew_count: u32,

    /// Maximum renewals allowed
    pub max_renewals: Option<u32>,

    /// Last renewed at
    pub last_renewed_at: Option<DateTime<Utc>>,

    /// Revocation callback
    pub revoke_callback: Option<String>,

    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl From<Lease> for EnhancedLease {
    fn from(lease: Lease) -> Self {
        Self {
            id: lease.id,
            _user: lease.user,
            resource: lease.resource,
            resource_type: lease.resource_type,
            issued_at: lease.issued_at,
            expired_at: lease.expired_at,
            _status: lease.status,
            namespace: lease.namespace,
            parent_id: None,
            child_ids: Vec::new(),
            renewable: true,
            max_ttl: 86400,
            renew_count: 0,
            max_renewals: None,
            last_renewed_at: None,
            revoke_callback: None,
            metadata: HashMap::new(),
        }
    }
}

impl From<EnhancedLease> for Lease {
    fn from(val: EnhancedLease) -> Self {
        Lease {
            id: val.id,
            user: val._user,
            resource: val.resource,
            resource_type: val.resource_type,
            issued_at: val.issued_at,
            expired_at: val.expired_at,
            status: val._status,
            namespace: val.namespace,
        }
    }
}

/// Enhanced lease manager
pub struct LeaseManager {
    leases: Arc<RwLock<HashMap<String, EnhancedLease>>>,
    by_user: Arc<RwLock<HashMap<String, Vec<String>>>>,
    by_resource: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl LeaseManager {
    /// Create new lease manager
    pub fn new() -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            by_user: Arc::new(RwLock::new(HashMap::new())),
            by_resource: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create lease
    #[allow(clippy::too_many_arguments)]
    pub async fn create_lease(
        &self,
        _user: &str,
        resource: &str,
        resource_type: &str,
        ttl_secs: i64,
        max_ttl: i64,
        renewable: bool,
        parent_id: Option<String>,
    ) -> Result<EnhancedLease, LeaseError> {
        if ttl_secs <= 0 || ttl_secs > max_ttl {
            return Err(LeaseError::InvalidTtl(format!(
                "TTL {} must be between 1 and {}",
                ttl_secs, max_ttl
            )));
        }

        let now = Utc::now();
        let lease = EnhancedLease {
            id: Uuid::new_v4().to_string(),
            _user: _user.to_string(),
            resource: resource.to_string(),
            resource_type: resource_type.to_string(),
            issued_at: now,
            expired_at: now + Duration::seconds(ttl_secs),
            _status: "active".to_string(),
            namespace: "default".to_string(),
            parent_id: parent_id.clone(),
            child_ids: Vec::new(),
            renewable,
            max_ttl,
            renew_count: 0,
            max_renewals: None,
            last_renewed_at: None,
            revoke_callback: None,
            metadata: HashMap::new(),
        };

        // Store lease
        let mut leases = self.leases.write().await;
        leases.insert(lease.id.clone(), lease.clone());
        drop(leases);

        // Index by _user
        let mut by_user = self.by_user.write().await;
        by_user
            .entry(_user.to_string())
            .or_insert_with(Vec::new)
            .push(lease.id.clone());
        drop(by_user);

        // Index by resource
        let mut by_resource = self.by_resource.write().await;
        by_resource
            .entry(resource.to_string())
            .or_insert_with(Vec::new)
            .push(lease.id.clone());
        drop(by_resource);

        // Add to parent's children
        if let Some(parent_id) = parent_id {
            let mut leases = self.leases.write().await;
            if let Some(parent) = leases.get_mut(&parent_id) {
                parent.child_ids.push(lease.id.clone());
            }
        }

        Ok(lease)
    }

    /// Renew lease
    pub async fn renew_lease(
        &self,
        lease_id: &str,
        increment: i64,
    ) -> Result<EnhancedLease, LeaseError> {
        let mut leases = self.leases.write().await;
        let lease = leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::LeaseNotFound(lease_id.to_string()))?;

        if lease._status != "active" {
            return Err(LeaseError::LeaseRevoked);
        }

        if !lease.renewable {
            return Err(LeaseError::RenewalNotAllowed);
        }

        let now = Utc::now();
        if now > lease.expired_at {
            return Err(LeaseError::LeaseExpired);
        }

        // Check max renewals
        if let Some(max_renewals) = lease.max_renewals
            && lease.renew_count >= max_renewals {
            return Err(LeaseError::RenewalNotAllowed);
        }

        // Calculate new expiration
        let new_ttl = increment.min(lease.max_ttl);
        lease.expired_at = now + Duration::seconds(new_ttl);
        lease.renew_count += 1;
        lease.last_renewed_at = Some(now);

        Ok(lease.clone())
    }

    /// Revoke lease and all children
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<Vec<String>, LeaseError> {
        let mut revoked_ids = Vec::new();

        // Get lease
        let mut leases = self.leases.write().await;
        let lease = leases
            .get_mut(lease_id)
            .ok_or_else(|| LeaseError::LeaseNotFound(lease_id.to_string()))?;

        if lease._status == "revoked" {
            return Ok(revoked_ids);
        }

        lease._status = "revoked".to_string();
        revoked_ids.push(lease.id.clone());

        // Get child IDs before releasing lock
        let child_ids = lease.child_ids.clone();
        drop(leases);

        // Recursively revoke children
        for child_id in child_ids {
            if let Ok(mut child_revoked) = Box::pin(self.revoke_lease(&child_id)).await {
                revoked_ids.append(&mut child_revoked);
            }
        }

        Ok(revoked_ids)
    }

    /// Get lease
    pub async fn get_lease(&self, lease_id: &str) -> Result<EnhancedLease, LeaseError> {
        let leases = self.leases.read().await;
        leases
            .get(lease_id)
            .cloned()
            .ok_or_else(|| LeaseError::LeaseNotFound(lease_id.to_string()))
    }

    /// List leases by _user
    pub async fn list_by_user(&self, _user: &str) -> Vec<EnhancedLease> {
        let by_user = self.by_user.read().await;
        let lease_ids = by_user.get(_user).cloned().unwrap_or_default();
        drop(by_user);

        let leases = self.leases.read().await;
        lease_ids
            .iter()
            .filter_map(|id| leases.get(id).cloned())
            .collect()
    }

    /// List leases by resource
    pub async fn list_by_resource(&self, resource: &str) -> Vec<EnhancedLease> {
        let by_resource = self.by_resource.read().await;
        let lease_ids = by_resource.get(resource).cloned().unwrap_or_default();
        drop(by_resource);

        let leases = self.leases.read().await;
        lease_ids
            .iter()
            .filter_map(|id| leases.get(id).cloned())
            .collect()
    }

    /// Get expired leases
    pub async fn get_expired_leases(&self) -> Vec<EnhancedLease> {
        let now = Utc::now();
        let leases = self.leases.read().await;

        leases
            .values()
            .filter(|lease| lease._status == "active" && now > lease.expired_at)
            .cloned()
            .collect()
    }

    /// Cleanup expired leases
    pub async fn cleanup_expired(&self) -> usize {
        let expired = self.get_expired_leases().await;
        let count = expired.len();

        for lease in expired {
            let _ = self.revoke_lease(&lease.id).await;
        }

        count
    }

    /// Count active leases
    pub async fn count_active(&self) -> usize {
        let leases = self.leases.read().await;
        leases
            .values()
            .filter(|lease| lease._status == "active")
            .count()
    }
}

impl Default for LeaseManager {
    fn default() -> Self {
        Self::new()
    }
}

// Legacy functions for compatibility - commented out during refactoring
/*
pub async fn create_lease(
    _storage: &dyn StorageEngine,
    _user: &str,
    resource: &str,
    resource_type: &str,
    ttl_secs: i64,
) -> Result<Lease> {
    let now = Utc::now();
    let lease = Lease {
        id: Uuid::new_v4().to_string(),
        _user: _user.to_string(),
        resource: resource.to_string(),
        resource_type: resource_type.to_string(),
        issued_at: now,
        expired_at: now + Duration::seconds(ttl_secs),
        _status: "active".to_string(),
        namespace: "default".to_string(),
    };
    Ok(lease)
}

pub async fn renew_lease(
    _storage: &dyn StorageEngine,
    lease_id: &str,
    ttl_secs: i64,
) -> Result<Lease> {
    let now = Utc::now();
    let lease = Lease {
        id: lease_id.to_string(),
        _user: "unknown".to_string(),
        resource: "unknown".to_string(),
        resource_type: "unknown".to_string(),
        issued_at: now,
        expired_at: now + Duration::seconds(ttl_secs),
        _status: "active".to_string(),
        namespace: "default".to_string(),
    };
    Ok(lease)
}

pub async fn revoke_lease(_storage: &dyn StorageEngine, _lease_id: &str) -> Result<()> {
    Ok(())
}

pub async fn get_expired_leases(_storage: &dyn StorageEngine) -> Result<Vec<Lease>> {
    Ok(vec![])
}
*/

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_lease() {
        let manager = LeaseManager::new();

        let lease = manager
            .create_lease(
                "user1",
                "/_secret/_data/test",
                "kv",
                3600,
                86400,
                true,
                None,
            )
            .await
            .unwrap();

        assert_eq!(lease._user, "user1");
        assert_eq!(lease._status, "active");
        assert!(lease.renewable);
    }

    #[tokio::test]
    async fn test_renew_lease() {
        let manager = LeaseManager::new();

        let lease = manager
            .create_lease(
                "user1",
                "/_secret/_data/test",
                "kv",
                1800,
                86400,
                true,
                None,
            )
            .await
            .unwrap();

        let renewed = manager.renew_lease(&lease.id, 3600).await.unwrap();
        assert_eq!(renewed.renew_count, 1);
        assert!(renewed.last_renewed_at.is_some());
    }

    #[tokio::test]
    async fn test_revoke_lease() {
        let manager = LeaseManager::new();

        let lease = manager
            .create_lease(
                "user1",
                "/_secret/_data/test",
                "kv",
                3600,
                86400,
                true,
                None,
            )
            .await
            .unwrap();

        let revoked = manager.revoke_lease(&lease.id).await.unwrap();
        assert_eq!(revoked.len(), 1);

        let lease = manager.get_lease(&lease.id).await.unwrap();
        assert_eq!(lease._status, "revoked");
    }

    #[tokio::test]
    async fn test_parent_child_revocation() {
        let manager = LeaseManager::new();

        let parent = manager
            .create_lease("user1", "/parent", "kv", 3600, 86400, true, None)
            .await
            .unwrap();

        let _child = manager
            .create_lease(
                "user1",
                "/child",
                "kv",
                3600,
                86400,
                true,
                Some(parent.id.clone()),
            )
            .await
            .unwrap();

        // Revoke parent should revoke child too
        let revoked = manager.revoke_lease(&parent.id).await.unwrap();
        assert_eq!(revoked.len(), 2);
    }
}
