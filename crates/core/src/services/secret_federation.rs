//! Secret Federation Manager
//!
//! Provides cross-region secret replication with conflict resolution,
//! federation topology management, and sync status tracking.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::RwLock;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum FederationError {
    #[error("Federation not found: {0}")]
    FederationNotFound(String),
    #[error("Region not found: {0}")]
    RegionNotFound(String),
    #[error("Sync conflict: {0}")]
    SyncConflict(String),
    #[error("Invalid topology: {0}")]
    InvalidTopology(String),
    #[error("Replication failed: {0}")]
    ReplicationFailed(String),
}

pub type Result<T> = std::result::Result<T, FederationError>;

/// Federation topology types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FederationTopology {
    HubSpoke,  // Central hub with spokes
    Mesh,      // All nodes connected
    Chain,     // Linear replication
    TreeBased, // Hierarchical structure
}

/// Conflict resolution strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConflictResolution {
    LastWriteWins,
    VectorClock,
    Manual,
    PreferRegion(String),
}

/// Federation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationConfig {
    pub federation_id: String,
    pub name: String,
    pub topology: FederationTopology,
    pub regions: Vec<String>,
    pub sync_interval_seconds: u64,
    pub conflict_resolution: ConflictResolution,
    pub enabled: bool,
}

/// Replica information for a secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicaInfo {
    pub region: String,
    pub last_synced_at: DateTime<Utc>,
    pub sync_status: SyncStatus,
    pub version: u64,
    pub data_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SyncStatus {
    Synced,
    Pending,
    Failed,
    Conflicted,
}

/// Federated secret with replicas
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedSecret {
    pub secret_path: String,
    pub federation_id: String,
    pub primary_region: String,
    pub replicas: HashMap<String, ReplicaInfo>,
    pub created_at: DateTime<Utc>,
    pub last_synced_at: DateTime<Utc>,
}

/// Sync operation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncOperation {
    pub operation_id: String,
    pub federation_id: String,
    pub secret_path: String,
    pub source_region: String,
    pub target_regions: Vec<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub status: SyncStatus,
    pub errors: Vec<String>,
}

/// Conflict record for manual resolution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConflictRecord {
    pub conflict_id: String,
    pub secret_path: String,
    pub regions: Vec<String>,
    pub versions: HashMap<String, u64>,
    pub detected_at: DateTime<Utc>,
    pub resolved: bool,
    pub resolution_strategy: Option<ConflictResolution>,
}

/// Federation health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederationHealth {
    pub federation_id: String,
    pub healthy_regions: Vec<String>,
    pub unhealthy_regions: Vec<String>,
    pub total_secrets: usize,
    pub synced_secrets: usize,
    pub pending_syncs: usize,
    pub conflicts: usize,
    pub last_check: DateTime<Utc>,
}

/// Secret federation manager
pub struct SecretFederation {
    federations: Arc<RwLock<HashMap<String, FederationConfig>>>,
    secrets: Arc<RwLock<HashMap<String, FederatedSecret>>>,
    sync_operations: Arc<RwLock<HashMap<String, SyncOperation>>>,
    conflicts: Arc<RwLock<HashMap<String, ConflictRecord>>>,
}

impl SecretFederation {
    pub fn new() -> Self {
        Self {
            federations: Arc::new(RwLock::new(HashMap::new())),
            secrets: Arc::new(RwLock::new(HashMap::new())),
            sync_operations: Arc::new(RwLock::new(HashMap::new())),
            conflicts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new federation
    pub async fn create_federation(
        &self,
        name: String,
        topology: FederationTopology,
        regions: Vec<String>,
        conflict_resolution: ConflictResolution,
    ) -> Result<FederationConfig> {
        if regions.len() < 2 {
            return Err(FederationError::InvalidTopology(
                "At least 2 regions required".to_string(),
            ));
        }

        let federation = FederationConfig {
            federation_id: Uuid::new_v4().to_string(),
            name,
            topology,
            regions,
            sync_interval_seconds: 300, // 5 minutes
            conflict_resolution,
            enabled: true,
        };

        let mut federations = self.federations.write().await;
        federations.insert(federation.federation_id.clone(), federation.clone());

        Ok(federation)
    }

    /// Federate a secret across regions
    pub async fn federate_secret(
        &self,
        secret_path: String,
        federation_id: String,
        primary_region: String,
    ) -> Result<FederatedSecret> {
        let federations = self.federations.read().await;
        let federation = federations
            .get(&federation_id)
            .ok_or_else(|| FederationError::FederationNotFound(federation_id.clone()))?;

        if !federation.regions.contains(&primary_region) {
            return Err(FederationError::RegionNotFound(primary_region));
        }

        let mut replicas = HashMap::new();
        for region in &federation.regions {
            replicas.insert(
                region.clone(),
                ReplicaInfo {
                    region: region.clone(),
                    last_synced_at: Utc::now(),
                    sync_status: if region == &primary_region {
                        SyncStatus::Synced
                    } else {
                        SyncStatus::Pending
                    },
                    version: 1,
                    data_hash: "".to_string(),
                },
            );
        }

        let federated_secret = FederatedSecret {
            secret_path: secret_path.clone(),
            federation_id: federation_id.clone(),
            primary_region,
            replicas,
            created_at: Utc::now(),
            last_synced_at: Utc::now(),
        };

        let mut secrets = self.secrets.write().await;
        secrets.insert(secret_path, federated_secret.clone());

        Ok(federated_secret)
    }

    /// Sync secret replicas across regions
    pub async fn sync_replicas(&self, secret_path: &str) -> Result<SyncOperation> {
        let mut secrets = self.secrets.write().await;
        let secret = secrets
            .get_mut(secret_path)
            .ok_or_else(|| FederationError::FederationNotFound(secret_path.to_string()))?;

        let operation = SyncOperation {
            operation_id: Uuid::new_v4().to_string(),
            federation_id: secret.federation_id.clone(),
            secret_path: secret_path.to_string(),
            source_region: secret.primary_region.clone(),
            target_regions: secret.replicas.keys().cloned().collect(),
            started_at: Utc::now(),
            completed_at: None,
            status: SyncStatus::Synced,
            errors: vec![],
        };

        // Simulate sync to all replicas
        for replica in secret.replicas.values_mut() {
            replica.last_synced_at = Utc::now();
            replica.sync_status = SyncStatus::Synced;
            replica.version += 1;
        }

        secret.last_synced_at = Utc::now();

        let mut operations = self.sync_operations.write().await;
        operations.insert(operation.operation_id.clone(), operation.clone());

        Ok(operation)
    }

    /// Resolve conflict between replicas
    pub async fn resolve_conflict(
        &self,
        conflict_id: &str,
        resolution: ConflictResolution,
    ) -> Result<()> {
        let mut conflicts = self.conflicts.write().await;
        let conflict = conflicts
            .get_mut(conflict_id)
            .ok_or_else(|| FederationError::SyncConflict(conflict_id.to_string()))?;

        let mut secrets = self.secrets.write().await;
        let secret = secrets
            .get_mut(&conflict.secret_path)
            .ok_or_else(|| FederationError::FederationNotFound(conflict.secret_path.clone()))?;

        match resolution {
            ConflictResolution::LastWriteWins => {
                // Find replica with most recent sync
                let (winning_region, _) = secret
                    .replicas
                    .iter()
                    .max_by_key(|(_, r)| r.last_synced_at)
                    .unwrap();
                secret.primary_region = winning_region.clone();
            }
            ConflictResolution::PreferRegion(ref region) => {
                if secret.replicas.contains_key(region) {
                    secret.primary_region = region.clone();
                } else {
                    return Err(FederationError::RegionNotFound(region.clone()));
                }
            }
            ConflictResolution::VectorClock => {
                // Use version numbers as vector clock
                let (winning_region, _) = secret
                    .replicas
                    .iter()
                    .max_by_key(|(_, r)| r.version)
                    .unwrap();
                secret.primary_region = winning_region.clone();
            }
            ConflictResolution::Manual => {
                // Manual resolution requires external intervention
                return Ok(());
            }
        }

        // Mark all replicas as pending resync
        for replica in secret.replicas.values_mut() {
            if replica.region != secret.primary_region {
                replica.sync_status = SyncStatus::Pending;
            }
        }

        conflict.resolved = true;
        conflict.resolution_strategy = Some(resolution);

        Ok(())
    }

    /// Get federation health status
    pub async fn get_federation_health(&self, federation_id: &str) -> Result<FederationHealth> {
        let federations = self.federations.read().await;
        let federation = federations
            .get(federation_id)
            .ok_or_else(|| FederationError::FederationNotFound(federation_id.to_string()))?;

        let secrets = self.secrets.read().await;
        let conflicts = self.conflicts.read().await;

        let mut healthy_regions = Vec::new();
        let mut unhealthy_regions = Vec::new();
        let mut total_secrets = 0;
        let mut synced_secrets = 0;
        let mut pending_syncs = 0;

        for secret in secrets.values() {
            if secret.federation_id == federation_id {
                total_secrets += 1;
                let all_synced = secret
                    .replicas
                    .values()
                    .all(|r| r.sync_status == SyncStatus::Synced);
                if all_synced {
                    synced_secrets += 1;
                } else {
                    pending_syncs += 1;
                }
            }
        }

        // Check region health based on recent sync status
        for region in &federation.regions {
            let recent_failures = secrets
                .values()
                .filter(|s| s.federation_id == federation_id)
                .filter_map(|s| s.replicas.get(region))
                .filter(|r| r.sync_status == SyncStatus::Failed)
                .count();

            if recent_failures == 0 {
                healthy_regions.push(region.clone());
            } else {
                unhealthy_regions.push(region.clone());
            }
        }

        Ok(FederationHealth {
            federation_id: federation_id.to_string(),
            healthy_regions,
            unhealthy_regions,
            total_secrets,
            synced_secrets,
            pending_syncs,
            conflicts: conflicts.len(),
            last_check: Utc::now(),
        })
    }

    /// Detect sync conflicts
    pub async fn detect_conflicts(&self, secret_path: &str) -> Result<Option<ConflictRecord>> {
        let secrets = self.secrets.read().await;
        let secret = secrets
            .get(secret_path)
            .ok_or_else(|| FederationError::FederationNotFound(secret_path.to_string()))?;

        // Check for version mismatches
        let versions: HashMap<String, u64> = secret
            .replicas
            .iter()
            .map(|(region, replica)| (region.clone(), replica.version))
            .collect();

        let unique_versions: Vec<_> = versions
            .values()
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();

        if unique_versions.len() > 1 {
            let conflict = ConflictRecord {
                conflict_id: Uuid::new_v4().to_string(),
                secret_path: secret_path.to_string(),
                regions: versions.keys().cloned().collect(),
                versions,
                detected_at: Utc::now(),
                resolved: false,
                resolution_strategy: None,
            };

            let mut conflicts = self.conflicts.write().await;
            conflicts.insert(conflict.conflict_id.clone(), conflict.clone());

            return Ok(Some(conflict));
        }

        Ok(None)
    }

    /// Get sync status for a secret
    pub async fn get_sync_status(&self, secret_path: &str) -> Result<FederatedSecret> {
        let secrets = self.secrets.read().await;
        secrets
            .get(secret_path)
            .cloned()
            .ok_or_else(|| FederationError::FederationNotFound(secret_path.to_string()))
    }

    /// List all federations
    pub async fn list_federations(&self) -> Vec<FederationConfig> {
        let federations = self.federations.read().await;
        federations.values().cloned().collect()
    }

    /// Get sync operations history
    pub async fn get_sync_history(&self, federation_id: &str) -> Vec<SyncOperation> {
        let operations = self.sync_operations.read().await;
        operations
            .values()
            .filter(|op| op.federation_id == federation_id)
            .cloned()
            .collect()
    }
}

impl Default for SecretFederation {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_create_federation() {
        let federation = SecretFederation::new();
        let config = federation
            .create_federation(
                "Global".to_string(),
                FederationTopology::Mesh,
                vec!["us-east".to_string(), "eu-west".to_string()],
                ConflictResolution::LastWriteWins,
            )
            .await
            .unwrap();

        assert_eq!(config.name, "Global");
        assert_eq!(config.regions.len(), 2);
    }

    #[tokio::test]
    async fn test_federate_secret() {
        let federation = SecretFederation::new();
        let config = federation
            .create_federation(
                "Global".to_string(),
                FederationTopology::Mesh,
                vec!["us-east".to_string(), "eu-west".to_string()],
                ConflictResolution::LastWriteWins,
            )
            .await
            .unwrap();

        let secret = federation
            .federate_secret(
                "/secret/test".to_string(),
                config.federation_id.clone(),
                "us-east".to_string(),
            )
            .await
            .unwrap();

        assert_eq!(secret.replicas.len(), 2);
        assert_eq!(secret.primary_region, "us-east");
    }

    #[tokio::test]
    async fn test_sync_replicas() {
        let federation = SecretFederation::new();
        let config = federation
            .create_federation(
                "Global".to_string(),
                FederationTopology::Mesh,
                vec!["us-east".to_string(), "eu-west".to_string()],
                ConflictResolution::LastWriteWins,
            )
            .await
            .unwrap();

        federation
            .federate_secret(
                "/secret/test".to_string(),
                config.federation_id,
                "us-east".to_string(),
            )
            .await
            .unwrap();

        let operation = federation.sync_replicas("/secret/test").await.unwrap();
        assert_eq!(operation.status, SyncStatus::Synced);
    }

    #[tokio::test]
    async fn test_federation_health() {
        let federation = SecretFederation::new();
        let config = federation
            .create_federation(
                "Global".to_string(),
                FederationTopology::Mesh,
                vec!["us-east".to_string(), "eu-west".to_string()],
                ConflictResolution::LastWriteWins,
            )
            .await
            .unwrap();

        let health = federation
            .get_federation_health(&config.federation_id)
            .await
            .unwrap();

        assert_eq!(health.healthy_regions.len(), 2);
        assert_eq!(health.unhealthy_regions.len(), 0);
    }

    #[tokio::test]
    async fn test_conflict_detection() {
        let federation = SecretFederation::new();
        let config = federation
            .create_federation(
                "Global".to_string(),
                FederationTopology::Mesh,
                vec!["us-east".to_string(), "eu-west".to_string()],
                ConflictResolution::LastWriteWins,
            )
            .await
            .unwrap();

        federation
            .federate_secret(
                "/secret/test".to_string(),
                config.federation_id,
                "us-east".to_string(),
            )
            .await
            .unwrap();

        // Simulate version mismatch
        {
            let mut secrets = federation.secrets.write().await;
            let secret = secrets.get_mut("/secret/test").unwrap();
            secret.replicas.get_mut("eu-west").unwrap().version = 5;
        }

        let conflict = federation.detect_conflicts("/secret/test").await.unwrap();
        assert!(conflict.is_some());
    }
}
