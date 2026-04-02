//! Database Secret Engine Service
//!
//! Handles persistence and management of database configurations and roles.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

use crate::services::crypto::CryptoService;
use secreton_secrets_database::{DatabaseConfig, DatabaseEngine, DatabaseRole};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde_json::{json, Value};

const DB_CONFIG_PATH: &str = "sys/database/config";
const DB_ROLE_PREFIX: &str = "sys/database/roles/";
const DB_LEASE_PREFIX: &str = "sys/database/leases/";

pub struct DatabaseService {
    storage: Arc<dyn StorageBackend + Send + Sync>,
    crypto: Arc<CryptoService>,
    engine: Arc<RwLock<DatabaseEngine>>,
    initialized: std::sync::atomic::AtomicBool,
}

impl DatabaseService {
    pub fn new(storage: Arc<dyn StorageBackend + Send + Sync>, crypto: Arc<CryptoService>) -> Self {
        let engine = DatabaseEngine::new(DatabaseConfig::default());
        Self {
            storage,
            crypto,
            engine: Arc::new(RwLock::new(engine)),
            initialized: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub async fn ensure_initialized(&self) -> Result<()> {
        if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }

        // Load config from storage (if any) BEFORE acquiring the write lock so
        // that a storage failure does not leave the engine in a half-initialised
        // state.
        let maybe_config: Option<DatabaseConfig> =
            if let Some(entry) = self.storage.get_by_path(DB_CONFIG_PATH).await? {
                let decrypted = self.crypto.decrypt(&entry.encrypted_data).await?;
                Some(serde_json::from_slice(&decrypted)?)
            } else {
                None
            };

        // Load roles from storage
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await?;
        let mut loaded_roles: Vec<(String, DatabaseRole)> = Vec::new();
        for entry in entries {
            if let Some(name) = entry.path.strip_prefix(DB_ROLE_PREFIX) {
                match self.crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => {
                        if let Ok(role) = serde_json::from_slice::<DatabaseRole>(&decrypted) {
                            loaded_roles.push((name.to_string(), role));
                        }
                    }
                    Err(e) => warn!("Failed to decrypt role {}: {}", name, e),
                }
            }
        }

        // Now apply config + roles under a single write lock so concurrent
        // readers never see an engine with the right config but zero roles.
        {
            let mut engine = self.engine.write().await;
            if let Some(config) = maybe_config {
                *engine = DatabaseEngine::new(config);
                engine.enable();
            }
            for (name, role) in loaded_roles {
                engine.add_role(name, role);
            }
        }

        self.initialized.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub async fn set_config(&self, config: DatabaseConfig) -> Result<()> {
        self.ensure_initialized().await?;

        // Acquire the write lock FIRST, then persist config and load roles from
        // storage while holding it.  This prevents a concurrent `add_role` from
        // persisting a role and adding it to the old engine between the storage
        // read and the engine swap — which would silently drop that role from
        // the in-memory engine.  It also prevents two concurrent `set_config`
        // calls from ending up with the in-memory engine holding a stale config
        // that differs from what was last written to storage.
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;

        // Persist config to storage while holding the lock
        let data = serde_json::to_vec(&config)?;
        let encrypted = self.crypto.encrypt_data(&data).await?;
        let entry = SecretEntry::new(
            DB_CONFIG_PATH.to_string(),
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        );
        self.storage.store(&entry).await?;

        // Load roles from storage while still holding the lock
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await?;
        let mut loaded_roles: Vec<(String, DatabaseRole)> = Vec::new();
        for entry in entries {
            if let Some(name) = entry.path.strip_prefix(DB_ROLE_PREFIX) {
                if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                    if let Ok(role) = serde_json::from_slice::<DatabaseRole>(&decrypted) {
                        loaded_roles.push((name.to_string(), role));
                    }
                }
            }
        }

        // Build the new engine and apply roles atomically
        let mut new_engine = DatabaseEngine::new(config);
        new_engine.enable();
        for (name, role) in loaded_roles {
            new_engine.add_role(name, role);
        }

        *engine = new_engine;

        Ok(())
    }

    pub async fn add_role(&self, name: &str, role: DatabaseRole) -> Result<()> {
        self.ensure_initialized().await?;

        // Acquire the write lock FIRST (same strategy as set_config) to
        // prevent concurrent add_role calls from creating a divergence
        // between the persisted role and the in-memory engine.
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;

        // Persist
        let path = format!("{}{}", DB_ROLE_PREFIX, name);
        let data = serde_json::to_vec(&role)?;
        let encrypted = self.crypto.encrypt_data(&data).await?;
        let entry = SecretEntry::new(
            path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        self.storage.store(&entry).await?;

        // Update engine
        engine.add_role(name.to_string(), role);

        Ok(())
    }
    }

    pub async fn list_roles(&self) -> Result<Vec<String>> {
        self.ensure_initialized().await?;
        let engine: tokio::sync::RwLockReadGuard<'_, DatabaseEngine> = self.engine.read().await;
        Ok(engine.list_roles())
    }

    pub async fn generate_credentials(&self, role_name: &str) -> Result<HashMap<String, Value>> {
        self.ensure_initialized().await?;

        // Hold the read lock only for the engine call, then drop it before
        // performing storage I/O so that concurrent set_config/add_role calls
        // are not blocked.
        let (mut creds, lease_duration) = {
            let engine = self.engine.read().await;
            let creds = engine.generate_credentials(role_name).await
                .map_err(|e| anyhow!("Engine failed: {}", e))?;
            // Read the role's default_ttl while we still hold the lock, since
            // the engine's returned HashMap does not include lease_duration.
            let ttl = engine.get_role_default_ttl(role_name).unwrap_or(3600);
            (creds, ttl)
        };

        // Create lease — use underscores instead of slashes so the ID is a single
        // path segment and can be used directly in DELETE /leases/{id}.
        let lease_id = format!("db_{}_{}", role_name, uuid::Uuid::new_v4().simple());
        creds.insert("lease_id".to_string(), Value::String(lease_id.clone()));
        creds.insert("lease_duration".to_string(), Value::Number(serde_json::Number::from(lease_duration)));

        // Store lease info
        let lease_path = format!("{}{}", DB_LEASE_PREFIX, lease_id);
        let lease_data = json!({
            "lease_id": lease_id,
            "role": role_name,
            "username": creds.get("username").and_then(|v| v.as_str()).unwrap_or_default(),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "lease_duration": lease_duration,
        });

        let data = serde_json::to_vec(&lease_data)?;
        let encrypted = self.crypto.encrypt_data(&data).await?;
        let entry = SecretEntry::new(
            lease_path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        self.storage.store(&entry).await?;

        Ok(creds)
    }

    pub async fn list_leases(&self) -> Result<Vec<Value>> {
        self.ensure_initialized().await?;
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_LEASE_PREFIX.to_string()),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await?;
        let mut leases = Vec::new();
        for entry in entries {
            match self.crypto.decrypt(&entry.encrypted_data).await {
                Ok(decrypted) => {
                    if let Ok(lease) = serde_json::from_slice::<Value>(&decrypted) {
                        leases.push(lease);
                    }
                }
                Err(e) => warn!("Failed to decrypt lease {}: {}", entry.path, e),
            }
        }
        Ok(leases)
    }

    pub async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        self.ensure_initialized().await?;
        // In a real implementation, we would call the engine to drop the user
        // For now, we just delete the lease record
        let lease_path = format!("{}{}", DB_LEASE_PREFIX, lease_id);
        self.storage.delete_by_path(&lease_path).await?;
        Ok(())
    }
}
