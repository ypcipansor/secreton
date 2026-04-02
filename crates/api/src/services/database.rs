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

        // Load config
        if let Some(entry) = self.storage.get_by_path(DB_CONFIG_PATH).await? {
            let decrypted = self.crypto.decrypt(&entry.encrypted_data).await?;
            let config: DatabaseConfig = serde_json::from_slice(&decrypted)?;

            let mut engine = self.engine.write().await;
            *engine = DatabaseEngine::new(config);
            engine.enable();
        }

        // Load roles
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await?;
        {
            let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;
            for entry in entries {
                if let Some(name) = entry.path.strip_prefix(DB_ROLE_PREFIX) {
                    match self.crypto.decrypt(&entry.encrypted_data).await {
                        Ok(decrypted) => {
                            if let Ok(role) = serde_json::from_slice::<DatabaseRole>(&decrypted) {
                                engine.add_role(name.to_string(), role);
                            }
                        }
                        Err(e) => warn!("Failed to decrypt role {}: {}", name, e),
                    }
                }
            }
        }

        self.initialized.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    pub async fn set_config(&self, config: DatabaseConfig) -> Result<()> {
        self.ensure_initialized().await?;

        // Persist
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

        // Update engine
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;
        let mut new_engine = DatabaseEngine::new(config);
        new_engine.enable();

        *engine = new_engine;

        // Re-add roles
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await?;
        for entry in entries {
            if let Some(name) = entry.path.strip_prefix(DB_ROLE_PREFIX) {
                if let Ok(decrypted) = self.crypto.decrypt(&entry.encrypted_data).await {
                    if let Ok(role) = serde_json::from_slice::<DatabaseRole>(&decrypted) {
                        engine.add_role(name.to_string(), role);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn add_role(&self, name: &str, role: DatabaseRole) -> Result<()> {
        self.ensure_initialized().await?;

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
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;
        engine.add_role(name.to_string(), role);

        Ok(())
    }

    pub async fn list_roles(&self) -> Result<Vec<String>> {
        self.ensure_initialized().await?;
        let engine: tokio::sync::RwLockReadGuard<'_, DatabaseEngine> = self.engine.read().await;
        Ok(engine.list_roles())
    }

    pub async fn generate_credentials(&self, role_name: &str) -> Result<HashMap<String, Value>> {
        self.ensure_initialized().await?;
        let engine: tokio::sync::RwLockReadGuard<'_, DatabaseEngine> = self.engine.read().await;

        let mut creds: HashMap<String, Value> = engine.generate_credentials(role_name).await
            .map_err(|e| anyhow!("Engine failed: {}", e))?;

        // Create lease — use underscores instead of slashes so the ID is a single
        // path segment and can be used directly in DELETE /leases/{id}.
        let lease_id = format!("db_{}_{}", role_name, uuid::Uuid::new_v4().simple());
        creds.insert("lease_id".to_string(), Value::String(lease_id.clone()));

        // Store lease info
        let lease_path = format!("{}{}", DB_LEASE_PREFIX, lease_id);
        let lease_data = json!({
            "lease_id": lease_id,
            "role": role_name,
            "username": creds.get("username").and_then(|v| v.as_str()).unwrap_or_default(),
            "created_at": chrono::Utc::now().to_rfc3339(),
            "lease_duration": creds.get("lease_duration").and_then(|v: &Value| v.as_u64()).unwrap_or(3600),
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
