//! Database Secret Engine Service
//!
//! Handles persistence and management of database configurations and roles.

use anyhow::Result;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::warn;

use crate::services::crypto::CryptoService;
use secreton_secrets_database::{DatabaseConfig, DatabaseEngine, DatabaseRole};
use secreton_storage::{EncryptionMetadata, SecretEntry, SecurityLevel, StorageBackend};
use serde_json::{json, Value};

/// Categorised service error that handlers can map to the appropriate HTTP status.
#[derive(Debug)]
pub enum DatabaseServiceError {
    /// The requested resource was not found (→ 404).
    NotFound(String),
    /// The engine is disabled / not ready (→ 503).
    Unavailable(String),
    /// A client-supplied value is invalid (→ 400).
    BadRequest(String),
    /// Any other unexpected failure (→ 500).
    Internal(String),
}

impl std::fmt::Display for DatabaseServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "{}", msg),
            Self::Unavailable(msg) => write!(f, "{}", msg),
            Self::BadRequest(msg) => write!(f, "{}", msg),
            Self::Internal(msg) => write!(f, "{}", msg),
        }
    }
}

impl From<anyhow::Error> for DatabaseServiceError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

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
        if self.initialized.load(std::sync::atomic::Ordering::Acquire) {
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

        // Load roles from storage.
        //
        // Cap the scan with an explicit upper bound. Before the PostgreSQL
        // backend's default `LIMIT 100` was removed (in the lifecycle PR),
        // this scan was implicitly bounded; without an explicit limit it
        // would now load every role into memory and decrypt each one on
        // every initialization. 10k DB roles is far above realistic
        // deployments while still bounding worst-case startup memory.
        const DB_ROLE_LOAD_MAX_ENTRIES: u32 = 10_000;
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            limit: Some(DB_ROLE_LOAD_MAX_ENTRIES),
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
        // Re-check the flag inside the lock to prevent redundant initialization
        // when multiple callers race past the initial check.
        {
            let mut engine = self.engine.write().await;
            if self.initialized.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }
            if let Some(config) = maybe_config {
                *engine = DatabaseEngine::new(config);
                engine.enable();
            }
            for (name, role) in loaded_roles {
                engine.add_role(name, role);
            }
            self.initialized.store(true, std::sync::atomic::Ordering::Release);
        }

        Ok(())
    }

    pub async fn set_config(&self, config: DatabaseConfig) -> std::result::Result<(), DatabaseServiceError> {
        self.ensure_initialized().await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        // Validate the connection URL early so the admin gets immediate feedback
        // instead of a deferred error at credential-generation time.
        //
        // NOTE: `config.verify_connection` is accepted and persisted but not yet
        // acted upon — the service does not attempt to open a real connection to
        // the target database at configuration time.  Connection errors will
        // surface later at credential-generation time.  A future improvement
        // should honour the flag by performing a test connection here when it is
        // `true`.
        if config.connection_url.is_empty() {
            return Err(DatabaseServiceError::BadRequest(
                "connection_url must not be empty".to_string(),
            ));
        }
        let known_prefixes = [
            "postgresql://",
            "postgres://",
            "mysql://",
            "mongodb://",
            "redis://",
        ];
        if !known_prefixes
            .iter()
            .any(|p| config.connection_url.starts_with(p))
        {
            return Err(DatabaseServiceError::BadRequest(format!(
                "Unsupported database type in connection_url. \
                 Must start with one of: {}",
                known_prefixes.join(", "),
            )));
        }

        // Acquire the write lock FIRST, then load roles, persist config, and
        // rebuild the engine while holding it.  This prevents a concurrent
        // `add_role` from persisting a role and adding it to the old engine
        // between the storage read and the engine swap — which would silently
        // drop that role from the in-memory engine.  It also prevents two
        // concurrent `set_config` calls from ending up with the in-memory
        // engine holding a stale config that differs from what was last
        // written to storage.
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;

        // Load roles from storage BEFORE persisting the new config.  If the
        // role-loading step fails, we return an error without having written
        // the config — keeping storage and the in-memory engine consistent.
        //
        // Cap mirrors `ensure_initialized` — see DB_ROLE_LOAD_MAX_ENTRIES
        // there for the rationale. Without an explicit limit, set_config
        // would now perform an unbounded scan of the role namespace on
        // PostgreSQL after the lifecycle PR removed the default LIMIT 100.
        const DB_ROLE_LOAD_MAX_ENTRIES: u32 = 10_000;
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_ROLE_PREFIX.to_string()),
            limit: Some(DB_ROLE_LOAD_MAX_ENTRIES),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let mut loaded_roles: Vec<(String, DatabaseRole)> = Vec::new();
        for entry in entries {
            if let Some(name) = entry.path.strip_prefix(DB_ROLE_PREFIX) {
                match self.crypto.decrypt(&entry.encrypted_data).await {
                    Ok(decrypted) => {
                        if let Ok(role) = serde_json::from_slice::<DatabaseRole>(&decrypted) {
                            loaded_roles.push((name.to_string(), role));
                        } else {
                            warn!("Failed to deserialize role '{}' during set_config; it will be missing from the engine", name);
                        }
                    }
                    Err(e) => warn!("Failed to decrypt role '{}' during set_config: {}", name, e),
                }
            }
        }

        // Build the new engine and apply roles BEFORE persisting the config.
        // If serialization or engine construction fails we return an error
        // without having written anything — keeping storage and the in-memory
        // engine consistent.  We also pre-serialize/encrypt the config so that
        // if encryption fails, we haven't swapped the engine yet.
        let data = serde_json::to_vec(&config)
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let encrypted = self.crypto.encrypt_data(&data).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        let mut new_engine = DatabaseEngine::new(config);
        new_engine.enable();
        for (name, role) in loaded_roles {
            new_engine.add_role(name, role);
        }

        // Persist config to storage only after the new engine is fully built.
        // If this storage write fails, the in-memory engine is still the old
        // one — consistent with what's in storage.
        let entry = SecretEntry::new(
            DB_CONFIG_PATH.to_string(),
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::TopSecret,
            uuid::Uuid::nil(),
        );
        self.storage.store(&entry).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        // Swap the engine only after storage persistence succeeds.
        *engine = new_engine;

        Ok(())
    }

    pub async fn add_role(&self, name: &str, role: DatabaseRole) -> std::result::Result<(), DatabaseServiceError> {
        self.ensure_initialized().await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        // Acquire the write lock FIRST (same strategy as set_config) to
        // prevent concurrent add_role calls from creating a divergence
        // between the persisted role and the in-memory engine.
        let mut engine: tokio::sync::RwLockWriteGuard<'_, DatabaseEngine> = self.engine.write().await;

        // Persist
        let path = format!("{}{}", DB_ROLE_PREFIX, name);
        let data = serde_json::to_vec(&role)
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let encrypted = self.crypto.encrypt_data(&data).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let entry = SecretEntry::new(
            path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        self.storage.store(&entry).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        // Update engine
        engine.add_role(name.to_string(), role);

        Ok(())
    }

    pub async fn list_roles(&self) -> std::result::Result<Vec<String>, DatabaseServiceError> {
        self.ensure_initialized().await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let engine: tokio::sync::RwLockReadGuard<'_, DatabaseEngine> = self.engine.read().await;
        Ok(engine.list_roles())
    }

    pub async fn generate_credentials(
        &self,
        role_name: &str,
    ) -> std::result::Result<HashMap<String, Value>, DatabaseServiceError> {
        self.ensure_initialized().await?;

        // Hold the read lock only for the engine call, then drop it before
        // performing storage I/O so that concurrent set_config/add_role calls
        // are not blocked.
        let (mut creds, lease_duration) = {
            let engine = self.engine.read().await;
            let creds = engine
                .generate_credentials(role_name)
                .await
                .map_err(|e| {
                    use secreton_secrets_database::DatabaseError;
                    match &e {
                        DatabaseError::RoleNotFound(_) => {
                            DatabaseServiceError::NotFound(e.to_string())
                        }
                        DatabaseError::EngineDisabled => {
                            DatabaseServiceError::Unavailable(e.to_string())
                        }
                        DatabaseError::InvalidConfiguration(_)
                        | DatabaseError::UnsupportedDatabaseType(_) => {
                            DatabaseServiceError::BadRequest(e.to_string())
                        }
                        _ => DatabaseServiceError::Internal(e.to_string()),
                    }
                })?;
            // Read the role's default_ttl while we still hold the lock, since
            // the engine's returned HashMap does not include lease_duration.
            let ttl = engine.get_role_default_ttl(role_name).unwrap_or(3600);
            (creds, ttl)
        };

        // Create lease — use underscores instead of slashes so the ID is a single
        // path segment and can be used directly in DELETE /leases/{id}.
        let lease_id = format!("db_{}_{}", role_name, uuid::Uuid::new_v4().simple());
        creds.insert("lease_id".to_string(), Value::String(lease_id.clone()));
        creds.insert(
            "lease_duration".to_string(),
            Value::Number(serde_json::Number::from(lease_duration)),
        );

        // Store lease info.  If this fails the database user has already been
        // created.  The engine does not currently expose a revoke/drop-user API,
        // so we cannot perform automatic cleanup here.  We log the orphaned
        // username at WARN level so that operators can remove it manually.
        let username_for_log = creds
            .get("username")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let lease_path = format!("{}{}", DB_LEASE_PREFIX, lease_id);
        let lease_data = json!({
            "lease_id": lease_id,
            "role": role_name,
            "username": &username_for_log,
            "created_at": chrono::Utc::now().to_rfc3339(),
            "lease_duration": lease_duration,
        });

        let data = serde_json::to_vec(&lease_data)
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        let encrypted = self.crypto.encrypt_data(&data).await.map_err(|e| {
            warn!(
                "Failed to encrypt lease data for role '{}'; \
                 database user '{}' may have been orphaned: {}",
                role_name, username_for_log, e
            );
            DatabaseServiceError::Internal(e.to_string())
        })?;
        let entry = SecretEntry::new(
            lease_path,
            encrypted,
            EncryptionMetadata::default(),
            SecurityLevel::Secret,
            uuid::Uuid::nil(),
        );
        if let Err(e) = self.storage.store(&entry).await {
            warn!(
                "Failed to persist lease for role '{}'; \
                 database user '{}' may have been orphaned: {}",
                role_name, username_for_log, e
            );
            return Err(DatabaseServiceError::Internal(e.to_string()));
        }

        Ok(creds)
    }

    pub async fn list_leases(&self) -> std::result::Result<Vec<Value>, DatabaseServiceError> {
        self.ensure_initialized().await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
        // Cap the lease scan with an explicit upper bound. Before the
        // PostgreSQL backend's default `LIMIT 100` was removed (in the
        // lifecycle PR), this scan was implicitly bounded; without an
        // explicit limit `list_leases` would now perform an unbounded
        // scan of the lease namespace on every call. 10k active leases is
        // far above realistic deployments while still bounding memory.
        const DB_LEASE_LIST_MAX_ENTRIES: u32 = 10_000;
        let query = secreton_storage::QueryParams {
            path_prefix: Some(DB_LEASE_PREFIX.to_string()),
            limit: Some(DB_LEASE_LIST_MAX_ENTRIES),
            ..Default::default()
        };
        let entries = self.storage.list(&query).await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;
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

    pub async fn revoke_lease(
        &self,
        lease_id: &str,
    ) -> std::result::Result<(), DatabaseServiceError> {
        self.ensure_initialized().await?;

        let lease_path = format!("{}{}", DB_LEASE_PREFIX, lease_id);

        // Fetch lease info to get the username
        let entry = self
            .storage
            .get_by_path(&lease_path)
            .await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?
            .ok_or_else(|| DatabaseServiceError::NotFound(format!("Lease '{}' not found", lease_id)))?;

        let decrypted = self.crypto.decrypt(&entry.encrypted_data).await
            .map_err(|e| DatabaseServiceError::Internal(format!("Failed to decrypt lease: {}", e)))?;

        let lease_info: Value = serde_json::from_slice(&decrypted)
            .map_err(|e| DatabaseServiceError::Internal(format!("Failed to parse lease: {}", e)))?;

        let username = lease_info.get("username")
            .and_then(|v| v.as_str())
            .ok_or_else(|| DatabaseServiceError::Internal("Lease missing username".to_string()))?;

        // Call engine to revoke credentials.
        // If the backend returns `RevocationNotImplemented` (e.g. MongoDB,
        // Redis), we warn but still proceed with deleting the lease tracking
        // record so it does not become permanently irrecoverable.  For any
        // other error (connection failure, query failure, etc.) we propagate
        // the error and leave the lease record intact for retry.
        {
            let engine = self.engine.read().await;
            match engine.revoke_credentials(username).await {
                Ok(()) => {}
                Err(secreton_secrets_database::DatabaseError::RevocationNotImplemented(ref msg)) => {
                    warn!(
                        "Revoking lease '{}': credential revocation not implemented — \
                         the database user '{}' may still be active on the target database. \
                         Detail: {}",
                        lease_id, username, msg
                    );
                }
                Err(e) => {
                    warn!("Failed to revoke database credentials for '{}': {}", username, e);
                    return Err(DatabaseServiceError::Internal(format!("Database revocation failed: {}", e)));
                }
            }
        }

        // Delete the lease tracking record
        let deleted = self
            .storage
            .delete_by_path(&lease_path)
            .await
            .map_err(|e| DatabaseServiceError::Internal(e.to_string()))?;

        if !deleted {
            return Err(DatabaseServiceError::NotFound(format!(
                "Lease '{}' not found during deletion",
                lease_id
            )));
        }

        Ok(())
    }
}
