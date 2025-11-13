use anyhow::{Result, anyhow};
use async_trait::async_trait;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::storage::secure::storage::SharedSecureStorage;
use crate::storage::traits::StorageBackend;

/// Represents a versioned secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretVersion {
    pub id: String,
    pub version: u32,
    pub data: Value,
    pub created_at: chrono::DateTime<Utc>,
    pub created_by: String,
    pub metadata: HashMap<String, String>,
    pub deleted: bool,
}

/// Secret metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub id: String,
    pub path: String,
    pub current_version: u32,
    pub versions: u32,
    pub created_at: chrono::DateTime<Utc>,
    pub updated_at: chrono::DateTime<Utc>,
    pub max_versions: u32,
    pub custom_metadata: HashMap<String, String>,
}

/// Secret manager configuration
#[derive(Debug, Clone)]
pub struct SecretManagerConfig {
    pub max_versions: u32,
    pub default_lease_ttl: chrono::Duration,
    pub max_lease_ttl: chrono::Duration,
}

impl Default for SecretManagerConfig {
    fn default() -> Self {
        Self {
            max_versions: 10,
            default_lease_ttl: chrono::Duration::hours(24 * 7), // 1 week
            max_lease_ttl: chrono::Duration::days(30 * 6),      // 6 months
        }
    }
}

/// Secret manager for handling versioned secrets
pub struct SecretManager<T: StorageBackend> {
    backend: Arc<T>,
    secure_storage: SharedSecureStorage,
    config: SecretManagerConfig,
    secret_index: Arc<RwLock<HashSet<String>>>,
}

impl<T: StorageBackend> SecretManager<T> {
    /// Create a new SecretManager
    pub fn new(backend: Arc<T>, secure_storage: SharedSecureStorage) -> Self {
        Self {
            backend,
            secure_storage,
            config: SecretManagerConfig::default(),
            secret_index: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create a new SecretManager with custom configuration
    pub fn with_config(
        backend: Arc<T>,
        secure_storage: SharedSecureStorage,
        config: SecretManagerConfig,
    ) -> Self {
        Self {
            backend,
            secure_storage,
            config,
            secret_index: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    /// Create or update a secret
    pub async fn create_secret(
        &self,
        path: &str,
        data: Value,
        created_by: &str,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<SecretMetadata> {
        // Validate path
        if path.is_empty() || path.starts_with('/') {
            return Err(anyhow!("Invalid secret path"));
        }

        // Encrypt the secret data
        let encrypted_data = self.secure_storage.encrypt_value(&data).await?;

        // Store the secret in the backend
        let metadata = self
            .backend
            .store_secret_versioned(
                path,
                &json!({
                    "data": encrypted_data,
                    "created_by": created_by,
                    "metadata": metadata.unwrap_or_default(),
                }),
            )
            .await?;

        // Add path to index
        self.secret_index.write().await.insert(path.to_string());

        Ok(SecretMetadata {
            id: Uuid::new_v4().to_string(),
            path: path.to_string(),
            current_version: metadata,
            versions: 1,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            max_versions: self.config.max_versions,
            custom_metadata: HashMap::new(),
        })
    }

    /// Get the latest version of a secret
    pub async fn get_secret(&self, path: &str) -> Result<Option<SecretVersion>> {
        if let Some((stored_data, version)) = self.backend.get_latest_secret(path).await? {
            let encrypted_data = stored_data
                .get("data")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow!("Invalid secret data format"))?;

            let decrypted_bytes = self.secure_storage.decrypt(encrypted_data).await?;
            let data: Value = serde_json::from_slice(&decrypted_bytes)?;

            Ok(Some(SecretVersion {
                id: Uuid::new_v4().to_string(),
                version,
                data,
                created_at: Utc::now(),
                created_by: stored_data
                    .get("created_by")
                    .and_then(|v| v.as_str())
                    .unwrap_or("system")
                    .to_string(),
                metadata: stored_data
                    .get("metadata")
                    .and_then(|m| serde_json::from_value(m.clone()).ok())
                    .unwrap_or_default(),
                deleted: false,
            }))
        } else {
            Ok(None)
        }
    }

    /// List all secrets under a path
    pub async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        let index = self.secret_index.read().await;
        let matching_paths: Vec<String> = index
            .iter()
            .filter(|secret_path| secret_path.starts_with(path))
            .cloned()
            .collect();
        Ok(matching_paths)
    }

    /// Delete a secret or specific version
    pub async fn delete_secret(&self, path: &str, version: Option<u32>) -> Result<()> {
        if let Some(version) = version {
            // Delete specific version
            self.backend.delete_secret_version(path, version).await?;
            Ok(())
        } else {
            // Delete all versions and remove from index
            self.backend.delete_secret(path, "default").await?;
            self.secret_index.write().await.remove(path);
            Ok(())
        }
    }

    /// Get secret metadata
    pub async fn get_metadata(&self, path: &str) -> Result<Option<SecretMetadata>> {
        // In a real implementation, this would fetch from the database
        // For now, we'll return a simplified version
        if let Some((_data, version)) = self.backend.get_latest_secret(path).await? {
            Ok(Some(SecretMetadata {
                id: Uuid::new_v4().to_string(),
                path: path.to_string(),
                current_version: version,
                versions: 1, // This would be fetched from the database
                created_at: Utc::now(),
                updated_at: Utc::now(),
                max_versions: self.config.max_versions,
                custom_metadata: HashMap::new(),
            }))
        } else {
            Ok(None)
        }
    }
}

#[async_trait]
pub trait SecretStorage: Send + Sync {
    /// Store a new version of a secret
    async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32>;

    /// Get the latest version of a secret
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>>;

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>>;

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()>;

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()>;
}

#[async_trait]
impl<T: StorageBackend> SecretStorage for SecretManager<T> {
    /// Store a new version of a secret
    async fn store_secret_versioned(&self, path: &str, data: &serde_json::Value) -> Result<u32> {
        // This is a simplified implementation - in practice, you'd want to use the full create_secret logic
        let version = self.backend.store_secret_versioned(path, data).await?;
        self.secret_index.write().await.insert(path.to_string());
        Ok(version)
    }

    /// Get the latest version of a secret
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(serde_json::Value, u32)>> {
        self.backend
            .get_latest_secret(path)
            .await
            .map_err(|e| anyhow!(e))
    }

    /// List all secrets under a path
    async fn list_secrets(&self, path: &str) -> Result<Vec<String>> {
        self.list_secrets(path).await
    }

    /// Delete a secret (soft delete)
    async fn delete_secret(&self, path: &str) -> Result<()> {
        self.delete_secret(path, None).await
    }

    /// Delete a specific version of a secret
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<()> {
        self.backend.delete_secret_version(path, version).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::secure::storage::SecureStorage;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Mock storage backend for testing
    #[derive(Clone)]
    struct MockStorageBackend {
        data: Arc<RwLock<HashMap<String, Vec<u8>>>>,
        mfa_secrets: Arc<RwLock<HashMap<String, String>>>,
        mfa_recovery_codes: Arc<RwLock<HashMap<String, Vec<String>>>>,
        secret_versions: Arc<RwLock<HashMap<String, Vec<(u32, Value)>>>>,
        users: Arc<RwLock<HashMap<String, String>>>,
        roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
        policies: Arc<RwLock<HashMap<String, secreton_security::policies::policy::Policy>>>,
        tokens: Arc<RwLock<HashMap<String, secreton_auth::token::Token>>>,
        leases: Arc<RwLock<HashMap<String, secreton_storage::models::lease::Lease>>>,
        audit_logs: Arc<RwLock<Vec<crate::storage::types::AuditLog>>>,
        is_sealed: Arc<RwLock<bool>>,
        master_key: Arc<RwLock<Option<Vec<u8>>>>,
        audit_devices:
            Arc<RwLock<HashMap<String, Box<dyn secreton_security::policies::audit::AuditDevice>>>>,
        pki_cas: Arc<RwLock<HashMap<String, crate::models::pki::PkiCa>>>,
        pki_certs: Arc<RwLock<HashMap<String, crate::models::pki::PkiCert>>>,
        plugins: Arc<RwLock<HashMap<String, crate::models::plugin::PluginCatalogEntry>>>,
        sentinel_policies: Arc<RwLock<HashMap<String, crate::models::sentinel::SentinelPolicy>>>,
    }

    impl MockStorageBackend {
        fn new() -> Self {
            Self {
                data: Arc::new(RwLock::new(HashMap::new())),
                mfa_secrets: Arc::new(RwLock::new(HashMap::new())),
                mfa_recovery_codes: Arc::new(RwLock::new(HashMap::new())),
                secret_versions: Arc::new(RwLock::new(HashMap::new())),
                users: Arc::new(RwLock::new(HashMap::new())),
                roles: Arc::new(RwLock::new(HashMap::new())),
                policies: Arc::new(RwLock::new(HashMap::new())),
                tokens: Arc::new(RwLock::new(HashMap::new())),
                leases: Arc::new(RwLock::new(HashMap::new())),
                audit_logs: Arc::new(RwLock::new(Vec::new())),
                is_sealed: Arc::new(RwLock::new(false)),
                master_key: Arc::new(RwLock::new(None)),
                audit_devices: Arc::new(RwLock::new(HashMap::new())),
                pki_cas: Arc::new(RwLock::new(HashMap::new())),
                pki_certs: Arc::new(RwLock::new(HashMap::new())),
                plugins: Arc::new(RwLock::new(HashMap::new())),
                sentinel_policies: Arc::new(RwLock::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl StorageBackend for MockStorageBackend {
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }

        async fn store_secret_versioned(
            &self,
            path: &str,
            data: &Value,
        ) -> Result<u32, crate::CoreError> {
            let mut store = self.data.write().await;
            let mut versions_store = self.secret_versions.write().await;

            // Get current version number
            let current_version = versions_store
                .get(path)
                .map(|v| v.len() as u32)
                .unwrap_or(0)
                + 1;

            // Store the data
            let key = format!("{}:{}", path, current_version);
            let json_data = serde_json::to_vec(data).map_err(|_| crate::CoreError::Internal {
                message: "Serialization failed".to_string(),
            })?;
            store.insert(key, json_data);

            // Store version history
            let versions = versions_store
                .entry(path.to_string())
                .or_insert_with(Vec::new);
            versions.push((current_version, data.clone()));

            Ok(current_version)
        }

        async fn get_latest_secret(
            &self,
            path: &str,
        ) -> Result<Option<(Value, u32)>, crate::CoreError> {
            let versions_store = self.secret_versions.read().await;
            if let Some(versions) = versions_store.get(path) {
                if let Some((version, data)) = versions.last() {
                    Ok(Some((data.clone(), *version)))
                } else {
                    Ok(None)
                }
            } else {
                Ok(None)
            }
        }

        async fn delete_secret_version(
            &self,
            _path: &str,
            _version: u32,
        ) -> Result<(), crate::CoreError> {
            Ok(())
        }

        // Stub implementations for other required methods
        async fn store_mfa_secret(
            &self,
            user_id: &str,
            secret: &str,
            method: secreton_auth::MfaMethod,
        ) -> Result<(), crate::CoreError> {
            let mut mfa_store = self.mfa_secrets.write().await;
            let key = format!("{}:{}", user_id, method.as_str());
            mfa_store.insert(key, secret.to_string());
            Ok(())
        }

        async fn get_mfa_secret(
            &self,
            user_id: &str,
            method: secreton_auth::MfaMethod,
        ) -> Result<String, crate::CoreError> {
            let mfa_store = self.mfa_secrets.read().await;
            let key = format!("{}:{}", user_id, method.as_str());
            mfa_store
                .get(&key)
                .cloned()
                .ok_or_else(|| crate::CoreError::NotFound {
                    resource: "MFA secret not found".to_string(),
                })
        }

        async fn delete_mfa_secret(
            &self,
            user_id: &str,
            method: secreton_auth::MfaMethod,
        ) -> Result<(), crate::CoreError> {
            let mut mfa_store = self.mfa_secrets.write().await;
            let key = format!("{}:{}", user_id, method.as_str());
            mfa_store.remove(&key);
            Ok(())
        }

        async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool, crate::CoreError> {
            let mfa_store = self.mfa_secrets.read().await;
            let totp_key = format!("{}:{}", user_id, "totp");
            Ok(mfa_store.contains_key(&totp_key))
        }
        async fn get_user_mfa_methods(
            &self,
            user_id: &str,
        ) -> Result<Vec<secreton_auth::MfaMethod>, crate::CoreError> {
            let mfa_store = self.mfa_secrets.read().await;
            let mut methods = Vec::new();

            // Check each possible MFA method
            for method in &[
                secreton_auth::MfaMethod::Totp,
                secreton_auth::MfaMethod::Sms,
                secreton_auth::MfaMethod::Email,
                secreton_auth::MfaMethod::Hardware,
                secreton_auth::MfaMethod::Push,
                secreton_auth::MfaMethod::WebAuthn,
            ] {
                let key = format!("{}:{}", user_id, method.as_str());
                if mfa_store.contains_key(&key) {
                    methods.push(method.clone());
                }
            }

            Ok(methods)
        }

        async fn get_mfa_status(
            &self,
            user_id: &str,
        ) -> Result<HashMap<secreton_auth::MfaMethod, bool>, crate::CoreError> {
            let mfa_store = self.mfa_secrets.read().await;
            let mut status = HashMap::new();

            // Check status for each possible MFA method
            for method in &[
                secreton_auth::MfaMethod::Totp,
                secreton_auth::MfaMethod::Sms,
                secreton_auth::MfaMethod::Email,
                secreton_auth::MfaMethod::Hardware,
                secreton_auth::MfaMethod::Push,
                secreton_auth::MfaMethod::WebAuthn,
            ] {
                let key = format!("{}:{}", user_id, method.as_str());
                status.insert(method.clone(), mfa_store.contains_key(&key));
            }

            Ok(status)
        }

        async fn enable_mfa(
            &self,
            user_id: &str,
            method: secreton_auth::MfaMethod,
        ) -> Result<(), crate::CoreError> {
            let mut mfa_store = self.mfa_secrets.write().await;
            let key = format!("{}:{}", user_id, method.as_str());
            // Generate a random secret for the MFA method
            let secret = format!("mfa_secret_{}_{}", user_id, method.as_str());
            mfa_store.insert(key, secret);
            Ok(())
        }

        async fn disable_mfa(&self, user_id: &str) -> Result<(), crate::CoreError> {
            let mut mfa_store = self.mfa_secrets.write().await;
            // Remove all MFA methods for the user
            let keys_to_remove: Vec<String> = mfa_store
                .keys()
                .filter(|key| key.starts_with(&format!("{}:", user_id)))
                .cloned()
                .collect();

            for key in keys_to_remove {
                mfa_store.remove(&key);
            }

            // Also remove recovery codes
            let mut recovery_codes = self.mfa_recovery_codes.write().await;
            recovery_codes.remove(user_id);

            Ok(())
        }

        async fn store_mfa_recovery_codes(
            &self,
            user_id: &str,
            codes: &[String],
        ) -> Result<(), crate::CoreError> {
            let mut recovery_store = self.mfa_recovery_codes.write().await;
            recovery_store.insert(user_id.to_string(), codes.to_vec());
            Ok(())
        }

        async fn get_mfa_recovery_codes(
            &self,
            user_id: &str,
        ) -> Result<Vec<String>, crate::CoreError> {
            let recovery_store = self.mfa_recovery_codes.read().await;
            Ok(recovery_store.get(user_id).cloned().unwrap_or_default())
        }

        async fn get_secret_versions(
            &self,
            path: &str,
        ) -> Result<Vec<(u32, Value)>, crate::CoreError> {
            let versions_store = self.secret_versions.read().await;
            Ok(versions_store.get(path).cloned().unwrap_or_default())
        }
        async fn create_user(
            &self,
            username: &str,
            password: &str,
        ) -> Result<(), crate::CoreError> {
            let mut users = self.users.write().await;
            users.insert(username.to_string(), password.to_string());
            Ok(())
        }

        async fn authenticate_user(
            &self,
            username: &str,
            password: &str,
        ) -> Result<bool, crate::CoreError> {
            let users = self.users.read().await;
            if let Some(stored_password) = users.get(username) {
                Ok(stored_password == password)
            } else {
                Ok(false)
            }
        }

        async fn assign_role_to_user(
            &self,
            username: &str,
            role: &str,
        ) -> Result<(), crate::CoreError> {
            let mut roles = self.roles.write().await;
            roles
                .entry(username.to_string())
                .or_insert_with(Vec::new)
                .push(role.to_string());
            Ok(())
        }

        async fn get_user_roles(&self, username: &str) -> Result<Vec<String>, crate::CoreError> {
            let roles = self.roles.read().await;
            Ok(roles.get(username).cloned().unwrap_or_default())
        }

        async fn add_policy_to_role(
            &self,
            role: &str,
            policy: &str,
        ) -> Result<(), crate::CoreError> {
            let mut roles = self.roles.write().await;
            if let Some(role_policies) = roles.get_mut(role) {
                if !role_policies.contains(&policy.to_string()) {
                    role_policies.push(policy.to_string());
                }
            } else {
                roles.insert(role.to_string(), vec![policy.to_string()]);
            }
            Ok(())
        }

        async fn get_role_policies(&self, role: &str) -> Result<Vec<String>, crate::CoreError> {
            let roles = self.roles.read().await;
            Ok(roles.get(role).cloned().unwrap_or_default())
        }

        async fn store_policy(
            &self,
            name: &str,
            policy: &secreton_security::policies::policy::Policy,
        ) -> Result<(), crate::CoreError> {
            let mut policies = self.policies.write().await;
            policies.insert(name.to_string(), policy.clone());
            Ok(())
        }

        async fn get_policy(
            &self,
            name: &str,
        ) -> Result<Option<secreton_security::policies::policy::Policy>, crate::CoreError> {
            let policies = self.policies.read().await;
            Ok(policies.get(name).cloned())
        }

        async fn list_policies(&self) -> Result<Vec<String>, crate::CoreError> {
            let policies = self.policies.read().await;
            Ok(policies.keys().cloned().collect())
        }

        async fn delete_policy(&self, name: &str) -> Result<(), crate::CoreError> {
            let mut policies = self.policies.write().await;
            policies.remove(name);
            Ok(())
        }

        async fn store_token(
            &self,
            token: &secreton_auth::token::Token,
        ) -> Result<(), crate::CoreError> {
            let mut tokens = self.tokens.write().await;
            tokens.insert(token.accessor.clone(), token.clone());
            Ok(())
        }

        async fn get_token(
            &self,
            accessor: &str,
        ) -> Result<Option<secreton_auth::token::Token>, crate::CoreError> {
            let tokens = self.tokens.read().await;
            Ok(tokens.get(accessor).cloned())
        }

        async fn revoke_token(&self, accessor: &str) -> Result<(), crate::CoreError> {
            let mut tokens = self.tokens.write().await;
            tokens.remove(accessor);
            Ok(())
        }

        async fn list_tokens(&self) -> Result<Vec<secreton_auth::token::Token>, crate::CoreError> {
            let tokens = self.tokens.read().await;
            Ok(tokens.values().cloned().collect())
        }
        async fn store_lease(
            &self,
            lease: &secreton_storage::models::lease::Lease,
        ) -> Result<(), crate::CoreError> {
            let mut leases = self.leases.write().await;
            leases.insert(lease.id.clone(), lease.clone());
            Ok(())
        }

        async fn get_lease(
            &self,
            lease_id: &str,
        ) -> Result<Option<secreton_storage::models::lease::Lease>, crate::CoreError> {
            let leases = self.leases.read().await;
            Ok(leases.get(lease_id).cloned())
        }

        async fn revoke_lease(&self, lease_id: &str) -> Result<(), crate::CoreError> {
            let mut leases = self.leases.write().await;
            leases.remove(lease_id);
            Ok(())
        }

        async fn list_leases(
            &self,
        ) -> Result<Vec<secreton_storage::models::lease::Lease>, crate::CoreError> {
            let leases = self.leases.read().await;
            Ok(leases.values().cloned().collect())
        }
        async fn store_pki_ca(
            &self,
            ca: &crate::models::pki::PkiCa,
        ) -> Result<(), crate::CoreError> {
            let mut pki_cas = self.pki_cas.write().await;
            pki_cas.insert(ca.common_name.clone(), ca.clone());
            Ok(())
        }

        async fn get_pki_ca(
            &self,
            name: &str,
        ) -> Result<Option<crate::models::pki::PkiCa>, crate::CoreError> {
            let pki_cas = self.pki_cas.read().await;
            Ok(pki_cas.get(name).cloned())
        }

        async fn list_pki_cas(&self) -> Result<Vec<String>, crate::CoreError> {
            let pki_cas = self.pki_cas.read().await;
            Ok(pki_cas.keys().cloned().collect())
        }

        async fn delete_pki_ca(&self, name: &str) -> Result<(), crate::CoreError> {
            let mut pki_cas = self.pki_cas.write().await;
            pki_cas.remove(name);
            Ok(())
        }
        async fn store_pki_cert(
            &self,
            cert: &crate::models::pki::PkiCert,
        ) -> Result<(), crate::CoreError> {
            let mut pki_certs = self.pki_certs.write().await;
            pki_certs.insert(cert.serial_number.clone(), cert.clone());
            Ok(())
        }

        async fn get_pki_cert(
            &self,
            serial: &str,
        ) -> Result<Option<crate::models::pki::PkiCert>, crate::CoreError> {
            let pki_certs = self.pki_certs.read().await;
            Ok(pki_certs.get(serial).cloned())
        }

        async fn list_pki_certs(&self) -> Result<Vec<String>, crate::CoreError> {
            let pki_certs = self.pki_certs.read().await;
            Ok(pki_certs.keys().cloned().collect())
        }

        async fn revoke_pki_cert(&self, serial: &str) -> Result<(), crate::CoreError> {
            let mut pki_certs = self.pki_certs.write().await;
            pki_certs.remove(serial);
            Ok(())
        }
        async fn store_plugin(
            &self,
            plugin: &crate::models::plugin::PluginCatalogEntry,
        ) -> Result<(), crate::CoreError> {
            let mut plugins = self.plugins.write().await;
            plugins.insert(plugin.name.clone(), plugin.clone());
            Ok(())
        }

        async fn get_plugin(
            &self,
            name: &str,
        ) -> Result<Option<crate::models::plugin::PluginCatalogEntry>, crate::CoreError> {
            let plugins = self.plugins.read().await;
            Ok(plugins.get(name).cloned())
        }

        async fn list_plugins(&self) -> Result<Vec<String>, crate::CoreError> {
            let plugins = self.plugins.read().await;
            Ok(plugins.keys().cloned().collect())
        }

        async fn delete_plugin(&self, name: &str) -> Result<(), crate::CoreError> {
            let mut plugins = self.plugins.write().await;
            plugins.remove(name);
            Ok(())
        }
        async fn store_sentinel_policy(
            &self,
            policy: &crate::models::sentinel::SentinelPolicy,
        ) -> Result<(), crate::CoreError> {
            let mut sentinel_policies = self.sentinel_policies.write().await;
            sentinel_policies.insert(policy.name.clone(), policy.clone());
            Ok(())
        }

        async fn get_sentinel_policy(
            &self,
            name: &str,
        ) -> Result<Option<crate::models::sentinel::SentinelPolicy>, crate::CoreError> {
            let sentinel_policies = self.sentinel_policies.read().await;
            Ok(sentinel_policies.get(name).cloned())
        }

        async fn list_sentinel_policies(&self) -> Result<Vec<String>, crate::CoreError> {
            let sentinel_policies = self.sentinel_policies.read().await;
            Ok(sentinel_policies.keys().cloned().collect())
        }

        async fn delete_sentinel_policy(&self, name: &str) -> Result<(), crate::CoreError> {
            let mut sentinel_policies = self.sentinel_policies.write().await;
            sentinel_policies.remove(name);
            Ok(())
        }

        async fn store_audit_log(
            &self,
            log: &crate::storage::types::AuditLog,
        ) -> Result<(), crate::CoreError> {
            let mut audit_logs = self.audit_logs.write().await;
            audit_logs.push(log.clone());
            Ok(())
        }

        async fn get_audit_logs(
            &self,
            user: Option<&str>,
            limit: usize,
        ) -> Result<Vec<crate::storage::types::AuditLog>, crate::CoreError> {
            let audit_logs = self.audit_logs.read().await;
            let mut filtered_logs: Vec<_> = if let Some(user_id) = user {
                audit_logs
                    .iter()
                    .filter(|log| log.user.as_deref() == Some(user_id))
                    .cloned()
                    .collect()
            } else {
                audit_logs.clone()
            };

            // Sort by timestamp descending and limit results
            filtered_logs.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
            filtered_logs.truncate(limit);
            Ok(filtered_logs)
        }
        async fn is_sealed(&self) -> Result<bool, crate::CoreError> {
            let is_sealed = self.is_sealed.read().await;
            Ok(*is_sealed)
        }

        async fn seal(&self) -> Result<(), crate::CoreError> {
            let mut is_sealed = self.is_sealed.write().await;
            *is_sealed = true;
            Ok(())
        }

        async fn unseal(&self, _key: &str) -> Result<bool, crate::CoreError> {
            // In a real implementation, we'd verify the key
            // For the mock, we'll just unseal
            let mut is_sealed = self.is_sealed.write().await;
            *is_sealed = false;
            Ok(true)
        }

        async fn store_master_key(&self, key: &[u8]) -> Result<(), crate::CoreError> {
            let mut master_key = self.master_key.write().await;
            *master_key = Some(key.to_vec());
            Ok(())
        }

        async fn get_master_key(&self) -> Result<Option<Vec<u8>>, crate::CoreError> {
            let master_key = self.master_key.read().await;
            Ok(master_key.clone())
        }

        async fn register_audit_device(
            &self,
            device: Box<dyn secreton_security::policies::audit::AuditDevice>,
        ) -> Result<(), crate::CoreError> {
            // For mock purposes, we'll store by a generated name
            let name = format!("device_{}", self.audit_devices.read().await.len());
            let mut audit_devices = self.audit_devices.write().await;
            audit_devices.insert(name, device);
            Ok(())
        }

        async fn get_audit_devices(
            &self,
        ) -> Result<Vec<Box<dyn secreton_security::policies::audit::AuditDevice>>, crate::CoreError>
        {
            // For mock purposes, return empty vector since we can't easily clone boxed trait objects
            // In a real implementation, this would return actual device references
            Ok(vec![])
        }

        async fn enable_audit_device(&self, _name: &str) -> Result<(), crate::CoreError> {
            // Mock implementation - in real implementation would enable the device
            Ok(())
        }

        async fn disable_audit_device(&self, _name: &str) -> Result<(), crate::CoreError> {
            // Mock implementation - in real implementation would disable the device
            Ok(())
        }

        async fn check_policy(
            &self,
            _username: &str,
            _path: &str,
            _action: &str,
        ) -> Result<bool, crate::CoreError> {
            // Mock implementation - always allow
            Ok(true)
        }

        async fn insert_token(
            &self,
            _user: &str,
            _token: &str,
            _expires_at: Option<&str>,
        ) -> Result<(), crate::CoreError> {
            // Mock implementation
            Ok(())
        }

        async fn is_token_valid(&self, _token: &str) -> Result<bool, crate::CoreError> {
            // Mock implementation - always valid
            Ok(true)
        }

        async fn log_audit(
            &self,
            _user: &str,
            _action: &str,
            _path: &str,
            _status: &str,
        ) -> Result<(), crate::CoreError> {
            // Mock implementation
            Ok(())
        }

        async fn get_policies_for_user(
            &self,
            _user_id: &str,
            _entity_alias: Option<&str>,
        ) -> Result<Vec<secreton_security::policies::policy::Policy>, crate::CoreError> {
            // Mock implementation
            Ok(vec![])
        }

        async fn insert_sentinel_policy_version(
            &self,
            _p: &crate::models::sentinel::SentinelPolicy,
        ) -> Result<(), crate::CoreError> {
            // Mock implementation
            Ok(())
        }

        async fn list_sentinel_policy_versions(
            &self,
            _namespace: &str,
            _name: &str,
        ) -> Result<Vec<crate::models::sentinel::SentinelPolicy>, crate::CoreError> {
            // Mock implementation
            Ok(vec![])
        }

        async fn delete_sentinel_policy_version(
            &self,
            _namespace: &str,
            _name: &str,
            _version: u32,
        ) -> Result<(), crate::CoreError> {
            // Mock implementation
            Ok(())
        }

        async fn delete_secret(
            &self,
            _path: &str,
            _namespace: &str,
        ) -> Result<(), crate::CoreError> {
            // Mock implementation
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_create_and_retrieve_secret() {
        // Setup secure storage with a test key
        let secure_storage = SharedSecureStorage::new(
            SecureStorage::new_with_keystore(
                b"test-master-key-secret-32-bytes",
                std::sync::Arc::new(crate::storage::secure::MemoryKeyStore::new()),
                None,
            )
            .await
            .unwrap(),
        );

        // Setup mock storage backend
        let backend = Arc::new(MockStorageBackend::new());

        // Create secret manager
        let manager = SecretManager::new(backend, secure_storage);

        // Test data
        let path = "test/secret";
        let data = json!({ "username": "testuser", "password": "testpass" });

        // Create secret
        let metadata = manager
            .create_secret(path, data.clone(), "test-user", None)
            .await
            .expect("Failed to create secret");

        assert_eq!(metadata.path, path);
        assert_eq!(metadata.current_version, 1);

        // Retrieve secret
        let secret = manager
            .get_secret(path)
            .await
            .expect("Failed to get secret")
            .expect("Secret not found");

        // Verify data
        assert_eq!(secret.data, data);
        assert_eq!(secret.version, 1);
    }
}
