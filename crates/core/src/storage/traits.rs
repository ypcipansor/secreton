//! Storage traits and interfaces
//!
//! This module defines the core traits that storage backends must implement.

use crate::CoreError;
use crate::models::plugin::PluginCatalogEntry;
use async_trait::async_trait;
use secreton_auth::MfaMethod;
use serde_json::Value;
use std::any::Any;
use std::collections::HashMap;

// Import the actual types from their respective crates
use crate::models::pki::{PkiCa, PkiCert};
use crate::models::sentinel::SentinelPolicy;
use secreton_auth::token::Token;
use secreton_security::policies::audit::AuditDevice;
use secreton_security::policies::policy::Policy;
use secreton_storage::models::lease::Lease;

use super::types::StorageEntry;

// Storage engine trait for simple key-value operations
#[async_trait]
pub trait StorageEngine: Send + Sync + 'static {
    async fn get(&self, key: &str) -> Result<Option<StorageEntry>, CoreError>;
    async fn put(&self, entry: StorageEntry) -> Result<(), CoreError>;
    async fn delete(&self, key: &str) -> Result<(), CoreError>;
    async fn list(&self, prefix: &str) -> Result<Vec<String>, CoreError>;
}

/// Comprehensive storage backend trait
#[async_trait]
pub trait StorageBackend: Send + Sync {
    fn as_any(&self) -> &dyn Any;

    // MFA related methods
    async fn store_mfa_secret(
        &self,
        user_id: &str,
        secret: &str,
        method: MfaMethod,
    ) -> Result<(), CoreError>;
    async fn get_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<String, CoreError>;
    async fn delete_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError>;
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool, CoreError>;
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>, CoreError>;
    async fn get_mfa_status(&self, user_id: &str) -> Result<HashMap<MfaMethod, bool>, CoreError>;
    async fn enable_mfa(&self, user_id: &str, method: MfaMethod) -> Result<(), CoreError>;
    async fn disable_mfa(&self, user_id: &str) -> Result<(), CoreError>;
    async fn store_mfa_recovery_codes(
        &self,
        user_id: &str,
        codes: &[String],
    ) -> Result<(), CoreError>;
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>, CoreError>;

    // Secret versioning methods
    async fn store_secret_versioned(&self, path: &str, data: &Value) -> Result<u32, CoreError>;
    async fn get_latest_secret(&self, path: &str) -> Result<Option<(Value, u32)>, CoreError>;
    async fn get_secret_versions(&self, path: &str) -> Result<Vec<(u32, Value)>, CoreError>;
    async fn delete_secret_version(&self, path: &str, version: u32) -> Result<(), CoreError>;
    async fn delete_secret(&self, path: &str, namespace: &str) -> Result<(), CoreError>;

    // User management methods
    async fn create_user(&self, username: &str, password: &str) -> Result<(), CoreError>;
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<bool, CoreError>;
    async fn assign_role_to_user(&self, username: &str, role: &str) -> Result<(), CoreError>;
    async fn add_policy_to_role(&self, role: &str, policy: &str) -> Result<(), CoreError>;
    async fn get_user_roles(&self, username: &str) -> Result<Vec<String>, CoreError>;
    async fn get_role_policies(&self, role: &str) -> Result<Vec<String>, CoreError>;

    // Policy management methods
    async fn store_policy(&self, name: &str, policy: &Policy) -> Result<(), CoreError>;
    async fn get_policy(&self, name: &str) -> Result<Option<Policy>, CoreError>;
    async fn list_policies(&self) -> Result<Vec<String>, CoreError>;
    async fn delete_policy(&self, name: &str) -> Result<(), CoreError>;

    // Additional policy methods
    async fn check_policy(&self, username: &str, path: &str, action: &str) -> Result<bool, CoreError>;
    async fn get_policies_for_user(&self, user_id: &str, entity_alias: Option<&str>) -> Result<Vec<Policy>, CoreError>;

    // Token management methods
    async fn store_token(&self, token: &Token) -> Result<(), CoreError>;
    async fn get_token(&self, accessor: &str) -> Result<Option<Token>, CoreError>;
    async fn revoke_token(&self, accessor: &str) -> Result<(), CoreError>;
    async fn list_tokens(&self) -> Result<Vec<Token>, CoreError>;
    async fn insert_token(&self, user: &str, token: &str, expires_at: Option<&str>) -> Result<(), CoreError>;
    async fn is_token_valid(&self, token: &str) -> Result<bool, CoreError>;

    // Lease management methods
    async fn store_lease(&self, lease: &Lease) -> Result<(), CoreError>;
    async fn get_lease(&self, lease_id: &str) -> Result<Option<Lease>, CoreError>;
    async fn revoke_lease(&self, lease_id: &str) -> Result<(), CoreError>;
    async fn list_leases(&self) -> Result<Vec<Lease>, CoreError>;

    // PKI management methods
    async fn store_pki_ca(&self, ca: &PkiCa) -> Result<(), CoreError>;
    async fn get_pki_ca(&self, name: &str) -> Result<Option<PkiCa>, CoreError>;
    async fn list_pki_cas(&self) -> Result<Vec<String>, CoreError>;
    async fn delete_pki_ca(&self, name: &str) -> Result<(), CoreError>;
    async fn store_pki_cert(&self, cert: &PkiCert) -> Result<(), CoreError>;
    async fn get_pki_cert(&self, serial: &str) -> Result<Option<PkiCert>, CoreError>;
    async fn list_pki_certs(&self) -> Result<Vec<String>, CoreError>;
    async fn revoke_pki_cert(&self, serial: &str) -> Result<(), CoreError>;

    // Plugin management methods
    async fn store_plugin(&self, plugin: &PluginCatalogEntry) -> Result<(), CoreError>;
    async fn get_plugin(&self, name: &str) -> Result<Option<PluginCatalogEntry>, CoreError>;
    async fn list_plugins(&self) -> Result<Vec<String>, CoreError>;
    async fn delete_plugin(&self, name: &str) -> Result<(), CoreError>;

    // Sentinel policy management methods
    async fn store_sentinel_policy(&self, policy: &SentinelPolicy) -> Result<(), CoreError>;
    async fn get_sentinel_policy(&self, name: &str) -> Result<Option<SentinelPolicy>, CoreError>;
    async fn list_sentinel_policies(&self) -> Result<Vec<String>, CoreError>;
    async fn delete_sentinel_policy(&self, name: &str) -> Result<(), CoreError>;
    async fn insert_sentinel_policy_version(&self, p: &SentinelPolicy) -> Result<(), CoreError>;
    async fn list_sentinel_policy_versions(&self, namespace: &str, name: &str) -> Result<Vec<SentinelPolicy>, CoreError>;
    async fn delete_sentinel_policy_version(&self, namespace: &str, name: &str, version: u32) -> Result<(), CoreError>;

    // Audit logging methods
    async fn store_audit_log(&self, log: &super::types::AuditLog) -> Result<(), CoreError>;
    async fn get_audit_logs(
        &self,
        user: Option<&str>,
        limit: usize,
    ) -> Result<Vec<super::types::AuditLog>, CoreError>;
    async fn log_audit(&self, user: &str, action: &str, path: &str, status: &str) -> Result<(), CoreError>;

    // Secret state management methods
    async fn is_sealed(&self) -> Result<bool, CoreError>;
    async fn seal(&self) -> Result<(), CoreError>;
    async fn unseal(&self, key: &str) -> Result<bool, CoreError>;
    async fn store_master_key(&self, key: &[u8]) -> Result<(), CoreError>;
    async fn get_master_key(&self) -> Result<Option<Vec<u8>>, CoreError>;

    // Audit device management methods
    async fn register_audit_device(&self, device: Box<dyn AuditDevice>) -> Result<(), CoreError>;
    async fn get_audit_devices(&self) -> Result<Vec<Box<dyn AuditDevice>>, CoreError>;
    async fn enable_audit_device(&self, name: &str) -> Result<(), CoreError>;
    async fn disable_audit_device(&self, name: &str) -> Result<(), CoreError>;
}
