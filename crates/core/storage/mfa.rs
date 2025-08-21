use crate::auth::mfa::MfaMethod;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Represents an MFA secret in the database
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaSecret {
    pub user_id: String,
    pub secret: String,
    pub method: MfaMethod,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Represents MFA recovery codes for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MfaRecoveryCodes {
    pub user_id: String,
    pub codes: Vec<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// MFA storage operations
#[async_trait::async_trait]
pub trait MfaStorage: Send + Sync + 'static {
    /// Store an MFA secret for a user
    async fn store_mfa_secret(&self, user_id: &str, secret: &str, method: MfaMethod) -> Result<()>;

    /// Get the MFA secret for a user
    async fn get_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<String>;

    /// Delete an MFA secret for a user
    async fn delete_mfa_secret(&self, user_id: &str, method: MfaMethod) -> Result<()>;

    /// Check if MFA is enabled for a user
    async fn is_mfa_enabled(&self, user_id: &str) -> Result<bool>;

    /// Enable MFA for a user
    async fn enable_mfa(&self, user_id: &str, method: MfaMethod) -> Result<()>;

    /// Disable MFA for a user
    async fn disable_mfa(&self, user_id: &str) -> Result<()>;

    /// Store recovery codes for a user
    async fn store_mfa_recovery_codes(&self, user_id: &str, codes: &[String]) -> Result<()>;

    /// Get recovery codes for a user
    async fn get_mfa_recovery_codes(&self, user_id: &str) -> Result<Vec<String>>;

    /// Get all MFA methods for a user
    async fn get_user_mfa_methods(&self, user_id: &str) -> Result<Vec<MfaMethod>>;

    /// Get MFA status for a user
    async fn get_mfa_status(&self, user_id: &str) -> Result<HashMap<MfaMethod, bool>>;
}
