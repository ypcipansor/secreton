use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use uuid::Uuid;

/// Canonical User structure - use this throughout the project
/// All other User definitions should be removed and import this one
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct User {
    /// Unique user ID (UUID for consistency)
    pub id: Uuid,

    /// Username for login
    pub username: String,

    /// Email address
    pub email: String,

    /// Argon2id password hash (never expose in API responses)
    #[serde(skip_serializing)]
    pub password_hash: String,

    /// Full name (optional)
    pub full_name: Option<String>,

    /// Account active status
    pub is_active: bool,

    /// Superuser/admin privileges
    pub is_superuser: bool,

    /// Account creation timestamp
    pub created_at: DateTime<Utc>,

    /// Last update timestamp
    pub updated_at: DateTime<Utc>,

    /// Last successful login
    pub last_login: Option<DateTime<Utc>>,

    /// MFA enabled flag
    pub mfa_enabled: bool,

    /// User roles (set for deduplication)
    pub roles: HashSet<String>,

    /// Namespace/tenant (for multi-tenancy)
    pub namespace: String,

    /// Account locked (due to failed attempts)
    pub is_locked: bool,

    /// Failed login attempts counter
    pub failed_attempts: u32,

    /// Lock expiration time
    pub locked_until: Option<DateTime<Utc>>,
}

impl User {
    /// Create new user with defaults
    pub fn new(username: String, email: String, password_hash: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            full_name: None,
            is_active: true,
            is_superuser: false,
            created_at: now,
            updated_at: now,
            last_login: None,
            mfa_enabled: false,
            roles: HashSet::new(),
            namespace: "default".to_string(),
            is_locked: false,
            failed_attempts: 0,
            locked_until: None,
        }
    }

    /// Check if account is currently locked
    pub fn is_currently_locked(&self) -> bool {
        if !self.is_locked {
            return false;
        }

        if let Some(until) = self.locked_until {
            Utc::now() < until
        } else {
            self.is_locked
        }
    }

    /// Check if user has specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role) || self.is_superuser
    }

    /// Add role to user
    pub fn add_role(&mut self, role: String) {
        self.roles.insert(role);
        self.updated_at = Utc::now();
    }

    /// Remove role from user
    pub fn remove_role(&mut self, role: &str) -> bool {
        let removed = self.roles.remove(role);
        if removed {
            self.updated_at = Utc::now();
        }
        removed
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub token: String,
    pub user: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub orphan: bool,
    pub batch: bool,
    pub locked: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
}
