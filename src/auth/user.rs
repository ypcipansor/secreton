use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use uuid::Uuid;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand_core::OsRng;
use anyhow::{Result, anyhow};
use std::collections::HashSet;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub is_active: bool,
    pub is_superuser: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_login: Option<DateTime<Utc>>,
    pub mfa_enabled: bool,
    pub roles: HashSet<String>,
}

impl User {
    /// Create a new user with a hashed password
    pub fn new(
        username: String,
        email: String,
        password: &str,
        is_superuser: bool,
    ) -> Result<Self> {
        let password_hash = Self::hash_password(password)?;
        let now = Utc::now();

        Ok(Self {
            id: Uuid::new_v4(),
            username,
            email,
            password_hash,
            is_active: true,
            is_superuser,
            created_at: now,
            updated_at: now,
            last_login: None,
            mfa_enabled: false,
            roles: HashSet::new(),
        })
    }

    /// Hash a password using Argon2
    pub fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();
        let password_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!(e.to_string()))?
            .to_string();
        
        Ok(password_hash)
    }

    /// Verify a password against the stored hash
    pub fn verify_password(&self, password: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(&self.password_hash)
            .map_err(|e| anyhow!(e.to_string()))?;
        
        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }

    /// Update the user's password
    pub fn update_password(&mut self, new_password: &str) -> Result<()> {
        self.password_hash = Self::hash_password(new_password)?;
        self.updated_at = Utc::now();
        Ok(())
    }

    /// Record a successful login
    pub fn record_login(&mut self) {
        self.last_login = Some(Utc::now());
    }

    /// Check if the user has a specific role
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }

    /// Add a role to the user
    pub fn add_role(&mut self, role: &str) -> bool {
        self.roles.insert(role.to_string())
    }

    /// Remove a role from the user
    pub fn remove_role(&mut self, role: &str) -> bool {
        self.roles.remove(role)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_creation() {
        let user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "securepassword123",
            false,
        )
        .unwrap();

        assert_eq!(user.username, "testuser");
        assert_eq!(user.email, "test@example.com");
        assert!(user.verify_password("securepassword123").unwrap());
        assert!(!user.verify_password("wrongpassword").unwrap());
        assert!(user.is_active);
        assert!(!user.is_superuser);
    }

    #[test]
    fn test_password_update() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "oldpassword",
            false,
        )
        .unwrap();

        assert!(user.verify_password("oldpassword").unwrap());
        
        user.update_password("newpassword").unwrap();
        
        assert!(!user.verify_password("oldpassword").unwrap());
        assert!(user.verify_password("newpassword").unwrap());
    }

    #[test]
    fn test_roles() {
        let mut user = User::new(
            "testuser".to_string(),
            "test@example.com".to_string(),
            "password",
            false,
        )
        .unwrap();

        assert!(!user.has_role("admin"));
        
        user.add_role("admin");
        assert!(user.has_role("admin"));
        
        user.remove_role("admin");
        assert!(!user.has_role("admin"));
    }
}
