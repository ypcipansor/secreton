//! Main storage implementation
//!
//! This module provides a high-level storage interface that delegates
//! to the storage crate for actual persistence operations.

use anyhow::Result;

/// Main storage struct that provides high-level storage operations
/// by delegating to the storage crate
#[derive(Clone)]
pub struct Storage {
    // Storage operations are now handled by the storage crate
    // This struct provides high-level business logic on top of storage crate
}

impl Storage {
    /// Create a new storage instance
    /// Note: Actual storage backends are managed by the storage crate
    pub async fn new(_database_url: &str) -> Result<Self> {
        // Storage backends are now created via storage crate factory
        Ok(Self {})
    }

    /// Hash password using crypto service
    pub fn hash_password(password: &str) -> Result<String> {
        use secreton_crypto::hashing::HashingService;

        let result = HashingService::hash_password_argon2(password)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        Ok(result.hash)
    }

    /// Verify password using crypto service
    pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
        use secreton_crypto::hashing::HashingService;

        HashingService::verify_password_argon2(password, hash)
            .map_err(|e| anyhow::anyhow!("Password verification failed: {}", e))
    }

    // Note: High-level storage operations (create_user, store_secret, etc.)
    // should now be implemented at the service layer using the storage crate directly
    // rather than through this generic Storage struct
}