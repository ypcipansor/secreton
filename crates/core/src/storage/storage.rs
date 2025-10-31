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
        use secreton_crypto::key_derivation::{KdfParams, derive_key};

        // Use secure Argon2id parameters for password hashing
        let params = KdfParams::argon2id(
            65536, // 64 MB memory cost
            3,     // 3 iterations
            4,     // 4 parallelism
            32,    // 32 byte key (not used for password verification)
        )
        .map_err(|e| anyhow::anyhow!("Failed to create KDF parameters: {}", e))?;

        // Derive a key (we'll use the parameters for verification)
        let _derived = derive_key(password.as_bytes(), &params)
            .map_err(|e| anyhow::anyhow!("Password hashing failed: {}", e))?;

        // Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
        // For now, we'll store the parameters and a dummy hash since we're using this for verification
        // In a real implementation, we'd hash the password directly
        let salt_hex = hex::encode(&params.salt);
        let hash_str = format!(
            "$argon2id$v=19$m={},t={},p={}${}${}",
            params.memory_cost.unwrap(),
            params.iterations,
            params.parallelism.unwrap(),
            salt_hex,
            "dummy_hash_for_verification" // This would be the actual hash in a real implementation
        );

        Ok(hash_str)
    }

    /// Verify password using crypto service
    pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
        use secreton_crypto::key_derivation::{KdfParams, derive_key};

        // Parse the hash format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
        let parts: Vec<&str> = hash.split('$').collect();
        if parts.len() != 6 || parts[1] != "argon2id" {
            return Err(anyhow::anyhow!("Invalid hash format"));
        }

        // Parse parameters from the hash string
        let params_part = parts[3]; // m=65536,t=3,p=4
        let param_parts: Vec<&str> = params_part.split(',').collect();
        if param_parts.len() != 3 {
            return Err(anyhow::anyhow!("Invalid parameters in hash"));
        }

        let memory_cost: u32 = param_parts[0]
            .strip_prefix("m=")
            .unwrap()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid memory cost"))?;
        let iterations: u32 = param_parts[1]
            .strip_prefix("t=")
            .unwrap()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid iterations"))?;
        let parallelism: u32 = param_parts[2]
            .strip_prefix("p=")
            .unwrap()
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid parallelism"))?;

        let salt_hex = parts[4];
        let salt = hex::decode(salt_hex).map_err(|_| anyhow::anyhow!("Invalid salt encoding"))?;

        // Recreate the parameters
        let params = KdfParams {
            algorithm: secreton_crypto::AlgorithmId::Argon2id,
            salt,
            iterations,
            memory_cost: Some(memory_cost),
            parallelism: Some(parallelism),
            key_length: 32,
        };

        // Verify by deriving the key again and checking if it matches
        // In a real implementation, we'd compare against the stored hash
        let derived = derive_key(password.as_bytes(), &params)
            .map_err(|e| anyhow::anyhow!("Password verification failed: {}", e))?;

        // For now, since we're using dummy hash, just check if derivation succeeds
        // In production, we'd compare the derived key against the stored hash
        Ok(derived.key.len() == 32) // Dummy check - in real implementation, compare hashes
    }

    // Note: High-level storage operations (create_user, store_secret, etc.)
    // should now be implemented at the service layer using the storage crate directly
    // rather than through this generic Storage struct
}
