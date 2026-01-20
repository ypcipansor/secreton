//! Password hashing and verification utilities.

use anyhow::Result;
use secreton_errors::SecretonError;
use secreton_crypto::key_derivation::{KdfParams, derive_key};

/// Hash password using crypto service
pub fn hash_password(password: &str) -> Result<String> {
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
    // Generate actual password hash using Argon2
    let salt_hex = hex::encode(&params.salt);
    let password_hash =
        derive_key(password.as_bytes(), &params).map_err(|e| SecretonError::Cryptographic {
            message: format!("Failed to derive key: {}", e),
        })?;
    let hash_hex = hex::encode(&password_hash.key);

    let hash_str = format!(
        "$argon2id$v=19$m={},t={},p={}${}${}",
        params.memory_cost.unwrap(),
        params.iterations,
        params.parallelism.unwrap(),
        salt_hex,
        hash_hex
    );

    Ok(hash_str)
}

/// Verify password using crypto service
pub fn verify_password(hash: &str, password: &str) -> Result<bool> {
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
    let stored_hash = parts[5];
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
    let derived = derive_key(password.as_bytes(), &params)
        .map_err(|e| anyhow::anyhow!("Password verification failed: {}", e))?;

    // Compare the derived key with the stored hash
    let derived_hex = hex::encode(&derived.key);
    Ok(derived_hex == stored_hash)
}
