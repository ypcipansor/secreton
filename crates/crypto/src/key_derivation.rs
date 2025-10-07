//! Key derivation functions for secure password-based key generation

use crate::{generate_random_bytes, AlgorithmId, CryptoError, CryptoResult};
use argon2::{Algorithm, Argon2, Params, Version};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// Key derivation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub algorithm: AlgorithmId,
    pub salt: Vec<u8>,
    pub iterations: u32,
    pub memory_cost: Option<u32>, // For Argon2
    pub parallelism: Option<u32>, // For Argon2
    pub key_length: usize,
}

impl KdfParams {
    /// Create secure parameters for PBKDF2
    pub fn pbkdf2(iterations: u32, key_length: usize) -> CryptoResult<Self> {
        let salt = generate_random_bytes(16)?;
        Ok(Self {
            algorithm: AlgorithmId::Pbkdf2,
            salt,
            iterations,
            memory_cost: None,
            parallelism: None,
            key_length,
        })
    }

    /// Create secure parameters for Argon2id
    pub fn argon2id(
        memory_cost: u32,
        iterations: u32,
        parallelism: u32,
        key_length: usize,
    ) -> CryptoResult<Self> {
        let salt = generate_random_bytes(16)?;
        Ok(Self {
            algorithm: AlgorithmId::Argon2id,
            salt,
            iterations,
            memory_cost: Some(memory_cost),
            parallelism: Some(parallelism),
            key_length,
        })
    }

    /// Create default secure parameters for Argon2id
    pub fn argon2id_default(key_length: usize) -> CryptoResult<Self> {
        Self::argon2id(65536, 3, 1, key_length) // 64MB, 3 iterations, 1 thread
    }

    /// Validate parameters for security
    pub fn validate(&self) -> CryptoResult<()> {
        match self.algorithm {
            AlgorithmId::Pbkdf2 => {
                if self.iterations < 100_000 {
                    return Err(CryptoError::KeyGenerationFailed(format!(
                        "PBKDF2 iterations too low: {} (minimum 100,000)",
                        self.iterations
                    )));
                }
            }
            AlgorithmId::Argon2id => {
                if self.memory_cost.unwrap_or(0) < 65536 {
                    return Err(CryptoError::KeyGenerationFailed(
                        "Argon2id memory cost too low (minimum 64MB)".to_string(),
                    ));
                }
                if self.iterations < 3 {
                    return Err(CryptoError::KeyGenerationFailed(
                        "Argon2id iterations too low (minimum 3)".to_string(),
                    ));
                }
            }
            _ => {
                return Err(CryptoError::KeyGenerationFailed(format!(
                    "Unsupported KDF algorithm: {}",
                    self.algorithm
                )));
            }
        }

        if self.salt.len() < 16 {
            return Err(CryptoError::KeyGenerationFailed(
                "Salt too short (minimum 16 bytes)".to_string(),
            ));
        }

        if self.key_length < 16 {
            return Err(CryptoError::KeyGenerationFailed(
                "Key length too short (minimum 16 bytes)".to_string(),
            ));
        }

        Ok(())
    }
}

/// Key derivation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DerivedKey {
    pub algorithm: AlgorithmId,
    pub key: Vec<u8>,
    pub params: KdfParams,
}

impl DerivedKey {
    pub fn new(algorithm: AlgorithmId, key: Vec<u8>, params: KdfParams) -> Self {
        Self {
            algorithm,
            key,
            params,
        }
    }

    /// Verify that a password produces this key
    pub fn verify_password(&self, password: &str) -> CryptoResult<bool> {
        let derived = derive_key(password.as_bytes(), &self.params)?;
        Ok(derived.key == self.key)
    }
}

/// PBKDF2 key derivation
pub fn derive_key_pbkdf2(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_length: usize,
) -> CryptoResult<Vec<u8>> {
    let mut key = vec![0u8; key_length];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    Ok(key)
}

/// Argon2id key derivation
pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8],
    memory_cost: u32,
    iterations: u32,
    parallelism: u32,
    key_length: usize,
) -> CryptoResult<Vec<u8>> {
    let params =
        Params::new(memory_cost, iterations, parallelism, Some(key_length)).map_err(|e| {
            CryptoError::KeyGenerationFailed(format!("Invalid Argon2 parameters: {}", e))
        })?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = vec![0u8; key_length];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| {
            CryptoError::KeyGenerationFailed(format!("Argon2id key derivation failed: {}", e))
        })?;

    Ok(key)
}

/// Generic key derivation function
pub fn derive_key(password: &[u8], params: &KdfParams) -> CryptoResult<DerivedKey> {
    params.validate()?;

    let key = match params.algorithm {
        AlgorithmId::Pbkdf2 => {
            derive_key_pbkdf2(password, &params.salt, params.iterations, params.key_length)?
        }
        AlgorithmId::Argon2id => derive_key_argon2id(
            password,
            &params.salt,
            params.memory_cost.unwrap(),
            params.iterations,
            params.parallelism.unwrap(),
            params.key_length,
        )?,
        _ => {
            return Err(CryptoError::KeyGenerationFailed(format!(
                "Unsupported KDF algorithm: {}",
                params.algorithm
            )));
        }
    };

    Ok(DerivedKey::new(params.algorithm, key, params.clone()))
}

/// Convenient functions for common use cases
pub mod presets {
    use super::*;

    /// Derive AES-256 key from password using PBKDF2
    pub fn derive_aes256_pbkdf2(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::pbkdf2(100_000, 32)?;
        derive_key(password.as_bytes(), &params)
    }

    /// Derive AES-256 key from password using Argon2id (fast)
    pub fn derive_aes256_argon2_fast(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id(8192, 1, 1, 32)?; // 8MB, 1 iteration
        derive_key(password.as_bytes(), &params)
    }

    /// Derive AES-256 key from password using Argon2id (secure)
    pub fn derive_aes256_argon2_secure(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id_default(32)?;
        derive_key(password.as_bytes(), &params)
    }

    /// Derive ChaCha20 key from password using Argon2id
    pub fn derive_chacha20_argon2(password: &str) -> CryptoResult<DerivedKey> {
        let params = KdfParams::argon2id_default(32)?;
        derive_key(password.as_bytes(), &params)
    }
}

/// Key stretching utilities
pub mod stretch {
    use super::*;

    /// Simple key stretching for existing keys (not password-based)
    pub fn stretch_key_sha256(key: &[u8], iterations: u32) -> CryptoResult<Vec<u8>> {
        if iterations == 0 {
            return Err(CryptoError::KeyGenerationFailed(
                "Iterations must be greater than 0".to_string(),
            ));
        }

        let mut result = key.to_vec();
        for _ in 0..iterations {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&result);
            result = hasher.finalize().to_vec();
        }

        Ok(result)
    }

    /// Generate multiple keys from a master key using HKDF-like derivation
    pub fn derive_multiple_keys(
        master_key: &[u8],
        info_list: &[&str],
        key_length: usize,
    ) -> CryptoResult<Vec<Vec<u8>>> {
        let mut keys = Vec::new();

        for (index, info) in info_list.iter().enumerate() {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(master_key);
            hasher.update((index as u32).to_be_bytes());
            hasher.update(info.as_bytes());

            let hash = hasher.finalize();
            let mut key = hash.to_vec();

            // Stretch to desired length if needed
            while key.len() < key_length {
                let mut hasher = Sha256::new();
                hasher.update(&key);
                hasher.update([key.len() as u8]);
                key.extend_from_slice(&hasher.finalize());
            }

            key.truncate(key_length);
            keys.push(key);
        }

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_key_derivation() {
        let password = "test_password_123";
        let params = KdfParams::pbkdf2(100_000, 32).unwrap();

        let derived = derive_key(password.as_bytes(), &params).unwrap();

        assert_eq!(derived.key.len(), 32);
        assert_eq!(derived.algorithm, AlgorithmId::Pbkdf2);
        assert!(derived.verify_password(password).unwrap());
        assert!(!derived.verify_password("wrong_password").unwrap());
    }

    #[test]
    fn test_argon2id_key_derivation() {
        let password = "secure_password";
        let params = KdfParams::argon2id_default(32).unwrap();

        let derived = derive_key(password.as_bytes(), &params).unwrap();

        assert_eq!(derived.key.len(), 32);
        assert_eq!(derived.algorithm, AlgorithmId::Argon2id);
        assert!(derived.verify_password(password).unwrap());
    }

    #[test]
    fn test_parameter_validation() {
        // Test weak parameters
        let weak_pbkdf2 = KdfParams::pbkdf2(1000, 32).unwrap(); // Too few iterations
        assert!(weak_pbkdf2.validate().is_err());

        // Test strong parameters
        let strong_pbkdf2 = KdfParams::pbkdf2(100_000, 32).unwrap();
        assert!(strong_pbkdf2.validate().is_ok());
    }

    #[test]
    fn test_preset_functions() {
        let password = "my_secure_password";

        let aes_pbkdf2 = presets::derive_aes256_pbkdf2(password).unwrap();
        assert_eq!(aes_pbkdf2.key.len(), 32);

        let aes_argon2 = presets::derive_aes256_argon2_secure(password).unwrap();
        assert_eq!(aes_argon2.key.len(), 32);

        // Same password should produce different keys with different salts
        let aes_argon2_2 = presets::derive_aes256_argon2_secure(password).unwrap();
        assert_ne!(aes_argon2.key, aes_argon2_2.key);
    }

    #[test]
    fn test_key_stretching() {
        let original_key = b"original_key_data";
        let stretched = stretch::stretch_key_sha256(original_key, 1000).unwrap();

        assert_eq!(stretched.len(), 32); // SHA-256 output length
        assert_ne!(stretched, original_key);
    }

    #[test]
    fn test_multiple_key_derivation() {
        let master_key = b"master_key_for_derivation";
        let info_list = &["encryption", "authentication", "signing"];

        let keys = stretch::derive_multiple_keys(master_key, info_list, 32).unwrap();

        assert_eq!(keys.len(), 3);
        for key in &keys {
            assert_eq!(key.len(), 32);
        }

        // All keys should be different
        assert_ne!(keys[0], keys[1]);
        assert_ne!(keys[1], keys[2]);
        assert_ne!(keys[0], keys[2]);
    }
}
