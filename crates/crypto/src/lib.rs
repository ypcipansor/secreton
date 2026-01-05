//! Secreton Cryptographic Library
//!
//! High-performance, secure cryptographic primitives and protocols
//! with comprehensive RustCrypto integration and transit engine support.

use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fmt;
use pkcs8::EncodePrivateKey;

pub mod advanced_key_manager;
pub mod authenticated_key_operations;
pub mod crypto_policy_engine;
pub mod cryptography;
pub mod encryption;
pub mod error;
pub mod hashing;
pub mod homomorphic_encryption;
pub mod key_derivation;
pub mod key_manager;
pub mod kmip;
pub mod kv_engine;
pub mod policy_enforced_crypto;
// pub mod pqc; // Disabled for now
pub mod secure_multi_party_computation;
pub mod shamir;
pub mod transit;

// Integration modules are now enabled
pub mod integration;

pub use advanced_key_manager::{
    AdvancedKeyManager, KeyManagerError, KeyState as AdvancedKeyState, KeyType as AdvancedKeyType,
};
pub use authenticated_key_operations::{
    AuthenticatedKeyError, AuthenticatedKeyOperations, KeyOperation, KeyOperationRequest,
    KeyOperationResult, KeyPermission, MetricType,
};
pub use crypto_policy_engine::{
    AlgorithmMetadata, AlgorithmStatus, ComplianceStandard, ComplianceStatus, CryptoAlgorithm,
    CryptoAudit, CryptoInventoryItem, CryptoOperationRequest, CryptoPolicy, CryptoPolicyEngine,
    PolicyError,
};
pub use cryptography::*;
pub use encryption::*;
pub use error::*;
pub use homomorphic_encryption::{Ciphertext, HEError, HESystem};
pub use key_derivation::{DerivedKey, KdfParams, derive_key};
pub use key_manager::*;
pub use kmip::{KeyState as KmipKeyState, KmipClient};
pub use kv_engine::*;
pub use policy_enforced_crypto::{
    ComplianceScanResult, ComplianceViolation, EncryptedSecret, MigrationPlan, MigrationProgress,
    PolicyEnforcedCryptoOperations, PolicyEnforcedEncryptionRequest, PolicyEnforcementError,
    RemediationStatus, ViolationType,
};
pub use secure_multi_party_computation::{
    ComputationRequest, ComputationResult, DKGResult, PartialSignature, Participant, SMPCError,
    SMPCProtocol, SMPCSession, SMPCSystem, SecretShare, SessionState, ThresholdSignature,
};
pub use shamir::*;
pub use transit::TransitEngine;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AlgorithmId {
    // Symmetric encryption
    Aes256Gcm,
    ChaCha20Poly1305,

    // Asymmetric encryption / signing
    Rsa2048,
    Rsa4096,
    EcdsaP256,
    EcdsaP384,
    Ed25519,

    // Hash functions
    Sha256,
    Sha3_256,
    Blake3,

    // Key derivation
    Pbkdf2,
    Argon2id,
}

impl fmt::Display for AlgorithmId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            AlgorithmId::Aes256Gcm => "AES-256-GCM",
            AlgorithmId::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AlgorithmId::Rsa2048 => "RSA-2048",
            AlgorithmId::Rsa4096 => "RSA-4096",
            AlgorithmId::EcdsaP256 => "ECDSA-P256",
            AlgorithmId::EcdsaP384 => "ECDSA-P384",
            AlgorithmId::Ed25519 => "Ed25519",
            AlgorithmId::Sha256 => "SHA-256",
            AlgorithmId::Sha3_256 => "SHA3-256",
            AlgorithmId::Blake3 => "BLAKE3",
            AlgorithmId::Pbkdf2 => "PBKDF2",
            AlgorithmId::Argon2id => "Argon2id",
        };
        write!(f, "{}", name)
    }
}

/// Security parameters for cryptographic operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityParams {
    pub algorithm: AlgorithmId,
    pub key_size: usize,
    pub iterations: Option<u32>,
    pub salt_size: Option<usize>,
}

impl SecurityParams {
    /// Create security parameters for a given algorithm
    pub fn new(algorithm: AlgorithmId) -> Self {
        let (key_size, iterations, salt_size) = match algorithm {
            AlgorithmId::Aes256Gcm => (32, None, Some(12)),
            AlgorithmId::ChaCha20Poly1305 => (32, None, Some(12)),
            AlgorithmId::Rsa2048 => (256, None, None),
            AlgorithmId::Rsa4096 => (512, None, None),
            AlgorithmId::EcdsaP256 => (32, None, None),
            AlgorithmId::EcdsaP384 => (48, None, None),
            AlgorithmId::Ed25519 => (32, None, None),
            AlgorithmId::Sha256 => (32, None, None),
            AlgorithmId::Sha3_256 => (32, None, None),
            AlgorithmId::Blake3 => (32, None, None),
            AlgorithmId::Pbkdf2 => (32, Some(100_000), Some(16)),
            AlgorithmId::Argon2id => (32, Some(3), Some(16)),
        };

        Self {
            algorithm,
            key_size,
            iterations,
            salt_size,
        }
    }

    /// Check if parameters are secure for production use
    pub fn is_secure(&self) -> bool {
        match self.algorithm {
            AlgorithmId::Aes256Gcm | AlgorithmId::ChaCha20Poly1305 => self.key_size >= 32,
            AlgorithmId::Rsa2048 => self.key_size >= 256,
            AlgorithmId::Rsa4096 => self.key_size >= 512,
            AlgorithmId::EcdsaP256 => self.key_size >= 32,
            AlgorithmId::EcdsaP384 => self.key_size >= 48,
            AlgorithmId::Ed25519 => self.key_size >= 32,
            AlgorithmId::Pbkdf2 => self.iterations.unwrap_or(0) >= 100_000 && self.key_size >= 32,
            AlgorithmId::Argon2id => self.iterations.unwrap_or(0) >= 3 && self.key_size >= 32,
            _ => true,
        }
    }
}

/// Generate cryptographically secure random bytes
pub fn generate_random_bytes(len: usize) -> CryptoResult<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| CryptoError::RandomGenerationFailed)?;
    Ok(bytes)
}

/// Generate a random key for the specified algorithm
pub fn generate_key(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);

    match algorithm {
        AlgorithmId::Rsa2048 | AlgorithmId::Rsa4096 => {
            let bit_size = params.key_size * 8;
            let private_key = rsa::RsaPrivateKey::new(&mut OsRng, bit_size)
                .map_err(|e| CryptoError::KeyGenerationFailed(format!("RSA generation failed: {}", e)))?;

            let doc = private_key.to_pkcs8_der()
                .map_err(|e| CryptoError::KeyGenerationFailed(format!("RSA PKCS8 encoding failed: {}", e)))?;

            Ok(doc.as_bytes().to_vec())
        },
        AlgorithmId::EcdsaP256 => {
            let secret_key = p256::SecretKey::random(&mut OsRng);
            let doc = secret_key.to_pkcs8_der()
                .map_err(|e| CryptoError::KeyGenerationFailed(format!("ECDSA P-256 PKCS8 encoding failed: {}", e)))?;
            Ok(doc.as_bytes().to_vec())
        },
        AlgorithmId::EcdsaP384 => {
            let secret_key = p384::SecretKey::random(&mut OsRng);
            let doc = secret_key.to_pkcs8_der()
                .map_err(|e| CryptoError::KeyGenerationFailed(format!("ECDSA P-384 PKCS8 encoding failed: {}", e)))?;
            Ok(doc.as_bytes().to_vec())
        },
        AlgorithmId::Ed25519 => {
            // ed25519-dalek might not have 'rand' or 'pkcs8' feature enabled in workspace
            // Use explicit random generation and from_bytes
            let mut seed = [0u8; 32];
            OsRng.fill_bytes(&mut seed);

            // We return the raw 32-byte seed as the private key for Ed25519.
            // This avoids dependency on the 'pkcs8' feature of ed25519-dalek which might be missing.
            Ok(seed.to_vec())
        },
        _ => generate_random_bytes(params.key_size),
    }
}

/// Generate a random nonce/IV for the specified algorithm
pub fn generate_nonce(algorithm: AlgorithmId) -> CryptoResult<Vec<u8>> {
    let params = SecurityParams::new(algorithm);
    if let Some(nonce_size) = params.salt_size {
        generate_random_bytes(nonce_size)
    } else {
        Err(CryptoError::InvalidNonceLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_params_for_symmetric_algorithms() {
        let aes_params = SecurityParams::new(AlgorithmId::Aes256Gcm);
        assert_eq!(aes_params.key_size, 32);
        assert_eq!(aes_params.iterations, None);
        assert_eq!(aes_params.salt_size, Some(12));
        assert!(aes_params.is_secure());

        let chacha_params = SecurityParams::new(AlgorithmId::ChaCha20Poly1305);
        assert_eq!(chacha_params.key_size, 32);
        assert!(chacha_params.is_secure());
    }

    #[test]
    fn test_security_params_for_kdf_algorithms() {
        let pbkdf2_params = SecurityParams::new(AlgorithmId::Pbkdf2);
        assert_eq!(pbkdf2_params.iterations, Some(100_000));
        assert!(pbkdf2_params.is_secure());

        let mut unsafe_pbkdf2 = pbkdf2_params.clone();
        unsafe_pbkdf2.iterations = Some(10_000);
        assert!(!unsafe_pbkdf2.is_secure());

        let argon_params = SecurityParams::new(AlgorithmId::Argon2id);
        assert_eq!(argon_params.iterations, Some(3));
        assert!(argon_params.is_secure());

        let mut unsafe_argon = argon_params.clone();
        unsafe_argon.iterations = Some(1);
        assert!(!unsafe_argon.is_secure());
    }

    #[test]
    fn test_generate_key_lengths_match_algorithm_requirements() {
        let aes_key = generate_key(AlgorithmId::Aes256Gcm).expect("AES key generation failed");
        assert_eq!(aes_key.len(), 32);

        let argon_key = generate_key(AlgorithmId::Argon2id).expect("Argon2 key generation failed");
        assert_eq!(argon_key.len(), 32);
    }

    #[test]
    fn test_generate_nonce_respects_algorithm_requirements() {
        let aes_nonce = generate_nonce(AlgorithmId::Aes256Gcm).expect("nonce generation failed");
        assert_eq!(aes_nonce.len(), 12);

        let err =
            generate_nonce(AlgorithmId::Sha256).expect_err("expected nonce generation to fail");
        assert_eq!(err, CryptoError::InvalidNonceLength);
    }

    #[test]
    fn test_generate_random_bytes_produces_requested_length() {
        let bytes = generate_random_bytes(64).expect("random generation failed");
        assert_eq!(bytes.len(), 64);
    }
}
