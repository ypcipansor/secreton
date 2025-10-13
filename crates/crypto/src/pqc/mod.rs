//! Post-Quantum Cryptography (PQC) Module
//!
//! Unified interface for all post-quantum cryptographic algorithms
//! including ML-DSA, ML-KEM, and Falcon implementations.

pub mod constant_time;
pub mod falcon;
pub mod mldsa;
pub mod mlkem;
pub mod zeroize;

use crate::error::CryptoError;
use serde::{Deserialize, Serialize};
use std::fmt;

/// PQC error types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PQCError {
    /// Invalid key provided
    InvalidKey(String),
    /// Signature operation failed
    SignatureError(String),
    /// Verification operation failed
    VerificationError(String),
    /// Key exchange operation failed
    KeyExchangeError(String),
    /// Algorithm not supported
    UnsupportedAlgorithm(String),
    /// Invalid input data
    InvalidInput(String),
}

impl From<PQCError> for CryptoError {
    fn from(err: PQCError) -> Self {
        CryptoError::InvalidInput(err.to_string())
    }
}

impl From<CryptoError> for PQCError {
    fn from(err: CryptoError) -> Self {
        PQCError::InvalidInput(err.to_string())
    }
}

impl fmt::Display for PQCError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PQCError::InvalidKey(msg) => write!(f, "Invalid key: {}", msg),
            PQCError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            PQCError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            PQCError::KeyExchangeError(msg) => write!(f, "Key exchange error: {}", msg),
            PQCError::UnsupportedAlgorithm(msg) => write!(f, "Unsupported algorithm: {}", msg),
            PQCError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
        }
    }
}

impl std::error::Error for PQCError {}

/// Result type for PQC operations
pub type PQCResult<T> = Result<T, PQCError>;

/// Trait for post-quantum signature algorithms
pub trait PostQuantumSignatures {
    /// Get algorithm identifier
    fn algorithm_id(&self) -> &'static str;

    /// Generate a new keypair
    fn keypair_generate(&self) -> PQCResult<(Vec<u8>, Vec<u8>)>;

    /// Get public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get private key size in bytes
    fn private_key_size(&self) -> usize;

    /// Sign a message
    fn sign(&self, message: &[u8], private_key: &[u8]) -> PQCResult<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> PQCResult<bool>;

    /// Get signature size in bytes
    fn signature_size(&self) -> usize;
}

/// Trait for post-quantum key exchange algorithms
pub trait PostQuantumKeyExchange {
    /// Get algorithm identifier
    fn algorithm_id(&self) -> &'static str;

    /// Generate a new keypair
    fn keypair_generate(&self) -> PQCResult<(Vec<u8>, Vec<u8>)>;

    /// Get public key size in bytes
    fn public_key_size(&self) -> usize;

    /// Get private key size in bytes
    fn private_key_size(&self) -> usize;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &[u8]) -> PQCResult<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, ciphertext: &[u8], private_key: &[u8]) -> PQCResult<Vec<u8>>;

    /// Get ciphertext size in bytes
    fn ciphertext_size(&self) -> usize;

    /// Get shared secret size in bytes
    fn shared_secret_size(&self) -> usize;
}

/// PQC algorithm registry and factory
pub struct PQCRegistry;

impl PQCRegistry {
    /// Create ML-DSA provider
    pub fn create_mldsa_provider(
        variant: crate::pqc::mldsa::MLDsaVariant,
    ) -> Box<dyn PostQuantumSignatures> {
        Box::new(crate::pqc::mldsa::MLDsaProvider::new(variant))
    }

    /// Create ML-KEM provider
    pub fn create_mlkem_provider(
        variant: crate::pqc::mlkem::MLKemVariant,
    ) -> Box<dyn PostQuantumKeyExchange> {
        Box::new(crate::pqc::mlkem::MLKemProvider::new(variant))
    }

    /// Create Falcon provider
    pub fn create_falcon_provider(
        variant: crate::pqc::falcon::FalconVariant,
    ) -> Box<dyn PostQuantumSignatures> {
        Box::new(crate::pqc::falcon::FalconProvider::new(variant))
    }

    /// Get available algorithms
    pub fn get_available_algorithms() -> Vec<&'static str> {
        vec![
            "ML-DSA-44",
            "ML-DSA-65",
            "ML-DSA-87",
            "ML-KEM-512",
            "ML-KEM-768",
            "ML-KEM-1024",
            "Falcon-512",
            "Falcon-1024",
        ]
    }

    /// Create provider by algorithm name
    pub fn create_provider_by_name(name: &str) -> PQCResult<Box<dyn PostQuantumSignatures>> {
        match name {
            "ML-DSA-44" => Ok(Box::new(crate::pqc::mldsa::MLDsaProvider::new(
                crate::pqc::mldsa::MLDsaVariant::MLDsa44,
            ))),
            "ML-DSA-65" => Ok(Box::new(crate::pqc::mldsa::MLDsaProvider::new(
                crate::pqc::mldsa::MLDsaVariant::MLDsa65,
            ))),
            "ML-DSA-87" => Ok(Box::new(crate::pqc::mldsa::MLDsaProvider::new(
                crate::pqc::mldsa::MLDsaVariant::MLDsa87,
            ))),
            "Falcon-512" => Ok(Box::new(crate::pqc::falcon::FalconProvider::new(
                crate::pqc::falcon::FalconVariant::Falcon512,
            ))),
            "Falcon-1024" => Ok(Box::new(crate::pqc::falcon::FalconProvider::new(
                crate::pqc::falcon::FalconVariant::Falcon1024,
            ))),
            _ => Err(PQCError::UnsupportedAlgorithm(name.to_string())),
        }
    }

    /// Compare algorithm performance characteristics
    pub fn get_algorithm_characteristics() -> Vec<AlgorithmCharacteristics> {
        vec![
            AlgorithmCharacteristics {
                name: "ML-DSA-44".to_string(),
                security_level: "128-bit".to_string(),
                key_size: 1312,
                signature_size: 2420,
                operation: "Signature".to_string(),
                performance_rating: "Fast".to_string(),
            },
            AlgorithmCharacteristics {
                name: "ML-DSA-65".to_string(),
                security_level: "192-bit".to_string(),
                key_size: 1952,
                signature_size: 3309,
                operation: "Signature".to_string(),
                performance_rating: "Medium".to_string(),
            },
            AlgorithmCharacteristics {
                name: "ML-DSA-87".to_string(),
                security_level: "256-bit".to_string(),
                key_size: 2592,
                signature_size: 4627,
                operation: "Signature".to_string(),
                performance_rating: "Slow".to_string(),
            },
            AlgorithmCharacteristics {
                name: "ML-KEM-512".to_string(),
                security_level: "128-bit".to_string(),
                key_size: 800,
                signature_size: 768,
                operation: "Key Exchange".to_string(),
                performance_rating: "Fast".to_string(),
            },
            AlgorithmCharacteristics {
                name: "ML-KEM-768".to_string(),
                security_level: "192-bit".to_string(),
                key_size: 1184,
                signature_size: 1088,
                operation: "Key Exchange".to_string(),
                performance_rating: "Medium".to_string(),
            },
            AlgorithmCharacteristics {
                name: "ML-KEM-1024".to_string(),
                security_level: "256-bit".to_string(),
                key_size: 1568,
                signature_size: 1568,
                operation: "Key Exchange".to_string(),
                performance_rating: "Slow".to_string(),
            },
            AlgorithmCharacteristics {
                name: "Falcon-512".to_string(),
                security_level: "128-bit".to_string(),
                key_size: 897,
                signature_size: 690,
                operation: "Signature".to_string(),
                performance_rating: "Fast".to_string(),
            },
            AlgorithmCharacteristics {
                name: "Falcon-1024".to_string(),
                security_level: "256-bit".to_string(),
                key_size: 1793,
                signature_size: 1330,
                operation: "Signature".to_string(),
                performance_rating: "Medium".to_string(),
            },
        ]
    }
}

/// Algorithm characteristics for comparison
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmCharacteristics {
    pub name: String,
    pub security_level: String,
    pub key_size: usize,
    pub signature_size: usize,
    pub operation: String,
    pub performance_rating: String,
}
/// Hybrid classical + PQC implementation
// TODO: Re-enable when TransitProvider trait is defined
// pub struct HybridCryptoProvider {
//     classical_provider: Box<dyn crate::transit::TransitProvider>,
//     pqc_signatures: Box<dyn PostQuantumSignatures>,
//     pqc_key_exchange: Box<dyn PostQuantumKeyExchange>,
// }

// impl HybridCryptoProvider {
//     /// Create a new hybrid provider
//     pub fn new(
//         classical_provider: Box<dyn crate::transit::TransitProvider>,
//         pqc_signatures: Box<dyn PostQuantumSignatures>,
//         pqc_key_exchange: Box<dyn PostQuantumKeyExchange>,
//     ) -> Self {
//         Self {
//             classical_provider,
//             pqc_signatures,
//             pqc_key_exchange,
//         }
//     }
//
//     /// Generate hybrid signature (classical + PQC)
//     pub async fn hybrid_sign(&self, message: &[u8]) -> CryptoResult<HybridSignature> {
//         // Generate classical signature
//         let classical_sig = self.classical_provider.sign(message).await?;
//
//         // Generate PQC signature
//         let pqc_sig = self.pqc_signatures.sign(message, &Vec::new())?; // Would need proper key management
//
//         Ok(HybridSignature {
//             classical_signature: classical_sig,
//             pqc_signature: pqc_sig,
//             algorithm_info: format!(
//                 "{}/{}",
//                 self.classical_provider.algorithm_id(),
//                 self.pqc_signatures.algorithm_id()
//             ),
//         })
//     }
//
//     /// Verify hybrid signature
//     pub async fn hybrid_verify(&self, message: &[u8], signature: &HybridSignature) -> CryptoResult<bool> {
//         // Verify both signatures
//         let classical_valid = self.classical_provider.verify(message, &signature.classical_signature).await?;
//         let pqc_valid = self.pqc_signatures.verify(message, &signature.pqc_signature, &Vec::new())?; // Would need proper key management
//
//         Ok(classical_valid && pqc_valid)
//     }
// }

/// Hybrid signature structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    pub classical_signature: Vec<u8>,
    pub pqc_signature: Vec<u8>,
    pub algorithm_info: String,
}

/// PQC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCConfig {
    /// Default signature algorithm
    pub default_signature_algorithm: String,
    /// Default key exchange algorithm
    pub default_key_exchange_algorithm: String,
    /// Enable hybrid mode (classical + PQC)
    pub hybrid_mode_enabled: bool,
    /// Security level (128, 192, 256)
    pub security_level: u32,
}

impl Default for PQCConfig {
    fn default() -> Self {
        Self {
            default_signature_algorithm: "ML-DSA-65".to_string(),
            default_key_exchange_algorithm: "ML-KEM-768".to_string(),
            hybrid_mode_enabled: true,
            security_level: 192,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_registry() {
        let algorithms = PQCRegistry::get_available_algorithms();
        assert!(algorithms.contains(&"ML-DSA-65"));
        assert!(algorithms.contains(&"ML-KEM-768"));
        assert!(algorithms.contains(&"Falcon-512"));
    }

    #[test]
    fn test_algorithm_characteristics() {
        let characteristics = PQCRegistry::get_algorithm_characteristics();

        // Should have characteristics for all major algorithms
        assert!(characteristics.iter().any(|c| c.name == "ML-DSA-65"));
        assert!(characteristics.iter().any(|c| c.name == "ML-KEM-768"));
        assert!(characteristics.iter().any(|c| c.name == "Falcon-512"));

        // Check security levels
        let mldsa_65 = characteristics
            .iter()
            .find(|c| c.name == "ML-DSA-65")
            .unwrap();
        assert_eq!(mldsa_65.security_level, "192-bit");
        assert_eq!(mldsa_65.operation, "Signature");
    }

    #[test]
    fn test_provider_creation() {
        // Test ML-DSA provider creation
        let provider = PQCRegistry::create_mldsa_provider(crate::pqc::mldsa::MLDsaVariant::MLDsa44);
        assert_eq!(provider.algorithm_id(), "ML-DSA-44");

        // Test Falcon provider creation
        let provider =
            PQCRegistry::create_falcon_provider(crate::pqc::falcon::FalconVariant::Falcon512);
        assert_eq!(provider.algorithm_id(), "Falcon-512");
    }

    #[test]
    fn test_pqc_config_default() {
        let config = PQCConfig::default();
        assert_eq!(config.default_signature_algorithm, "ML-DSA-65");
        assert_eq!(config.default_key_exchange_algorithm, "ML-KEM-768");
        assert!(config.hybrid_mode_enabled);
        assert_eq!(config.security_level, 192);
    }
}
