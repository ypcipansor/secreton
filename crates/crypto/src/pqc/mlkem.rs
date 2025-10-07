//! ML-KEM (Module-Lattice Key Encapsulation Mechanism) Implementation
//!
//! NIST PQC Standard for Post-Quantum Key Exchange

use crate::error::{CryptoError, CryptoResult};
use pqcrypto_mlkem::*;
use pqcrypto_traits::kem::{
    Ciphertext as KemCiphertext, PublicKey as KemPublicKey, SecretKey as KemSecretKey,
    SharedSecret as KemSharedSecret,
};
use serde::{Deserialize, Serialize};
use std::fmt;

/// ML-KEM variant configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MLKemVariant {
    /// ML-KEM-512: 128-bit security, 800-byte public key, 768-byte ciphertext
    MLKem512,
    /// ML-KEM-768: 192-bit security, 1,184-byte public key, 1,088-byte ciphertext
    MLKem768,
    /// ML-KEM-1024: 256-bit security, 1,568-byte public key, 1,568-byte ciphertext
    MLKem1024,
}

impl MLKemVariant {
    /// Get the public key size in bytes for this variant
    pub fn public_key_size(&self) -> usize {
        match self {
            MLKemVariant::MLKem512 => 800,
            MLKemVariant::MLKem768 => 1184,
            MLKemVariant::MLKem1024 => 1568,
        }
    }

    /// Get the private key size in bytes for this variant
    pub fn private_key_size(&self) -> usize {
        match self {
            MLKemVariant::MLKem512 => 1632,
            MLKemVariant::MLKem768 => 2400,
            MLKemVariant::MLKem1024 => 3168,
        }
    }

    /// Get the ciphertext size in bytes for this variant
    pub fn ciphertext_size(&self) -> usize {
        match self {
            MLKemVariant::MLKem512 => 768,
            MLKemVariant::MLKem768 => 1088,
            MLKemVariant::MLKem1024 => 1568,
        }
    }

    /// Get the shared secret size in bytes for this variant
    pub fn shared_secret_size(&self) -> usize {
        match self {
            MLKemVariant::MLKem512 => 32,
            MLKemVariant::MLKem768 => 32,
            MLKemVariant::MLKem1024 => 32,
        }
    }

    /// Get the security level name
    pub fn security_level(&self) -> &'static str {
        match self {
            MLKemVariant::MLKem512 => "128-bit",
            MLKemVariant::MLKem768 => "192-bit",
            MLKemVariant::MLKem1024 => "256-bit",
        }
    }
}

impl fmt::Display for MLKemVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MLKemVariant::MLKem512 => write!(f, "ML-KEM-512"),
            MLKemVariant::MLKem768 => write!(f, "ML-KEM-768"),
            MLKemVariant::MLKem1024 => write!(f, "ML-KEM-1024"),
        }
    }
}

/// ML-KEM keypair for key exchange
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLKemKeypair {
    /// Public key for encapsulation
    pub public_key: Vec<u8>,
    /// Private key for decapsulation
    pub private_key: Vec<u8>,
    /// Algorithm variant
    pub variant: MLKemVariant,
}

impl MLKemKeypair {
    /// Generate a new ML-KEM keypair
    pub fn generate(variant: MLKemVariant) -> CryptoResult<Self> {
        let (public_key, private_key) = match variant {
            MLKemVariant::MLKem512 => {
                let (pk, sk) = mlkem512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            MLKemVariant::MLKem768 => {
                let (pk, sk) = mlkem768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            MLKemVariant::MLKem1024 => {
                let (pk, sk) = mlkem1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };

        Ok(Self {
            public_key,
            private_key,
            variant,
        })
    }

    /// Encapsulate a shared secret using the public key
    ///
    /// # Returns
    /// Tuple of (shared_secret, ciphertext):
    /// - shared_secret: 32-byte symmetric key (all variants)
    /// - ciphertext: Variant-specific size to send to recipient
    ///
    /// # Security
    /// - Uses cryptographically secure randomness internally
    /// - FIPS 203 compliant ML-KEM implementation
    /// - Constant-time operations resistant to timing attacks
    pub fn encapsulate(&self) -> CryptoResult<(Vec<u8>, Vec<u8>)> {
        // Validate public key size
        if self.public_key.len() != self.variant.public_key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid public key size: expected {} bytes, got {} bytes",
                self.variant.public_key_size(),
                self.public_key.len()
            )));
        }

        match self.variant {
            MLKemVariant::MLKem512 => {
                let pk = mlkem512::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let (shared_secret, ciphertext) = mlkem512::encapsulate(&pk);
                Ok((
                    shared_secret.as_bytes().to_vec(),
                    ciphertext.as_bytes().to_vec(),
                ))
            }
            MLKemVariant::MLKem768 => {
                let pk = mlkem768::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk);
                Ok((
                    shared_secret.as_bytes().to_vec(),
                    ciphertext.as_bytes().to_vec(),
                ))
            }
            MLKemVariant::MLKem1024 => {
                let pk = mlkem1024::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let (shared_secret, ciphertext) = mlkem1024::encapsulate(&pk);
                Ok((
                    shared_secret.as_bytes().to_vec(),
                    ciphertext.as_bytes().to_vec(),
                ))
            }
        }
    }

    /// Decapsulate a shared secret using the private key and ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - The ciphertext from encapsulation
    ///
    /// # Returns
    /// The 32-byte shared secret (same as produced by encapsulate)
    ///
    /// # Security
    /// - FIPS 203 compliant ML-KEM implementation
    /// - Constant-time decapsulation
    /// - Validates ciphertext size before processing
    pub fn decapsulate(&self, ciphertext: &[u8]) -> CryptoResult<Vec<u8>> {
        // Validate ciphertext size
        if ciphertext.len() != self.variant.ciphertext_size() {
            return Err(CryptoError::InvalidCiphertext(format!(
                "Invalid ciphertext size: expected {} bytes, got {} bytes",
                self.variant.ciphertext_size(),
                ciphertext.len()
            )));
        }

        // Validate private key size
        if self.private_key.len() != self.variant.private_key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid private key size: expected {} bytes, got {} bytes",
                self.variant.private_key_size(),
                self.private_key.len()
            )));
        }

        match self.variant {
            MLKemVariant::MLKem512 => {
                let sk = mlkem512::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let ct = mlkem512::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    CryptoError::InvalidCiphertext("Ciphertext format invalid".to_string())
                })?;
                let shared_secret = mlkem512::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            MLKemVariant::MLKem768 => {
                let sk = mlkem768::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let ct = mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    CryptoError::InvalidCiphertext("Ciphertext format invalid".to_string())
                })?;
                let shared_secret = mlkem768::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            MLKemVariant::MLKem1024 => {
                let sk = mlkem1024::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let ct = mlkem1024::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                    CryptoError::InvalidCiphertext("Ciphertext format invalid".to_string())
                })?;
                let shared_secret = mlkem1024::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }

    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the private key as bytes
    pub fn private_key_bytes(&self) -> &[u8] {
        &self.private_key
    }

    /// Get the variant
    pub fn variant(&self) -> MLKemVariant {
        self.variant
    }
}

/// ML-KEM provider implementing the PostQuantumKeyExchange trait
pub struct MLKemProvider {
    variant: MLKemVariant,
}

impl MLKemProvider {
    /// Create a new ML-KEM provider with the specified variant
    pub fn new(variant: MLKemVariant) -> Self {
        Self { variant }
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> CryptoResult<MLKemKeypair> {
        MLKemKeypair::generate(self.variant)
    }

    /// Create provider from existing keypair
    pub fn from_keypair(keypair: MLKemKeypair) -> Self {
        Self {
            variant: keypair.variant,
        }
    }
}

impl crate::pqc::PostQuantumKeyExchange for MLKemProvider {
    fn algorithm_id(&self) -> &'static str {
        match self.variant {
            MLKemVariant::MLKem512 => "ML-KEM-512",
            MLKemVariant::MLKem768 => "ML-KEM-768",
            MLKemVariant::MLKem1024 => "ML-KEM-1024",
        }
    }

    fn keypair_generate(&self) -> crate::pqc::PQCResult<(Vec<u8>, Vec<u8>)> {
        let keypair = MLKemKeypair::generate(self.variant)?;
        Ok((keypair.public_key, keypair.private_key))
    }

    fn public_key_size(&self) -> usize {
        self.variant.public_key_size()
    }

    fn private_key_size(&self) -> usize {
        self.variant.private_key_size()
    }

    fn encapsulate(&self, public_key: &[u8]) -> crate::pqc::PQCResult<(Vec<u8>, Vec<u8>)> {
        let keypair = MLKemKeypair {
            public_key: public_key.to_vec(),
            private_key: Vec::new(), // Not needed for encapsulation
            variant: self.variant,
        };
        keypair
            .encapsulate()
            .map_err(|e| crate::pqc::PQCError::KeyExchangeError(e.to_string()))
    }

    fn decapsulate(&self, ciphertext: &[u8], private_key: &[u8]) -> crate::pqc::PQCResult<Vec<u8>> {
        let keypair = MLKemKeypair {
            public_key: Vec::new(), // Not needed for decapsulation
            private_key: private_key.to_vec(),
            variant: self.variant,
        };
        keypair
            .decapsulate(ciphertext)
            .map_err(|e| crate::pqc::PQCError::KeyExchangeError(e.to_string()))
    }

    fn ciphertext_size(&self) -> usize {
        self.variant.ciphertext_size()
    }

    fn shared_secret_size(&self) -> usize {
        self.variant.shared_secret_size()
    }
}

/// ML-KEM batch operations for performance
pub struct MLKemBatchEncapsulator {
    public_key: Vec<u8>,
    variant: MLKemVariant,
}

impl MLKemBatchEncapsulator {
    /// Create a new batch encapsulator
    pub fn new(public_key: Vec<u8>, variant: MLKemVariant) -> Self {
        Self {
            public_key,
            variant,
        }
    }

    /// Encapsulate multiple shared secrets efficiently
    pub fn batch_encapsulate(&self, count: usize) -> CryptoResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut results = Vec::new();

        for _ in 0..count {
            let (shared_secret, ciphertext) = match self.variant {
                MLKemVariant::MLKem512 => {
                    let pk = mlkem512::PublicKey::from_bytes(&self.public_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-512 public key".to_string())
                    })?;
                    let (secret, cipher) = mlkem512::encapsulate(&pk);
                    (secret.as_bytes().to_vec(), cipher.as_bytes().to_vec())
                }
                MLKemVariant::MLKem768 => {
                    let pk = mlkem768::PublicKey::from_bytes(&self.public_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-768 public key".to_string())
                    })?;
                    let (secret, cipher) = mlkem768::encapsulate(&pk);
                    (secret.as_bytes().to_vec(), cipher.as_bytes().to_vec())
                }
                MLKemVariant::MLKem1024 => {
                    let pk = mlkem1024::PublicKey::from_bytes(&self.public_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-1024 public key".to_string())
                    })?;
                    let (secret, cipher) = mlkem1024::encapsulate(&pk);
                    (secret.as_bytes().to_vec(), cipher.as_bytes().to_vec())
                }
            };

            results.push((shared_secret, ciphertext));
        }

        Ok(results)
    }
}

/// ML-KEM batch decapsulator for performance
pub struct MLKemBatchDecapsulator {
    private_key: Vec<u8>,
    variant: MLKemVariant,
}

impl MLKemBatchDecapsulator {
    /// Create a new batch decapsulator
    pub fn new(private_key: Vec<u8>, variant: MLKemVariant) -> Self {
        Self {
            private_key,
            variant,
        }
    }

    /// Decapsulate multiple ciphertexts efficiently
    pub fn batch_decapsulate(&self, ciphertexts: &[&[u8]]) -> CryptoResult<Vec<Vec<u8>>> {
        let mut results = Vec::new();

        for ciphertext in ciphertexts {
            let shared_secret = match self.variant {
                MLKemVariant::MLKem512 => {
                    let sk = mlkem512::SecretKey::from_bytes(&self.private_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-512 private key".to_string())
                    })?;
                    let ct = mlkem512::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                        CryptoError::InvalidCiphertext("Invalid ML-KEM-512 ciphertext".to_string())
                    })?;
                    mlkem512::decapsulate(&ct, &sk).as_bytes().to_vec()
                }
                MLKemVariant::MLKem768 => {
                    let sk = mlkem768::SecretKey::from_bytes(&self.private_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-768 private key".to_string())
                    })?;
                    let ct = mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                        CryptoError::InvalidCiphertext("Invalid ML-KEM-768 ciphertext".to_string())
                    })?;
                    mlkem768::decapsulate(&ct, &sk).as_bytes().to_vec()
                }
                MLKemVariant::MLKem1024 => {
                    let sk = mlkem1024::SecretKey::from_bytes(&self.private_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid ML-KEM-1024 private key".to_string())
                    })?;
                    let ct = mlkem1024::Ciphertext::from_bytes(ciphertext).map_err(|_| {
                        CryptoError::InvalidCiphertext("Invalid ML-KEM-1024 ciphertext".to_string())
                    })?;
                    mlkem1024::decapsulate(&ct, &sk).as_bytes().to_vec()
                }
            };

            results.push(shared_secret);
        }

        Ok(results)
    }
}

/// Test key exchange correctness
pub fn test_key_exchange_correctness(variant: MLKemVariant) -> CryptoResult<bool> {
    // Generate keypair
    let keypair = MLKemKeypair::generate(variant)?;

    // Alice encapsulates
    let (alice_secret, ciphertext) = keypair.encapsulate()?;

    // Bob decapsulates
    let bob_secret = keypair.decapsulate(&ciphertext)?;

    // Secrets should match - use constant-time comparison
    use crate::pqc::constant_time::ct_eq;
    Ok(ct_eq(&alice_secret, &bob_secret))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc::PostQuantumKeyExchange;

    #[test]
    fn test_mlkem_variant_properties() {
        assert_eq!(MLKemVariant::MLKem512.public_key_size(), 800);
        assert_eq!(MLKemVariant::MLKem512.private_key_size(), 1632);
        assert_eq!(MLKemVariant::MLKem512.ciphertext_size(), 768);
        assert_eq!(MLKemVariant::MLKem512.shared_secret_size(), 32);

        assert_eq!(MLKemVariant::MLKem768.public_key_size(), 1184);
        assert_eq!(MLKemVariant::MLKem768.private_key_size(), 2400);
        assert_eq!(MLKemVariant::MLKem768.ciphertext_size(), 1088);
        assert_eq!(MLKemVariant::MLKem768.shared_secret_size(), 32);

        assert_eq!(MLKemVariant::MLKem1024.public_key_size(), 1568);
        assert_eq!(MLKemVariant::MLKem1024.private_key_size(), 3168);
        assert_eq!(MLKemVariant::MLKem1024.ciphertext_size(), 1568);
        assert_eq!(MLKemVariant::MLKem1024.shared_secret_size(), 32);
    }

    #[test]
    fn test_mlkem_keypair_generation() {
        let keypair = MLKemKeypair::generate(MLKemVariant::MLKem512).unwrap();

        assert_eq!(keypair.public_key.len(), 800);
        assert_eq!(keypair.private_key.len(), 1632);
        assert_eq!(keypair.variant, MLKemVariant::MLKem512);
    }

    #[test]
    fn test_mlkem_key_exchange() {
        let keypair = MLKemKeypair::generate(MLKemVariant::MLKem768).unwrap();

        // Alice encapsulates
        let (alice_secret, ciphertext) = keypair.encapsulate().unwrap();
        assert_eq!(alice_secret.len(), 32);
        assert_eq!(ciphertext.len(), 1088);

        // Bob decapsulates
        let bob_secret = keypair.decapsulate(&ciphertext).unwrap();
        assert_eq!(bob_secret.len(), 32);

        // Secrets should match
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn test_mlkem_provider_trait() {
        let provider = MLKemProvider::new(MLKemVariant::MLKem1024);

        assert_eq!(provider.algorithm_id(), "ML-KEM-1024");
        assert_eq!(provider.public_key_size(), 1568);
        assert_eq!(provider.private_key_size(), 3168);
        assert_eq!(provider.ciphertext_size(), 1568);
        assert_eq!(provider.shared_secret_size(), 32);
    }

    #[test]
    fn test_batch_operations() {
        let keypair = MLKemKeypair::generate(MLKemVariant::MLKem512).unwrap();

        let batch_encapsulator =
            MLKemBatchEncapsulator::new(keypair.public_key.clone(), MLKemVariant::MLKem512);
        let encapsulations = batch_encapsulator.batch_encapsulate(3).unwrap();

        assert_eq!(encapsulations.len(), 3);

        let ciphertexts: Vec<&[u8]> = encapsulations
            .iter()
            .map(|(_, cipher)| cipher.as_slice())
            .collect();
        let batch_decapsulator =
            MLKemBatchDecapsulator::new(keypair.private_key, MLKemVariant::MLKem512);
        let decryptions = batch_decapsulator.batch_decapsulate(&ciphertexts).unwrap();

        assert_eq!(decryptions.len(), 3);

        // Verify all decryptions match their corresponding encapsulations
        for ((alice_secret, _), bob_secret) in encapsulations.iter().zip(decryptions.iter()) {
            assert_eq!(alice_secret, bob_secret);
        }
    }

    #[test]
    fn test_different_variants() {
        for variant in [
            MLKemVariant::MLKem512,
            MLKemVariant::MLKem768,
            MLKemVariant::MLKem1024,
        ] {
            let keypair = MLKemKeypair::generate(variant).unwrap();

            let (alice_secret, ciphertext) = keypair.encapsulate().unwrap();
            let bob_secret = keypair.decapsulate(&ciphertext).unwrap();

            assert_eq!(alice_secret.len(), 32);
            assert_eq!(bob_secret.len(), 32);
            assert_eq!(alice_secret, bob_secret);
        }
    }

    #[test]
    fn test_key_exchange_correctness_fn() {
        for variant in [
            MLKemVariant::MLKem512,
            MLKemVariant::MLKem768,
            MLKemVariant::MLKem1024,
        ] {
            let is_correct = super::test_key_exchange_correctness(variant).unwrap();
            assert!(is_correct, "Key exchange failed for {:?}", variant);
        }
    }

    #[test]
    fn test_input_validation() {
        let keypair = MLKemKeypair::generate(MLKemVariant::MLKem512).unwrap();

        // Test invalid ciphertext size
        let invalid_ct = vec![0u8; 100]; // Wrong size
        let result = keypair.decapsulate(&invalid_ct);
        assert!(result.is_err(), "Should reject invalid ciphertext size");

        // Test invalid public key size for encapsulation
        let mut bad_keypair = keypair.clone();
        bad_keypair.public_key = vec![0u8; 100]; // Wrong size
        let result = bad_keypair.encapsulate();
        assert!(result.is_err(), "Should reject invalid public key size");

        // Test invalid private key size for decapsulation
        let (_, ciphertext) = keypair.encapsulate().unwrap();
        let mut bad_keypair2 = keypair.clone();
        bad_keypair2.private_key = vec![0u8; 100]; // Wrong size
        let result = bad_keypair2.decapsulate(&ciphertext);
        assert!(result.is_err(), "Should reject invalid private key size");
    }

    #[test]
    fn test_cross_variant_rejection() {
        // Generate keypairs for different variants
        let keypair_512 = MLKemKeypair::generate(MLKemVariant::MLKem512).unwrap();
        let keypair_768 = MLKemKeypair::generate(MLKemVariant::MLKem768).unwrap();

        // Encapsulate with 512
        let (_, ciphertext_512) = keypair_512.encapsulate().unwrap();

        // Try to decapsulate with 768 key (should fail due to size mismatch)
        let result = keypair_768.decapsulate(&ciphertext_512);
        assert!(result.is_err(), "Cross-variant decapsulation should fail");
    }

    #[test]
    fn test_shared_secret_size() {
        for variant in [
            MLKemVariant::MLKem512,
            MLKemVariant::MLKem768,
            MLKemVariant::MLKem1024,
        ] {
            let keypair = MLKemKeypair::generate(variant).unwrap();
            let (shared_secret, _) = keypair.encapsulate().unwrap();

            assert_eq!(
                shared_secret.len(),
                32,
                "All variants should produce 32-byte shared secrets"
            );
        }
    }
}
