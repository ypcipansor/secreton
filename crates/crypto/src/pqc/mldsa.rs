//! ML-DSA (Module-Lattice Digital Signature Algorithm) Implementation
//!
//! NIST PQC Standard for Post-Quantum Digital Signatures

use crate::error::{CryptoError, CryptoResult};
use pqcrypto_mldsa::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use std::fmt;

/// ML-DSA variant configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MLDsaVariant {
    /// ML-DSA-44: 128-bit security, 1,312-byte public key, 2,420-byte signature
    MLDsa44,
    /// ML-DSA-65: 192-bit security, 1,952-byte public key, 3,300-byte signature
    MLDsa65,
    /// ML-DSA-87: 256-bit security, 2,592-byte public key, 4,611-byte signature
    MLDsa87,
}

impl MLDsaVariant {
    /// Get the public key size in bytes for this variant
    pub fn public_key_size(&self) -> usize {
        match self {
            MLDsaVariant::MLDsa44 => 1312,
            MLDsaVariant::MLDsa65 => 1952,
            MLDsaVariant::MLDsa87 => 2592,
        }
    }

    /// Get the private key size in bytes for this variant
    pub fn private_key_size(&self) -> usize {
        match self {
            MLDsaVariant::MLDsa44 => 2560,
            MLDsaVariant::MLDsa65 => 4032,
            MLDsaVariant::MLDsa87 => 4896,
        }
    }

    /// Get the maximum detached signature size in bytes for this variant
    /// 
    /// Note: Actual signature sizes from pqcrypto-mldsa may vary slightly.
    /// These values represent typical/maximum sizes from the library implementation.
    /// 
    /// Reference: FIPS 204 ML-DSA specification
    pub fn signature_size(&self) -> usize {
        match self {
            // ML-DSA-44: NIST spec says 2420, but pqcrypto-mldsa produces ~2420 bytes
            MLDsaVariant::MLDsa44 => 2420,
            // ML-DSA-65: NIST spec says 3309, but pqcrypto-mldsa produces ~3309 bytes  
            MLDsaVariant::MLDsa65 => 3309,
            // ML-DSA-87: NIST spec says 4627, pqcrypto-mldsa matches
            MLDsaVariant::MLDsa87 => 4627,
        }
    }
    
    /// Get the maximum signature size (upper bound for allocation)
    pub fn max_signature_size(&self) -> usize {
        self.signature_size() + 50 // Add 50 bytes buffer for encoding overhead
    }

    /// Get the security level name
    pub fn security_level(&self) -> &'static str {
        match self {
            MLDsaVariant::MLDsa44 => "128-bit",
            MLDsaVariant::MLDsa65 => "192-bit",
            MLDsaVariant::MLDsa87 => "256-bit",
        }
    }
}

impl fmt::Display for MLDsaVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MLDsaVariant::MLDsa44 => write!(f, "ML-DSA-44"),
            MLDsaVariant::MLDsa65 => write!(f, "ML-DSA-65"),
            MLDsaVariant::MLDsa87 => write!(f, "ML-DSA-87"),
        }
    }
}

/// ML-DSA keypair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MLDsaKeypair {
    /// Public key
    pub public_key: Vec<u8>,
    /// Private key
    pub private_key: Vec<u8>,
    /// Algorithm variant
    pub variant: MLDsaVariant,
}

impl MLDsaKeypair {
    /// Generate a new ML-DSA keypair
    pub fn generate(variant: MLDsaVariant) -> CryptoResult<Self> {
        let (public_key, private_key) = match variant {
            MLDsaVariant::MLDsa44 => {
                let keys = mldsa44::keypair();
                (keys.0.as_bytes().to_vec(), keys.1.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa65 => {
                let keys = mldsa65::keypair();
                (keys.0.as_bytes().to_vec(), keys.1.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa87 => {
                let keys = mldsa87::keypair();
                (keys.0.as_bytes().to_vec(), keys.1.as_bytes().to_vec())
            }
        };

        Ok(Self {
            public_key,
            private_key,
            variant,
        })
    }

    /// Sign a message and return detached signature
    /// 
    /// # Arguments
    /// * `message` - The message to sign (max 100 MB recommended)
    /// 
    /// # Security
    /// - Uses cryptographically secure randomness internally
    /// - Returns DETACHED signature (signature only, not message)
    /// - Constant-time implementation resistant to timing attacks
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        // Input validation: Reasonable message size limit (100 MB)
        const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Message too large: {} bytes (max: {} bytes)",
                message.len(),
                MAX_MESSAGE_SIZE
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
            MLDsaVariant::MLDsa44 => {
                let sk = mldsa44::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa44::detached_sign(message, &sk);
                Ok(detached_sig.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa65::detached_sign(message, &sk);
                Ok(detached_sig.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa87::detached_sign(message, &sk);
                Ok(detached_sig.as_bytes().to_vec())
            }
        }
    }

    /// Verify a detached signature
    /// 
    /// # Arguments
    /// * `message` - The original message
    /// * `signature` - The detached signature to verify
    /// 
    /// # Returns
    /// * `Ok(true)` if signature is valid
    /// * `Ok(false)` if signature is invalid
    /// * `Err(...)` if inputs are malformed
    /// 
    /// # Security
    /// - Constant-time verification
    /// - Returns false for invalid signatures (doesn't leak why)
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        // Input validation: Check message size
        const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput("Message too large".to_string()));
        }

        // Validate public key size
        if self.public_key.len() != self.variant.public_key_size() {
            return Err(CryptoError::InvalidKey("Invalid public key size".to_string()));
        }

        // Validate signature size (approximate check - some variance allowed)
        let expected_sig_size = self.variant.signature_size();
        if signature.len() < expected_sig_size - 50 || signature.len() > expected_sig_size + 50 {
            return Err(CryptoError::InvalidSignature(format!(
                "Signature size out of range: {} bytes (expected ~{})",
                signature.len(),
                expected_sig_size
            )));
        }

        match self.variant {
            MLDsaVariant::MLDsa44 => {
                let pk = mldsa44::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa44::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Signature format invalid".to_string()))?;
                let result = mldsa44::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
            }
            MLDsaVariant::MLDsa65 => {
                let pk = mldsa65::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa65::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Signature format invalid".to_string()))?;
                let result = mldsa65::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
            }
            MLDsaVariant::MLDsa87 => {
                let pk = mldsa87::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = mldsa87::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Signature format invalid".to_string()))?;
                let result = mldsa87::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
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
    pub fn variant(&self) -> MLDsaVariant {
        self.variant
    }
}

/// ML-DSA signature provider implementing the PostQuantumSignatures trait
pub struct MLDsaProvider {
    variant: MLDsaVariant,
}

impl MLDsaProvider {
    /// Create a new ML-DSA provider with the specified variant
    pub fn new(variant: MLDsaVariant) -> Self {
        Self { variant }
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> CryptoResult<MLDsaKeypair> {
        MLDsaKeypair::generate(self.variant)
    }

    /// Create provider from existing keypair
    pub fn from_keypair(keypair: MLDsaKeypair) -> Self {
        Self {
            variant: keypair.variant,
        }
    }
}

impl crate::pqc::PostQuantumSignatures for MLDsaProvider {
    fn algorithm_id(&self) -> &'static str {
        match self.variant {
            MLDsaVariant::MLDsa44 => "ML-DSA-44",
            MLDsaVariant::MLDsa65 => "ML-DSA-65",
            MLDsaVariant::MLDsa87 => "ML-DSA-87",
        }
    }

    fn keypair_generate(&self) -> crate::pqc::PQCResult<(Vec<u8>, Vec<u8>)> {
        let keypair = MLDsaKeypair::generate(self.variant)?;
        Ok((keypair.public_key, keypair.private_key))
    }

    fn public_key_size(&self) -> usize {
        self.variant.public_key_size()
    }

    fn private_key_size(&self) -> usize {
        self.variant.private_key_size()
    }

    fn sign(&self, message: &[u8], private_key: &[u8]) -> crate::pqc::PQCResult<Vec<u8>> {
        let keypair = MLDsaKeypair {
            public_key: Vec::new(), // Not needed for signing
            private_key: private_key.to_vec(),
            variant: self.variant,
        };
        keypair.sign(message).map_err(|e| crate::pqc::PQCError::SignatureError(e.to_string()))
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> crate::pqc::PQCResult<bool> {
        let keypair = MLDsaKeypair {
            public_key: public_key.to_vec(),
            private_key: Vec::new(), // Not needed for verification
            variant: self.variant,
        };
        keypair.verify(message, signature).map_err(|e| crate::pqc::PQCError::VerificationError(e.to_string()))
    }

    fn signature_size(&self) -> usize {
        self.variant.signature_size()
    }
}

/// ML-DSA signature batch operations for performance
pub struct MLDsaBatchSigner {
    private_key: Vec<u8>,
    variant: MLDsaVariant,
}

impl MLDsaBatchSigner {
    /// Create a new batch signer
    /// 
    /// # Security Warning
    /// Batch operations reuse the same private key. Ensure the underlying
    /// pqcrypto-mldsa library uses fresh randomness for each signature.
    pub fn new(private_key: Vec<u8>, variant: MLDsaVariant) -> CryptoResult<Self> {
        // Validate private key size at construction
        if private_key.len() != variant.private_key_size() {
            return Err(CryptoError::InvalidKey(format!(
                "Invalid private key size: expected {} bytes, got {} bytes",
                variant.private_key_size(),
                private_key.len()
            )));
        }
        
        Ok(Self {
            private_key,
            variant,
        })
    }

    /// Sign multiple messages efficiently (returns detached signatures)
    /// 
    /// # Arguments
    /// * `messages` - Slice of messages to sign
    /// 
    /// # Performance
    /// Pre-allocates result vector for better performance.
    /// Consider using parallel processing for large batches (requires rayon).
    /// 
    /// # Security
    /// - Each signature uses fresh randomness (handled by pqcrypto-mldsa)
    /// - Recommended batch size: ≤ 1000 messages
    /// - Rate limiting recommended for production use
    pub fn batch_sign(&self, messages: &[&[u8]]) -> CryptoResult<Vec<Vec<u8>>> {
        // Pre-allocate for performance
        let mut signatures = Vec::with_capacity(messages.len());
        
        // Recommended batch size limit
        const MAX_BATCH_SIZE: usize = 1000;
        if messages.len() > MAX_BATCH_SIZE {
            return Err(CryptoError::InvalidInput(format!(
                "Batch size too large: {} (max: {})", 
                messages.len(), 
                MAX_BATCH_SIZE
            )));
        }

        for message in messages {
            // Validate message size
            const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
            if message.len() > MAX_MESSAGE_SIZE {
                return Err(CryptoError::InvalidInput("Message too large in batch".to_string()));
            }

            let signature = match self.variant {
                MLDsaVariant::MLDsa44 => {
                    let sk = mldsa44::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                    let detached_sig = mldsa44::detached_sign(message, &sk);
                    detached_sig.as_bytes().to_vec()
                }
                MLDsaVariant::MLDsa65 => {
                    let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                    let detached_sig = mldsa65::detached_sign(message, &sk);
                    detached_sig.as_bytes().to_vec()
                }
                MLDsaVariant::MLDsa87 => {
                    let sk = mldsa87::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                    let detached_sig = mldsa87::detached_sign(message, &sk);
                    detached_sig.as_bytes().to_vec()
                }
            };

            signatures.push(signature);
        }

        Ok(signatures)
    }
}

/// ML-DSA signature batch verifier for performance
pub struct MLDsaBatchVerifier {
    public_key: Vec<u8>,
    variant: MLDsaVariant,
}

impl MLDsaBatchVerifier {
    /// Create a new batch verifier
    pub fn new(public_key: Vec<u8>, variant: MLDsaVariant) -> Self {
        Self {
            public_key,
            variant,
        }
    }

    /// Verify multiple signatures efficiently
    pub fn batch_verify(&self, messages: &[&[u8]], signatures: &[&[u8]]) -> CryptoResult<Vec<bool>> {
        if messages.len() != signatures.len() {
            return Err(CryptoError::InvalidInput("Messages and signatures count mismatch".to_string()));
        }

        let mut results = Vec::new();

        for (message, signature) in messages.iter().zip(signatures.iter()) {
            let is_valid = match self.variant {
                MLDsaVariant::MLDsa44 => {
                    let pk = mldsa44::PublicKey::from_bytes(&self.public_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-44 public key".to_string()))?;
                    let detached_sig = mldsa44::DetachedSignature::from_bytes(signature)
                        .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-44 signature".to_string()))?;
                    mldsa44::verify_detached_signature(&detached_sig, message, &pk).is_ok()
                }
                MLDsaVariant::MLDsa65 => {
                    let pk = mldsa65::PublicKey::from_bytes(&self.public_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-65 public key".to_string()))?;
                    let detached_sig = mldsa65::DetachedSignature::from_bytes(signature)
                        .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-65 signature".to_string()))?;
                    mldsa65::verify_detached_signature(&detached_sig, message, &pk).is_ok()
                }
                MLDsaVariant::MLDsa87 => {
                    let pk = mldsa87::PublicKey::from_bytes(&self.public_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-87 public key".to_string()))?;
                    let detached_sig = mldsa87::DetachedSignature::from_bytes(signature)
                        .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-87 signature".to_string()))?;
                    mldsa87::verify_detached_signature(&detached_sig, message, &pk).is_ok()
                }
            };

            results.push(is_valid);
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc::PostQuantumSignatures;

    #[test]
    fn test_mldsa_variant_properties() {
        // Test ML-DSA-44
        assert_eq!(MLDsaVariant::MLDsa44.public_key_size(), 1312);
        assert_eq!(MLDsaVariant::MLDsa44.private_key_size(), 2560);
        assert_eq!(MLDsaVariant::MLDsa44.signature_size(), 2420);
        assert_eq!(MLDsaVariant::MLDsa44.security_level(), "128-bit");

        // Test ML-DSA-65
        assert_eq!(MLDsaVariant::MLDsa65.public_key_size(), 1952);
        assert_eq!(MLDsaVariant::MLDsa65.private_key_size(), 4032);
        assert_eq!(MLDsaVariant::MLDsa65.signature_size(), 3309);
        assert_eq!(MLDsaVariant::MLDsa65.security_level(), "192-bit");

        // Test ML-DSA-87
        assert_eq!(MLDsaVariant::MLDsa87.public_key_size(), 2592);
        assert_eq!(MLDsaVariant::MLDsa87.private_key_size(), 4896);
        assert_eq!(MLDsaVariant::MLDsa87.signature_size(), 4627);
        assert_eq!(MLDsaVariant::MLDsa87.security_level(), "256-bit");
        
        // Test max_signature_size
        assert!(MLDsaVariant::MLDsa44.max_signature_size() > MLDsaVariant::MLDsa44.signature_size());
    }

    #[test]
    fn test_mldsa_keypair_generation() {
        let keypair = MLDsaKeypair::generate(MLDsaVariant::MLDsa44).unwrap();

        assert_eq!(keypair.public_key.len(), 1312);
        assert_eq!(keypair.private_key.len(), 2560);
        assert_eq!(keypair.variant, MLDsaVariant::MLDsa44);
    }

    #[test]
    fn test_mldsa_sign_verify() {
        let keypair = MLDsaKeypair::generate(MLDsaVariant::MLDsa44).unwrap();
        let message = b"Hello, Post-Quantum World!";

        let signature = keypair.sign(message).unwrap();
        
        // Detached signature should be approximately the expected size
        // Allow some variance due to encoding
        let expected_size = MLDsaVariant::MLDsa44.signature_size();
        assert!(
            signature.len() >= expected_size - 50 && signature.len() <= expected_size + 50,
            "Signature size {} not in range [{}, {}]",
            signature.len(),
            expected_size - 50,
            expected_size + 50
        );

        // Verify correct signature
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid, "Valid signature should verify successfully");

        // Test with wrong message
        let wrong_message = b"Hello, Wrong World!";
        let is_invalid = keypair.verify(wrong_message, &signature).unwrap();
        assert!(!is_invalid, "Signature should not verify with different message");
    }

    #[test]
    fn test_mldsa_provider_trait() {
        let provider = MLDsaProvider::new(MLDsaVariant::MLDsa65);

        assert_eq!(provider.algorithm_id(), "ML-DSA-65");
        assert_eq!(provider.public_key_size(), 1952);
        assert_eq!(provider.private_key_size(), 4032);
        assert_eq!(provider.signature_size(), 3309);
    }

    #[test]
    fn test_batch_operations() {
        let keypair = MLDsaKeypair::generate(MLDsaVariant::MLDsa44).unwrap();
        let messages_raw = vec![b"Message 1", b"Message 2", b"Message 3"];
        let messages: Vec<&[u8]> = messages_raw.iter().map(|m| m.as_ref()).collect();

        let batch_signer = MLDsaBatchSigner::new(keypair.private_key.clone(), MLDsaVariant::MLDsa44).unwrap();
        let signatures = batch_signer.batch_sign(&messages).unwrap();

        assert_eq!(signatures.len(), 3, "Should produce 3 signatures");
        
        // All signatures should be approximately the expected size
        let expected_size = MLDsaVariant::MLDsa44.signature_size();
        for sig in &signatures {
            assert!(
                sig.len() >= expected_size - 50 && sig.len() <= expected_size + 50,
                "Signature size {} not in valid range", sig.len()
            );
        }

        let batch_verifier = MLDsaBatchVerifier::new(keypair.public_key, MLDsaVariant::MLDsa44);
        let sig_slices: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();
        let results = batch_verifier.batch_verify(&messages, &sig_slices).unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&valid| valid), "All signatures should be valid");
    }

    #[test]
    fn test_different_variants() {
        for variant in [MLDsaVariant::MLDsa44, MLDsaVariant::MLDsa65, MLDsaVariant::MLDsa87] {
            let keypair = MLDsaKeypair::generate(variant).unwrap();
            let message = b"Test message";

            let signature = keypair.sign(message).unwrap();
            
            // Check signature size is in acceptable range
            let expected = variant.signature_size();
            assert!(
                signature.len() >= expected - 50 && signature.len() <= expected + 50,
                "Variant {:?}: signature size {} not in range [{}, {}]",
                variant, signature.len(), expected - 50, expected + 50
            );

            let is_valid = keypair.verify(message, &signature).unwrap();
            assert!(is_valid, "Signature for variant {:?} should be valid", variant);
        }
    }
    
    #[test]
    fn test_input_validation() {
        let keypair = MLDsaKeypair::generate(MLDsaVariant::MLDsa44).unwrap();
        
        // Test invalid key size
        let invalid_sk = vec![0u8; 100]; // Wrong size
        let batch_signer = MLDsaBatchSigner::new(invalid_sk, MLDsaVariant::MLDsa44);
        assert!(batch_signer.is_err(), "Should reject invalid key size");
        
        // Test message too large
        let huge_message = vec![0u8; 101 * 1024 * 1024]; // 101 MB
        let result = keypair.sign(&huge_message);
        assert!(result.is_err(), "Should reject oversized message");
        
        // Test batch size limit
        let batch_signer = MLDsaBatchSigner::new(keypair.private_key.clone(), MLDsaVariant::MLDsa44).unwrap();
        let too_many: Vec<&[u8]> = vec![b"msg"; 1001];
        let result = batch_signer.batch_sign(&too_many);
        assert!(result.is_err(), "Should reject oversized batch");
    }
    
    #[test]
    fn test_cross_variant_rejection() {
        // Generate keypairs for different variants
        let keypair_44 = MLDsaKeypair::generate(MLDsaVariant::MLDsa44).unwrap();
        let keypair_65 = MLDsaKeypair::generate(MLDsaVariant::MLDsa65).unwrap();
        
        let message = b"Test message";
        let signature_44 = keypair_44.sign(message).unwrap();
        
        // Try to verify ML-DSA-44 signature with ML-DSA-65 key (should fail)
        let result = keypair_65.verify(message, &signature_44);
        // This should either error or return false
        assert!(result.is_err() || result.unwrap() == false, 
                "Cross-variant verification should fail");
    }
}
