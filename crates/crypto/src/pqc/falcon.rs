//! Falcon Digital Signature Algorithm Implementation
//!
//! Alternative PQC Signature Scheme with smaller signatures than ML-DSA

use crate::error::{CryptoError, CryptoResult};
use pqcrypto_falcon::*;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Falcon variant configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FalconVariant {
    /// Falcon-512: 128-bit security, 897-byte public key, 690-byte signature
    Falcon512,
    /// Falcon-1024: 256-bit security, 1,793-byte public key, 1,330-byte signature
    Falcon1024,
}

impl FalconVariant {
    /// Get the public key size in bytes for this variant
    pub fn public_key_size(&self) -> usize {
        match self {
            FalconVariant::Falcon512 => 897,
            FalconVariant::Falcon1024 => 1793,
        }
    }

    /// Get the private key size in bytes for this variant
    pub fn private_key_size(&self) -> usize {
        match self {
            FalconVariant::Falcon512 => 1281,
            FalconVariant::Falcon1024 => 2305,
        }
    }

    /// Get the typical detached signature size in bytes for this variant
    ///
    /// **Important**: Falcon signatures use compression and have VARIABLE sizes!
    /// - Falcon-512: typically 660-690 bytes (max ~690)
    /// - Falcon-1024: typically 1280-1330 bytes (max ~1330)
    ///
    /// Use `max_signature_size()` for buffer allocation.
    ///
    /// # Security Note
    /// Variable-length signatures may leak minimal information about message
    /// content through compression ratios. This is a known tradeoff for Falcon's
    /// compact signature size.
    pub fn signature_size(&self) -> usize {
        match self {
            FalconVariant::Falcon512 => 690,   // Typical/max size
            FalconVariant::Falcon1024 => 1330, // Typical/max size
        }
    }

    /// Get the maximum signature size (upper bound for allocation)
    pub fn max_signature_size(&self) -> usize {
        match self {
            FalconVariant::Falcon512 => 700,   // Add safety margin
            FalconVariant::Falcon1024 => 1350, // Add safety margin
        }
    }

    /// Get the security level name
    pub fn security_level(&self) -> &'static str {
        match self {
            FalconVariant::Falcon512 => "128-bit",
            FalconVariant::Falcon1024 => "256-bit",
        }
    }
}

impl fmt::Display for FalconVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FalconVariant::Falcon512 => write!(f, "Falcon-512"),
            FalconVariant::Falcon1024 => write!(f, "Falcon-1024"),
        }
    }
}

/// Falcon keypair for digital signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FalconKeypair {
    /// Public key for verification
    pub public_key: Vec<u8>,
    /// Private key for signing
    pub private_key: Vec<u8>,
    /// Algorithm variant
    pub variant: FalconVariant,
}

impl FalconKeypair {
    /// Generate a new Falcon keypair
    pub fn generate(variant: FalconVariant) -> CryptoResult<Self> {
        let (public_key, private_key) = match variant {
            FalconVariant::Falcon512 => {
                let keys = falcon512::keypair();
                (keys.0.as_bytes().to_vec(), keys.1.as_bytes().to_vec())
            }
            FalconVariant::Falcon1024 => {
                let keys = falcon1024::keypair();
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
    /// - **Signature size varies** due to compression (typical range documented)
    ///
    /// # Note
    /// Falcon is NOT a NIST-standardized algorithm (Round 3 finalist only).
    /// Consider using ML-DSA for FIPS 204 compliance.
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
            FalconVariant::Falcon512 => {
                let sk = falcon512::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = falcon512::detached_sign(message, &sk);
                Ok(detached_sig.as_bytes().to_vec())
            }
            FalconVariant::Falcon1024 => {
                let sk = falcon1024::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig = falcon1024::detached_sign(message, &sk);
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
    ///
    /// # Note
    /// Falcon signatures have variable length. The verification accepts
    /// signatures within the valid range for the variant.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        // Input validation: Check message size
        const MAX_MESSAGE_SIZE: usize = 100 * 1024 * 1024;
        if message.len() > MAX_MESSAGE_SIZE {
            return Err(CryptoError::InvalidInput("Message too large".to_string()));
        }

        // Validate public key size
        if self.public_key.len() != self.variant.public_key_size() {
            return Err(CryptoError::InvalidKey(
                "Invalid public key size".to_string(),
            ));
        }

        // Validate signature size range (allow variability for Falcon)
        let max_sig_size = self.variant.max_signature_size();
        let min_sig_size = match self.variant {
            FalconVariant::Falcon512 => 650,
            FalconVariant::Falcon1024 => 1250,
        };

        if signature.len() < min_sig_size || signature.len() > max_sig_size {
            return Err(CryptoError::InvalidSignature(format!(
                "Signature size out of range: {} bytes (expected {}-{})",
                signature.len(),
                min_sig_size,
                max_sig_size
            )));
        }

        match self.variant {
            FalconVariant::Falcon512 => {
                let pk = falcon512::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig =
                    falcon512::DetachedSignature::from_bytes(signature).map_err(|_| {
                        CryptoError::InvalidSignature("Signature format invalid".to_string())
                    })?;
                let result = falcon512::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
            }
            FalconVariant::Falcon1024 => {
                let pk = falcon1024::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Key validation failed".to_string()))?;
                let detached_sig =
                    falcon1024::DetachedSignature::from_bytes(signature).map_err(|_| {
                        CryptoError::InvalidSignature("Signature format invalid".to_string())
                    })?;
                let result = falcon1024::verify_detached_signature(&detached_sig, message, &pk);
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
    pub fn variant(&self) -> FalconVariant {
        self.variant
    }
}

/// Falcon provider implementing the PostQuantumSignatures trait
pub struct FalconProvider {
    variant: FalconVariant,
}

impl FalconProvider {
    /// Create a new Falcon provider with the specified variant
    pub fn new(variant: FalconVariant) -> Self {
        Self { variant }
    }

    /// Generate a new keypair
    pub fn generate_keypair(&self) -> CryptoResult<FalconKeypair> {
        FalconKeypair::generate(self.variant)
    }

    /// Create provider from existing keypair
    pub fn from_keypair(keypair: FalconKeypair) -> Self {
        Self {
            variant: keypair.variant,
        }
    }
}

impl crate::pqc::PostQuantumSignatures for FalconProvider {
    fn algorithm_id(&self) -> &'static str {
        match self.variant {
            FalconVariant::Falcon512 => "Falcon-512",
            FalconVariant::Falcon1024 => "Falcon-1024",
        }
    }

    fn keypair_generate(&self) -> crate::pqc::PQCResult<(Vec<u8>, Vec<u8>)> {
        let keypair = FalconKeypair::generate(self.variant)?;
        Ok((keypair.public_key, keypair.private_key))
    }

    fn public_key_size(&self) -> usize {
        self.variant.public_key_size()
    }

    fn private_key_size(&self) -> usize {
        self.variant.private_key_size()
    }

    fn sign(&self, message: &[u8], private_key: &[u8]) -> crate::pqc::PQCResult<Vec<u8>> {
        let keypair = FalconKeypair {
            public_key: Vec::new(), // Not needed for signing
            private_key: private_key.to_vec(),
            variant: self.variant,
        };
        keypair
            .sign(message)
            .map_err(|e| crate::pqc::PQCError::SignatureError(e.to_string()))
    }

    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> crate::pqc::PQCResult<bool> {
        let keypair = FalconKeypair {
            public_key: public_key.to_vec(),
            private_key: Vec::new(), // Not needed for verification
            variant: self.variant,
        };
        keypair
            .verify(message, signature)
            .map_err(|e| crate::pqc::PQCError::VerificationError(e.to_string()))
    }

    fn signature_size(&self) -> usize {
        self.variant.signature_size()
    }
}

/// Falcon signature batch operations for performance
pub struct FalconBatchSigner {
    private_key: Vec<u8>,
    variant: FalconVariant,
}

impl FalconBatchSigner {
    /// Create a new batch signer with input validation
    pub fn new(private_key: Vec<u8>, variant: FalconVariant) -> CryptoResult<Self> {
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
    /// # Performance
    /// Pre-allocates result vector. Consider parallel processing for large batches.
    ///
    /// # Security
    /// - Recommended batch size: ≤ 1000 messages
    /// - Each signature uses fresh randomness
    pub fn batch_sign(&self, messages: &[&[u8]]) -> CryptoResult<Vec<Vec<u8>>> {
        // Pre-allocate for performance
        let mut signatures = Vec::with_capacity(messages.len());

        // Batch size limit
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
                return Err(CryptoError::InvalidInput(
                    "Message too large in batch".to_string(),
                ));
            }

            let signature = match self.variant {
                FalconVariant::Falcon512 => {
                    let sk = falcon512::SecretKey::from_bytes(&self.private_key).map_err(|_| {
                        CryptoError::InvalidKey("Key validation failed".to_string())
                    })?;
                    let detached_sig = falcon512::detached_sign(message, &sk);
                    detached_sig.as_bytes().to_vec()
                }
                FalconVariant::Falcon1024 => {
                    let sk =
                        falcon1024::SecretKey::from_bytes(&self.private_key).map_err(|_| {
                            CryptoError::InvalidKey("Key validation failed".to_string())
                        })?;
                    let detached_sig = falcon1024::detached_sign(message, &sk);
                    detached_sig.as_bytes().to_vec()
                }
            };

            signatures.push(signature);
        }

        Ok(signatures)
    }
}

/// Falcon signature batch verifier for performance
pub struct FalconBatchVerifier {
    public_key: Vec<u8>,
    variant: FalconVariant,
}

impl FalconBatchVerifier {
    /// Create a new batch verifier
    pub fn new(public_key: Vec<u8>, variant: FalconVariant) -> Self {
        Self {
            public_key,
            variant,
        }
    }

    /// Verify multiple signatures efficiently
    pub fn batch_verify(
        &self,
        messages: &[&[u8]],
        signatures: &[&[u8]],
    ) -> CryptoResult<Vec<bool>> {
        if messages.len() != signatures.len() {
            return Err(CryptoError::InvalidInput(
                "Messages and signatures count mismatch".to_string(),
            ));
        }

        let mut results = Vec::new();

        for (message, signature) in messages.iter().zip(signatures.iter()) {
            let is_valid = match self.variant {
                FalconVariant::Falcon512 => {
                    let pk = falcon512::PublicKey::from_bytes(&self.public_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid Falcon-512 public key".to_string())
                    })?;
                    let detached_sig = falcon512::DetachedSignature::from_bytes(signature)
                        .map_err(|_| {
                            CryptoError::InvalidSignature(
                                "Invalid Falcon-512 signature".to_string(),
                            )
                        })?;
                    falcon512::verify_detached_signature(&detached_sig, message, &pk).is_ok()
                }
                FalconVariant::Falcon1024 => {
                    let pk = falcon1024::PublicKey::from_bytes(&self.public_key).map_err(|_| {
                        CryptoError::InvalidKey("Invalid Falcon-1024 public key".to_string())
                    })?;
                    let detached_sig = falcon1024::DetachedSignature::from_bytes(signature)
                        .map_err(|_| {
                            CryptoError::InvalidSignature(
                                "Invalid Falcon-1024 signature".to_string(),
                            )
                        })?;
                    falcon1024::verify_detached_signature(&detached_sig, message, &pk).is_ok()
                }
            };

            results.push(is_valid);
        }

        Ok(results)
    }
}

/// Compare Falcon with ML-DSA for signature sizes
pub fn compare_signature_sizes() -> Vec<(String, usize, usize)> {
    vec![
        ("Falcon-512".to_string(), 690, 897),
        ("Falcon-1024".to_string(), 1330, 1793),
        ("ML-DSA-44".to_string(), 2420, 1312),
        ("ML-DSA-65".to_string(), 3309, 1952),
        ("ML-DSA-87".to_string(), 4627, 2592),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_falcon_variant_properties() {
        assert_eq!(FalconVariant::Falcon512.public_key_size(), 897);
        assert_eq!(FalconVariant::Falcon512.private_key_size(), 1281);
        assert_eq!(FalconVariant::Falcon512.signature_size(), 690);

        assert_eq!(FalconVariant::Falcon1024.public_key_size(), 1793);
        assert_eq!(FalconVariant::Falcon1024.private_key_size(), 2305);
        assert_eq!(FalconVariant::Falcon1024.signature_size(), 1330);
    }

    #[test]
    fn test_falcon_keypair_generation() {
        let keypair = FalconKeypair::generate(FalconVariant::Falcon512).unwrap();

        assert_eq!(keypair.public_key.len(), 897);
        assert_eq!(keypair.private_key.len(), 1281);
        assert_eq!(keypair.variant, FalconVariant::Falcon512);
    }

    #[test]
    fn test_falcon_sign_verify() {
        let keypair = FalconKeypair::generate(FalconVariant::Falcon1024).unwrap();
        let message = b"Hello, Falcon World!";

        let signature = keypair.sign(message).unwrap();

        // Falcon signatures have variable length - check within range
        let max_size = FalconVariant::Falcon1024.max_signature_size();
        let min_size = 1250; // Minimum expected
        assert!(
            signature.len() >= min_size && signature.len() <= max_size,
            "Signature size {} not in range [{}, {}]",
            signature.len(),
            min_size,
            max_size
        );

        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid, "Valid signature should verify successfully");

        // Test with wrong message
        let wrong_message = b"Hello, Wrong World!";
        let is_invalid = keypair.verify(wrong_message, &signature).unwrap();
        assert!(
            !is_invalid,
            "Signature should not verify with different message"
        );
    }

    #[test]
    fn test_falcon_provider_trait() {
        let provider = FalconProvider::new(FalconVariant::Falcon512);

        assert_eq!(provider.variant.security_level(), "128-bit");
        assert_eq!(provider.variant.public_key_size(), 897);
        assert_eq!(provider.variant.private_key_size(), 1281);
        assert_eq!(provider.variant.signature_size(), 690);
    }

    #[test]
    fn test_batch_operations() {
        let keypair = FalconKeypair::generate(FalconVariant::Falcon512).unwrap();
        let messages: Vec<&[u8]> = vec![b"Message 1", b"Message 2", b"Message 3"];

        let batch_signer =
            FalconBatchSigner::new(keypair.private_key.clone(), FalconVariant::Falcon512).unwrap();
        let signatures = batch_signer.batch_sign(&messages).unwrap();

        assert_eq!(signatures.len(), 3, "Should produce 3 signatures");

        // Falcon signatures have variable sizes - check all are within range
        let max_size = FalconVariant::Falcon512.max_signature_size();
        let min_size = 650;
        for sig in &signatures {
            assert!(
                sig.len() >= min_size && sig.len() <= max_size,
                "Signature size {} not in valid range [{}, {}]",
                sig.len(),
                min_size,
                max_size
            );
        }

        let batch_verifier = FalconBatchVerifier::new(keypair.public_key, FalconVariant::Falcon512);
        let results = batch_verifier
            .batch_verify(
                &messages,
                &signatures.iter().map(|s| s.as_slice()).collect::<Vec<_>>(),
            )
            .unwrap();

        assert_eq!(results.len(), 3);
        assert!(
            results.iter().all(|&valid| valid),
            "All signatures should be valid"
        );
    }

    #[test]
    fn test_signature_size_comparison() {
        let sizes = compare_signature_sizes();

        // Falcon should have smaller signatures than ML-DSA for same security level
        let falcon_128 = sizes
            .iter()
            .find(|(name, _, _)| name == "Falcon-512")
            .unwrap();
        let falcon_256 = sizes
            .iter()
            .find(|(name, _, _)| name == "Falcon-1024")
            .unwrap();
        let mldsa_128 = sizes
            .iter()
            .find(|(name, _, _)| name == "ML-DSA-44")
            .unwrap();
        let mldsa_256 = sizes
            .iter()
            .find(|(name, _, _)| name == "ML-DSA-87")
            .unwrap();

        // Falcon signatures should be smaller than ML-DSA for same security level
        assert!(falcon_128.1 < mldsa_128.1); // Falcon-512 sig < ML-DSA-44 sig
        assert!(falcon_256.1 < mldsa_256.1); // Falcon-1024 sig < ML-DSA-87 sig

        // But public keys might be different
        // Falcon-512 has smaller public key than ML-DSA-44
        assert!(falcon_128.2 < mldsa_128.2);
    }

    #[test]
    fn test_different_variants() {
        for variant in [FalconVariant::Falcon512, FalconVariant::Falcon1024] {
            let keypair = FalconKeypair::generate(variant).unwrap();
            let message = b"Test message";

            let signature = keypair.sign(message).unwrap();

            // Check signature is within valid range
            let max_size = variant.max_signature_size();
            let min_size = match variant {
                FalconVariant::Falcon512 => 650,
                FalconVariant::Falcon1024 => 1250,
            };
            assert!(
                signature.len() >= min_size && signature.len() <= max_size,
                "Variant {:?}: signature size {} not in range [{}, {}]",
                variant,
                signature.len(),
                min_size,
                max_size
            );

            let is_valid = keypair.verify(message, &signature).unwrap();
            assert!(
                is_valid,
                "Signature for variant {:?} should be valid",
                variant
            );
        }
    }

    #[test]
    fn test_input_validation() {
        let keypair = FalconKeypair::generate(FalconVariant::Falcon512).unwrap();

        // Test invalid key size
        let invalid_sk = vec![0u8; 100];
        let batch_signer = FalconBatchSigner::new(invalid_sk, FalconVariant::Falcon512);
        assert!(batch_signer.is_err(), "Should reject invalid key size");

        // Test message too large
        let huge_message = vec![0u8; 101 * 1024 * 1024];
        let result = keypair.sign(&huge_message);
        assert!(result.is_err(), "Should reject oversized message");

        // Test batch size limit
        let batch_signer =
            FalconBatchSigner::new(keypair.private_key.clone(), FalconVariant::Falcon512).unwrap();
        let too_many: Vec<&[u8]> = vec![b"msg"; 1001];
        let result = batch_signer.batch_sign(&too_many);
        assert!(result.is_err(), "Should reject oversized batch");
    }
}
