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

    /// Get the signature size in bytes for this variant
    pub fn signature_size(&self) -> usize {
        match self {
            MLDsaVariant::MLDsa44 => 2420,
            MLDsaVariant::MLDsa65 => 3309,
            MLDsaVariant::MLDsa87 => 4627,
        }
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

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> CryptoResult<Vec<u8>> {
        match self.variant {
            MLDsaVariant::MLDsa44 => {
                let sk = mldsa44::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-44 private key".to_string()))?;
                let signed_message = mldsa44::sign(message, &sk);
                Ok(signed_message.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa65 => {
                let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-65 private key".to_string()))?;
                let signed_message = mldsa65::sign(message, &sk);
                Ok(signed_message.as_bytes().to_vec())
            }
            MLDsaVariant::MLDsa87 => {
                let sk = mldsa87::SecretKey::from_bytes(&self.private_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-87 private key".to_string()))?;
                let signed_message = mldsa87::sign(message, &sk);
                Ok(signed_message.as_bytes().to_vec())
            }
        }
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> CryptoResult<bool> {
        match self.variant {
            MLDsaVariant::MLDsa44 => {
                let pk = mldsa44::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-44 public key".to_string()))?;
                let detached_sig = mldsa44::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-44 signature".to_string()))?;
                let result = mldsa44::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
            }
            MLDsaVariant::MLDsa65 => {
                let pk = mldsa65::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-65 public key".to_string()))?;
                let detached_sig = mldsa65::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-65 signature".to_string()))?;
                let result = mldsa65::verify_detached_signature(&detached_sig, message, &pk);
                Ok(result.is_ok())
            }
            MLDsaVariant::MLDsa87 => {
                let pk = mldsa87::PublicKey::from_bytes(&self.public_key)
                    .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-87 public key".to_string()))?;
                let detached_sig = mldsa87::DetachedSignature::from_bytes(signature)
                    .map_err(|_| CryptoError::InvalidSignature("Invalid ML-DSA-87 signature".to_string()))?;
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
    pub fn new(private_key: Vec<u8>, variant: MLDsaVariant) -> Self {
        Self {
            private_key,
            variant,
        }
    }

    /// Sign multiple messages efficiently
    pub fn batch_sign(&self, messages: &[&[u8]]) -> CryptoResult<Vec<Vec<u8>>> {
        let mut signatures = Vec::new();

        for message in messages {
            let signature = match self.variant {
                MLDsaVariant::MLDsa44 => {
                    let sk = mldsa44::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-44 private key".to_string()))?;
                    let signed_message = mldsa44::sign(message, &sk);
                    signed_message.as_bytes().to_vec()
                }
                MLDsaVariant::MLDsa65 => {
                    let sk = mldsa65::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-65 private key".to_string()))?;
                    let signed_message = mldsa65::sign(message, &sk);
                    signed_message.as_bytes().to_vec()
                }
                MLDsaVariant::MLDsa87 => {
                    let sk = mldsa87::SecretKey::from_bytes(&self.private_key)
                        .map_err(|_| CryptoError::InvalidKey("Invalid ML-DSA-87 private key".to_string()))?;
                    let signed_message = mldsa87::sign(message, &sk);
                    signed_message.as_bytes().to_vec()
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
        assert_eq!(MLDsaVariant::MLDsa44.public_key_size(), 1312);
        assert_eq!(MLDsaVariant::MLDsa44.private_key_size(), 2560);
        assert_eq!(MLDsaVariant::MLDsa44.signature_size(), 2420);

        assert_eq!(MLDsaVariant::MLDsa65.public_key_size(), 1952);
        assert_eq!(MLDsaVariant::MLDsa65.private_key_size(), 4032);
        assert_eq!(MLDsaVariant::MLDsa65.signature_size(), 3309);

        assert_eq!(MLDsaVariant::MLDsa87.public_key_size(), 2592);
        assert_eq!(MLDsaVariant::MLDsa87.private_key_size(), 4896);
        assert_eq!(MLDsaVariant::MLDsa87.signature_size(), 4627);
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
        assert_eq!(signature.len(), 2420);

        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid);

        // Test with wrong message
        let wrong_message = b"Hello, Wrong World!";
        let is_invalid = keypair.verify(wrong_message, &signature).unwrap();
        assert!(!is_invalid);
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

        let batch_signer = MLDsaBatchSigner::new(keypair.private_key.clone(), MLDsaVariant::MLDsa44);
        let signatures = batch_signer.batch_sign(&messages).unwrap();

        assert_eq!(signatures.len(), 3);
        assert!(signatures.iter().all(|sig| sig.len() == 2420));

        let batch_verifier = MLDsaBatchVerifier::new(keypair.public_key, MLDsaVariant::MLDsa44);
        let sig_slices: Vec<&[u8]> = signatures.iter().map(|s| s.as_slice()).collect();
        let results = batch_verifier.batch_verify(&messages, &sig_slices).unwrap();

        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|&valid| valid));
    }

    #[test]
    fn test_different_variants() {
        for variant in [MLDsaVariant::MLDsa44, MLDsaVariant::MLDsa65, MLDsaVariant::MLDsa87] {
            let keypair = MLDsaKeypair::generate(variant).unwrap();
            let message = b"Test message";

            let signature = keypair.sign(message).unwrap();
            assert_eq!(signature.len(), variant.signature_size());

            let is_valid = keypair.verify(message, &signature).unwrap();
            assert!(is_valid);
        }
    }
}
