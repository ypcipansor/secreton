//! Digital signature implementations

use crate::{AlgorithmId, CryptoError, CryptoResult};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use signature::{SignatureEncoding, Signer, Verifier};

/// Signing engine for digital signatures
pub struct SigningEngine;

impl SigningEngine {
    /// Sign data using the specified algorithm and private key
    pub fn sign(algorithm: AlgorithmId, key: &[u8], data: &[u8]) -> CryptoResult<Vec<u8>> {
        match algorithm {
            AlgorithmId::Ed25519 => {
                if key.len() != 32 {
                    return Err(CryptoError::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    });
                }
                let seed: &[u8; 32] =
                    key.try_into().map_err(|_| CryptoError::InvalidKeyLength {
                        expected: 32,
                        actual: key.len(),
                    })?;
                let signing_key = SigningKey::from_bytes(seed);
                let signature = signing_key.sign(data);
                Ok(signature.to_vec())
            }
            AlgorithmId::EcdsaP256 => {
                let signing_key = P256SigningKey::from_pkcs8_der(key).map_err(|e| {
                    CryptoError::InvalidKey(format!("Invalid ECDSA P-256 key: {}", e))
                })?;
                let signature: P256Signature = signing_key.sign(data);
                Ok(signature.to_vec())
            }
            AlgorithmId::EcdsaP384 => {
                let signing_key = P384SigningKey::from_pkcs8_der(key).map_err(|e| {
                    CryptoError::InvalidKey(format!("Invalid ECDSA P-384 key: {}", e))
                })?;
                let signature: P384Signature = signing_key.sign(data);
                Ok(signature.to_vec())
            }
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "Algorithm {} not supported for signing",
                algorithm
            ))),
        }
    }

    /// Verify signature using the specified algorithm and key
    ///
    /// The key can be either a private key (from which public key is derived)
    /// or a public key (if supported by the format - currently assuming private key for consistency with sign)
    pub fn verify(
        algorithm: AlgorithmId,
        key: &[u8],
        data: &[u8],
        signature: &[u8],
    ) -> CryptoResult<bool> {
        match algorithm {
            AlgorithmId::Ed25519 => {
                // If key is 32 bytes, assume it's private seed (standard for this codebase's generate_key)
                // If we want to support verifying with public key, we'd need to know if it's public.
                // For now, we assume we are using the stored key which is private.
                if let Ok(seed) = <&[u8; 32]>::try_from(key) {
                    let signing_key = SigningKey::from_bytes(seed);
                    let verifying_key = signing_key.verifying_key();

                    let signature = Signature::from_bytes(signature.try_into().map_err(|_| {
                        CryptoError::InvalidSignature(
                            "Invalid Ed25519 signature length".to_string(),
                        )
                    })?);
                    Ok(verifying_key.verify(data, &signature).is_ok())
                } else {
                    // Maybe it's a public key? (32 bytes as well for Ed25519 public)
                    // Ambiguous. But given context, we likely have the private key.
                    // If we passed public key, we would use VerifyingKey::from_bytes
                    let verifying_key = VerifyingKey::from_bytes(key.try_into().map_err(|_| {
                        CryptoError::InvalidKeyLength {
                            expected: 32,
                            actual: key.len(),
                        }
                    })?)
                    .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
                    let signature = Signature::from_bytes(signature.try_into().map_err(|_| {
                        CryptoError::InvalidSignature(
                            "Invalid Ed25519 signature length".to_string(),
                        )
                    })?);
                    Ok(verifying_key.verify(data, &signature).is_ok())
                }
            }
            AlgorithmId::EcdsaP256 => {
                // Try parsing as private key first
                if let Ok(signing_key) = P256SigningKey::from_pkcs8_der(key) {
                    let verifying_key = signing_key.verifying_key();
                    let signature = P256Signature::from_slice(signature).map_err(|e| {
                        CryptoError::InvalidSignature(format!("Invalid ECDSA signature: {}", e))
                    })?;
                    Ok(verifying_key.verify(data, &signature).is_ok())
                } else {
                    // Try as public key
                    let verifying_key =
                        P256VerifyingKey::from_public_key_der(key).map_err(|e| {
                            CryptoError::InvalidKey(format!("Invalid ECDSA P-256 key: {}", e))
                        })?;
                    let signature = P256Signature::from_slice(signature).map_err(|e| {
                        CryptoError::InvalidSignature(format!("Invalid ECDSA signature: {}", e))
                    })?;
                    Ok(verifying_key.verify(data, &signature).is_ok())
                }
            }
            AlgorithmId::EcdsaP384 => {
                // Try parsing as private key first
                if let Ok(signing_key) = P384SigningKey::from_pkcs8_der(key) {
                    let verifying_key = signing_key.verifying_key();
                    let signature = P384Signature::from_slice(signature).map_err(|e| {
                        CryptoError::InvalidSignature(format!("Invalid ECDSA signature: {}", e))
                    })?;
                    Ok(verifying_key.verify(data, &signature).is_ok())
                } else {
                    // Try as public key
                    let verifying_key =
                        P384VerifyingKey::from_public_key_der(key).map_err(|e| {
                            CryptoError::InvalidKey(format!("Invalid ECDSA P-384 key: {}", e))
                        })?;
                    let signature = P384Signature::from_slice(signature).map_err(|e| {
                        CryptoError::InvalidSignature(format!("Invalid ECDSA signature: {}", e))
                    })?;
                    Ok(verifying_key.verify(data, &signature).is_ok())
                }
            }
            _ => Err(CryptoError::InvalidAlgorithm(format!(
                "Algorithm {} not supported for verification",
                algorithm
            ))),
        }
    }
}
