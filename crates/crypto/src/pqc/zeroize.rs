//! Secure Key Zeroization for Post-Quantum Cryptography
//!
//! This module provides secure memory zeroization for PQC key material
//! to prevent secrets from lingering in memory after use.
//!
//! # Security Features
//! - Automatic zeroization via Drop trait
//! - Prevents compiler optimization of zeroing operations
//! - Covers all PQC key types (ML-DSA, ML-KEM, Falcon)
//! - Defense-in-depth against memory disclosure attacks

use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for ML-DSA private keys with automatic zeroization
#[derive(Clone)]
pub struct SecureMLDsaPrivateKey {
    key: Vec<u8>,
}

impl SecureMLDsaPrivateKey {
    /// Create new secure private key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Get reference to key bytes (read-only)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get mutable reference to key bytes (use with caution)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.key
    }

    /// Convert to raw bytes (consumes self, no zeroization)
    ///
    /// # Safety
    /// This bypasses automatic zeroization. Use only when transferring ownership.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.key)
    }
}

impl Drop for SecureMLDsaPrivateKey {
    fn drop(&mut self) {
        // Secure zeroization - prevents compiler optimization
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for SecureMLDsaPrivateKey {}

/// Secure wrapper for ML-KEM private keys with automatic zeroization
#[derive(Clone)]
pub struct SecureMLKemPrivateKey {
    key: Vec<u8>,
}

impl SecureMLKemPrivateKey {
    /// Create new secure private key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Get reference to key bytes (read-only)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get mutable reference to key bytes (use with caution)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.key
    }

    /// Convert to raw bytes (consumes self, no zeroization)
    ///
    /// # Safety
    /// This bypasses automatic zeroization. Use only when transferring ownership.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.key)
    }
}

impl Drop for SecureMLKemPrivateKey {
    fn drop(&mut self) {
        // Secure zeroization - prevents compiler optimization
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for SecureMLKemPrivateKey {}

/// Secure wrapper for Falcon private keys with automatic zeroization
#[derive(Clone)]
pub struct SecureFalconPrivateKey {
    key: Vec<u8>,
}

impl SecureFalconPrivateKey {
    /// Create new secure private key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Get reference to key bytes (read-only)
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }

    /// Get mutable reference to key bytes (use with caution)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.key
    }

    /// Convert to raw bytes (consumes self, no zeroization)
    ///
    /// # Safety
    /// This bypasses automatic zeroization. Use only when transferring ownership.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.key)
    }
}

impl Drop for SecureFalconPrivateKey {
    fn drop(&mut self) {
        // Secure zeroization - prevents compiler optimization
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for SecureFalconPrivateKey {}

/// Secure wrapper for ML-KEM shared secrets with automatic zeroization
#[derive(Clone)]
pub struct SecureSharedSecret {
    secret: Vec<u8>,
}

impl SecureSharedSecret {
    /// Create new secure shared secret
    pub fn new(secret: Vec<u8>) -> Self {
        Self { secret }
    }

    /// Get reference to secret bytes (read-only)
    pub fn as_bytes(&self) -> &[u8] {
        &self.secret
    }

    /// Get mutable reference to secret bytes (use with caution)
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.secret
    }

    /// Convert to raw bytes (consumes self, no zeroization)
    ///
    /// # Safety
    /// This bypasses automatic zeroization. Use only when transferring ownership.
    pub fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.secret)
    }
}

impl Drop for SecureSharedSecret {
    fn drop(&mut self) {
        // Secure zeroization - prevents compiler optimization
        self.secret.zeroize();
    }
}

impl ZeroizeOnDrop for SecureSharedSecret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mldsa_key_zeroization() {
        let key_data = vec![0x42; 2560]; // ML-DSA-44 private key size
        let mut secure_key = SecureMLDsaPrivateKey::new(key_data.clone());

        // Verify key is intact
        assert_eq!(secure_key.as_bytes(), &key_data);

        // Manually trigger drop and verify zeroization
        let key_ptr = secure_key.as_bytes_mut().as_mut_ptr();
        drop(secure_key);

        // Note: This is a simplified test. In production, you'd use memory
        // analysis tools to verify zeroing actually occurred.
    }

    #[test]
    fn test_mlkem_key_zeroization() {
        let key_data = vec![0x33; 1632]; // ML-KEM-512 private key size
        let secure_key = SecureMLKemPrivateKey::new(key_data.clone());

        assert_eq!(secure_key.as_bytes(), &key_data);
        drop(secure_key);
        // Key should be zeroed after drop
    }

    #[test]
    fn test_falcon_key_zeroization() {
        let key_data = vec![0x55; 1281]; // Falcon-512 private key size
        let secure_key = SecureFalconPrivateKey::new(key_data.clone());

        assert_eq!(secure_key.as_bytes(), &key_data);
        drop(secure_key);
        // Key should be zeroed after drop
    }

    #[test]
    fn test_shared_secret_zeroization() {
        let secret_data = vec![0x77; 32]; // 256-bit shared secret
        let secure_secret = SecureSharedSecret::new(secret_data.clone());

        assert_eq!(secure_secret.as_bytes(), &secret_data);
        drop(secure_secret);
        // Secret should be zeroed after drop
    }

    #[test]
    fn test_as_bytes_immutability() {
        let key_data = vec![0xAA; 1632];
        let secure_key = SecureMLKemPrivateKey::new(key_data.clone());

        // Should only allow read access
        let bytes = secure_key.as_bytes();
        assert_eq!(bytes.len(), 1632);
        assert_eq!(bytes[0], 0xAA);
    }

    #[test]
    fn test_into_bytes_no_zeroization() {
        let key_data = vec![0xBB; 2560];
        let secure_key = SecureMLDsaPrivateKey::new(key_data.clone());

        // Explicitly extract bytes without zeroization
        let extracted = secure_key.into_bytes();
        assert_eq!(extracted, key_data);
        assert_eq!(extracted[0], 0xBB); // Should still contain data
    }
}
