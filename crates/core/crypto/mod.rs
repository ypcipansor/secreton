use anyhow::Result;
use async_trait::async_trait;

/// A trait for cryptographic operations
#[async_trait]
pub trait CryptoService: Send + Sync + 'static {
    /// Encrypt the given plaintext data
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    
    /// Decrypt the given ciphertext data
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>>;
    
    /// Generate a new encryption key
    fn generate_key() -> Vec<u8>;
}

/// A simple implementation of CryptoService using AES-256-GCM
pub struct AesGcmCrypto {
    key: [u8; 32],
}

impl AesGcmCrypto {
    /// Create a new AesGcmCrypto instance with the given key
    pub fn new(key: [u8; 32]) -> Self {
        Self { key }
    }
    
    /// Generate a new random key
    pub fn generate() -> Self {
        let key = Self::generate_key();
        let key_array: [u8; 32] = key.try_into().expect("Failed to convert key to array");
        Self::new(key_array)
    }
}

#[async_trait]
impl CryptoService for AesGcmCrypto {
    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit, OsRng},
            Aes256Gcm, Nonce,
        };
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
            
        // Generate a random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        
        // Encrypt the data
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
            
        // Combine nonce and ciphertext
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        if ciphertext.len() < 12 {
            return Err(anyhow::anyhow!("Ciphertext too short"));
        }
        
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
            
        // Split nonce and ciphertext
        let (nonce_bytes, ciphertext) = ciphertext.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        // Decrypt the data
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow::anyhow!("Decryption failed"))?;
            
        Ok(plaintext)
    }
    
    fn generate_key() -> Vec<u8> {
        use rand::RngCore;
        
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_encrypt_decrypt() {
        let crypto = AesGcmCrypto::generate();
        let plaintext = b"test message";
        
        let ciphertext = crypto.encrypt(plaintext).await.unwrap();
        let decrypted = crypto.decrypt(&ciphertext).await.unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[tokio::test]
    async fn test_different_keys() {
        let crypto1 = AesGcmCrypto::generate();
        let crypto2 = AesGcmCrypto::generate();
        let plaintext = b"test message";
        
        let ciphertext = crypto1.encrypt(plaintext).await.unwrap();
        let result = crypto2.decrypt(&ciphertext).await;
        
        assert!(result.is_err());
    }
}
