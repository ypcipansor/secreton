use secreton_crypto::{EncryptedData, AlgorithmId, SecurityParams, CryptoEngine, generate_key};
use anyhow::Result;
use std::env;
use tracing::warn;

/// Crypto service for API operations
pub struct CryptoService {
    engine: CryptoEngine,
    master_key: Vec<u8>,
}

impl CryptoService {
    pub fn new() -> Self {
        let master_key = match env::var("SECRETON_MASTER_KEY") {
            Ok(key_hex) => {
                match hex::decode(&key_hex) {
                    Ok(bytes) => {
                        if bytes.len() != 32 {
                            warn!("SECRETON_MASTER_KEY must be 32 bytes (64 hex chars). Generating random key.");
                            generate_key(AlgorithmId::Aes256Gcm).unwrap_or_else(|_| vec![0u8; 32])
                        } else {
                            bytes
                        }
                    },
                    Err(_) => {
                        warn!("Invalid hex in SECRETON_MASTER_KEY. Generating random key.");
                        generate_key(AlgorithmId::Aes256Gcm).unwrap_or_else(|_| vec![0u8; 32])
                    }
                }
            },
            Err(_) => {
                warn!("SECRETON_MASTER_KEY not set. Generating random ephemeral key (data will be lost on restart).");
                generate_key(AlgorithmId::Aes256Gcm).unwrap_or_else(|_| vec![0u8; 32])
            }
        };

        Self {
            engine: CryptoEngine::new(),
            master_key,
        }
    }

    pub fn encrypt(&self, key: &[u8], plaintext: &[u8], _params: Option<&SecurityParams>) -> Result<EncryptedData> {
        let result = self.engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, key)?;
        Ok(result)
    }

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Deserialize the ciphertext back into EncryptedData using bincode (more compact than JSON)
        let (encrypted_data, _): (EncryptedData, usize) = bincode::serde::decode_from_slice(
            ciphertext,
            bincode::config::standard()
        ).map_err(|e| anyhow::anyhow!("Failed to deserialize encrypted data: {}", e))?;

        self.decrypt_data(&encrypted_data)
    }

    pub fn decrypt_full(&self, key: &[u8], nonce: &[u8], ciphertext: &[u8], _aad: Option<&[u8]>) -> Result<Vec<u8>> {
        // Construct EncryptedData
        let encrypted_data = EncryptedData {
            algorithm: AlgorithmId::Aes256Gcm,
            nonce: nonce.to_vec(),
            ciphertext: ciphertext.to_vec(),
            tag: None, // Tag is implicitly in ciphertext for GCM in this implementation usually, but EncryptedData has Option<tag>
        };

        // Use engine to decrypt
        let result = self.engine.decrypt(&encrypted_data, key)?;
        Ok(result)
    }

    pub fn decrypt_data(&self, data: &EncryptedData) -> Result<Vec<u8>> {
        // Use the master key to decrypt
        let result = self.engine.decrypt(data, &self.master_key)?;
        Ok(result)
    }

    /// Encrypt data with the internal master key
    pub fn encrypt_data(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        // Encrypt using master key
        let encrypted_data = self.engine.encrypt(AlgorithmId::Aes256Gcm, plaintext, &self.master_key)?;

        // Serialize EncryptedData to Vec<u8> using bincode
        let serialized = bincode::serde::encode_to_vec(&encrypted_data, bincode::config::standard())
            .map_err(|e| anyhow::anyhow!("Failed to serialize encrypted data: {}", e))?;

        Ok(serialized)
    }

    pub fn sign_data(&self, _key: &[u8], _data: &[u8]) -> Result<Vec<u8>> {
        // Placeholder signature
        // TODO: Implement actual signing using key
        Ok(vec![0u8; 64])
    }

    pub fn verify_signature(&self, _key: &[u8], _data: &[u8], _signature: &[u8]) -> Result<bool> {
        // Placeholder verification
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_service_lifecycle() {
        let service = CryptoService::new();
        let plaintext = b"Hello, World!";

        // Test encryption
        let encrypted = service.encrypt_data(plaintext).expect("Encryption failed");
        assert_ne!(plaintext, encrypted.as_slice());

        // Verify it is not JSON (simple heuristic: doesn't start with curly brace)
        assert_ne!(encrypted[0], b'{');

        // Test decryption
        let decrypted = service.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_unique_ciphertexts() {
        let service = CryptoService::new();
        let plaintext = b"Hello, World!";

        let encrypted1 = service.encrypt_data(plaintext).expect("Encryption 1 failed");
        let encrypted2 = service.encrypt_data(plaintext).expect("Encryption 2 failed");

        // Nonces should make ciphertexts different
        assert_ne!(encrypted1, encrypted2);
    }
}
