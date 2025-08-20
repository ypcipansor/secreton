use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use std::sync::OnceLock;

static ENCRYPTION_KEY: OnceLock<[u8; 32]> = OnceLock::new();

pub fn init_encryption_key(key: &[u8]) -> Result<()> {
    if key.len() != 32 {
        return Err(anyhow::anyhow!("Encryption key must be 32 bytes"));
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(key);
    ENCRYPTION_KEY
        .set(key_bytes)
        .map_err(|_| anyhow::anyhow!("Encryption key already initialized"))?;
    Ok(())
}

pub fn encrypt_data(plaintext: &[u8]) -> Result<String> {
    let key = ENCRYPTION_KEY
        .get()
        .ok_or_else(|| anyhow::anyhow!("Encryption key not initialized"))?;
    
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .context("Failed to encrypt data")?;
    
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(general_purpose::STANDARD.encode(&result))
}

pub fn decrypt_data(encoded: &str) -> Result<Vec<u8>> {
    let key = ENCRYPTION_KEY
        .get()
        .ok_or_else(|| anyhow::anyhow!("Encryption key not initialized"))?;
    
    let data = general_purpose::STANDARD
        .decode(encoded)
        .context("Failed to decode base64 data")?;
    
    if data.len() < 12 {
        return Err(anyhow::anyhow!("Invalid encrypted data"));
    }
    
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    cipher
        .decrypt(nonce, ciphertext)
        .context("Failed to decrypt data")
}
