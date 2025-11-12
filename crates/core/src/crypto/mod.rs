pub mod pki;

pub use pki::{Certificate, PrivateKey, SignatureAlgorithm};

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::{Engine as _, engine::general_purpose};
use rand::RngCore;
use sha2::{Digest, Sha256};

// Basic crypto functions needed by MFA
pub fn encrypt_data(
    data: &str,
    key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Derive key from string (in production, use proper key derivation)
    let key_bytes = Sha256::digest(key.as_bytes());
    let cipher = <Aes256Gcm as KeyInit>::new(&key_bytes);

    // Generate random nonce
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Encrypt the data
    let ciphertext = cipher
        .encrypt(&nonce, data.as_bytes())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    // Combine nonce + ciphertext and encode as base64
    let mut combined = nonce_bytes.to_vec();
    combined.extend(ciphertext);
    let encoded = general_purpose::STANDARD.encode(&combined);

    Ok(encoded)
}

pub fn decrypt_data(
    encrypted: &str,
    key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Derive key from string (in production, use proper key derivation)
    let key_bytes = Sha256::digest(key.as_bytes());
    let cipher = <Aes256Gcm as KeyInit>::new(&key_bytes);

    // Decode from base64
    let combined = general_purpose::STANDARD.decode(encrypted)?;

    if combined.len() < 12 {
        return Err("Invalid encrypted data: too short".into());
    }

    // Extract nonce and ciphertext
    let nonce_bytes: [u8; 12] = combined[..12].try_into().unwrap();
    let nonce = Nonce::from(nonce_bytes);
    let ciphertext = &combined[12..];

    // Decrypt
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    let result = String::from_utf8(plaintext)?;
    Ok(result)
}
