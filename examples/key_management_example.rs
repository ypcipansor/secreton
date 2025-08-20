//! Example of using the key management system in Brankas Adhyaksa

use brankas_adhyaksa::{
    key_management::{
        KeyManager, KeyType, KeyMetadata, KeyData,
        KeyError, KeyManagerConfig
    },
};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), KeyError> {
    // Create a key manager with default config
    let key_manager = KeyManager::new();
    
    // Generate a new AES-256-GCM key
    let key_metadata = KeyMetadata::new("my-encryption-key")
        .with_ttl(30 * 24 * 60 * 60) // 30 days
        .with_tag("encryption")
        .with_tag("high-security");
    
    let key = key_manager.generate_symmetric_key(KeyType::Aes256Gcm)
        .await
        .with_metadata(key_metadata);
    
    println!("Generated key: {:?}", key.id);
    
    // Encrypt some data
    let plaintext = b"Hello, Brankas Adhyaksa!";
    let ciphertext = key_manager.encrypt(&key.id, plaintext).await?;
    println!("Encrypted data: {:?}", ciphertext);
    
    // Decrypt the data
    let decrypted = key_manager.decrypt(&key.id, &ciphertext).await?;
    let decrypted_str = String::from_utf8_lossy(&decrypted);
    println!("Decrypted data: {}", decrypted_str);
    
    // Generate an HMAC key for signing
    let hmac_key = key_manager.generate_symmetric_key(KeyType::HmacSha256)
        .await
        .with_metadata(KeyMetadata::new("my-hmac-key"));
    
    // In a real application, you would use the sign/verify methods
    // let signature = key_manager.sign(&hmac_key.id, plaintext).await?;
    // let is_valid = key_manager.verify(&hmac_key.id, plaintext, &signature).await?;
    
    println!("HMAC key generated: {}", hmac_key.id);
    
    Ok(())
}
