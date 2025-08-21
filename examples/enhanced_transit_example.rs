//! Enhanced Transit Engine Example with RustCrypto Integration
//! 
//! This example demonstrates the comprehensive features of the Brankas Transit Engine
//! including key management, encryption/decryption, and random generation.

use brankas_crypto::transit::*;
use brankas_crypto::error::{CryptoResult, CryptoError};
use tokio;
use tracing::{info, warn, error};

#[tokio::main]
async fn main() -> CryptoResult<()> {
    // Initialize tracing
    tracing_subscriber::init();
    
    info!("Starting Enhanced Transit Engine Example");
    
    // Create enhanced transit engine
    let engine = TransitEngine::new();
    
    // Demonstrate key creation with different algorithms
    demo_key_creation(&engine).await?;
    
    // Demonstrate encryption/decryption operations
    demo_encryption_operations(&engine).await?;
    
    // Demonstrate random generation
    demo_random_generation(&engine).await?;
    
    info!("Enhanced Transit Engine Example completed successfully");
    Ok(())
}

/// Demonstrate key creation with different algorithms
async fn demo_key_creation(engine: &TransitEngine) -> CryptoResult<()> {
    info!("=== Key Creation Demo ===");
    
    // Create AES-256-GCM key
    let aes_options = KeyOptions {
        exportable: false,
        usage: vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
    };
    engine.create_key("aes-key".to_string(), KeyType::Aes256Gcm, Some(aes_options)).await?;
    info!("Created AES-256-GCM key: aes-key");
    
    // Create ChaCha20-Poly1305 key
    engine.create_key("chacha-key".to_string(), KeyType::ChaCha20Poly1305, None).await?;
    info!("Created ChaCha20-Poly1305 key: chacha-key");
    
    // List all keys
    let keys = engine.list_keys().await;
    info!("Created {} keys: {:?}", keys.len(), keys);
    
    Ok(())
}

/// Demonstrate encryption and decryption operations
async fn demo_encryption_operations(engine: &TransitEngine) -> CryptoResult<()> {
    info!("=== Encryption/Decryption Demo ===");
    
    let plaintext = b"This is sensitive data that needs to be encrypted securely!";
    let context = Some(b"additional-context-data".as_slice());
    
    // AES-256-GCM encryption
    let aes_ciphertext = engine.encrypt("aes-key", plaintext, context, None).await?;
    info!("AES-GCM encrypted {} bytes -> {} characters", plaintext.len(), aes_ciphertext.len());
    
    let aes_decrypted = engine.decrypt("aes-key", &aes_ciphertext, context).await?;
    assert_eq!(plaintext, aes_decrypted.as_slice());
    info!("AES-GCM decryption successful");
    
    // ChaCha20-Poly1305 encryption
    let chacha_ciphertext = engine.encrypt("chacha-key", plaintext, context, None).await?;
    info!("ChaCha20 encrypted {} bytes -> {} characters", plaintext.len(), chacha_ciphertext.len());
    
    let chacha_decrypted = engine.decrypt("chacha-key", &chacha_ciphertext, context).await?;
    assert_eq!(plaintext, chacha_decrypted.as_slice());
    info!("ChaCha20 decryption successful");
    
    Ok(())
}

/// Demonstrate random generation
async fn demo_random_generation(engine: &TransitEngine) -> CryptoResult<()> {
    info!("=== Random Generation Demo ===");
    
    // Generate random data
    let random_256 = engine.random(32).await?;
    info!("Generated {} random bytes", random_256.len());
    
    let random_1024 = engine.random(128).await?;
    info!("Generated {} random bytes", random_1024.len());
    
    // Test that random data is different
    let random1 = engine.random(32).await?;
    let random2 = engine.random(32).await?;
    
    if random1 != random2 {
        info!("Random generation working correctly (different values)");
    } else {
        warn!("Random generation may have issues (same values)");
    }
    
    Ok(())
}
