use base64::{engine::general_purpose, Engine as _};
use secreton_core::secrets::engine::{
    CreateKeyRequest, DecryptRequest, EncryptRequest, SecretsEngine, TransitSecretsEngine,
};
use secreton_core::storage::MemoryStorage;
use serde_json::json;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧪 Testing Transit Secrets Engine...");

    // Initialize storage with proper URL parameter
    let storage = Arc::new(MemoryStorage::new("memory://").await.unwrap());
    let engine = TransitSecretsEngine::new(storage);

    // Test 1: Create encryption key
    println!("📝 Test 1: Creating encryption key...");
    let create_key_request = CreateKeyRequest {
        key_type: Some("aes256-gcm96".to_string()),
        exportable: Some(false),
        convergent_encryption: None,
        derived: None,
        allow_plaintext_backup: None,
        key_size: None,
    };

    let result = engine
        .create_secret("transit/keys/test-key", json!(create_key_request), None)
        .await;

    match result {
        Ok(_) => println!("✅ Key creation successful"),
        Err(e) => println!("❌ Key creation failed: {}", e),
    }

    // Test 2: Encrypt data
    println!("📝 Test 2: Encrypting data...");
    let plaintext = "Hello, Secreton!";
    let plaintext_b64 = general_purpose::STANDARD.encode(plaintext.as_bytes());

    let encrypt_request = EncryptRequest {
        plaintext: plaintext_b64,
        context: None,
        key_version: None,
        nonce: None,
        associated_data: None,
        batch_input: None,
    };

    let encrypt_result = engine
        .create_secret("transit/encrypt/test-key", json!(encrypt_request), None)
        .await;

    let ciphertext = match encrypt_result {
        Ok(data) => {
            println!("✅ Encryption successful");
            // The engine returns Secret, need to extract data
            if let Some(secret_data) = data.data.as_object() {
                if let Some(ct) = secret_data.get("ciphertext").and_then(|v| v.as_str()) {
                    ct.to_string()
                } else {
                    println!("❌ Failed to extract ciphertext from response");
                    return Ok(());
                }
            } else {
                println!("❌ Invalid response format");
                return Ok(());
            }
        }
        Err(e) => {
            println!("❌ Encryption failed: {}", e);
            return Err(e.into());
        }
    };

    // Test 3: Decrypt data
    println!("📝 Test 3: Decrypting data...");
    let decrypt_request = DecryptRequest {
        ciphertext: ciphertext.clone(),
        context: None,
        nonce: None,
        associated_data: None,
        batch_input: None,
    };

    let decrypt_result = engine
        .create_secret("transit/decrypt/test-key", json!(decrypt_request), None)
        .await;

    match decrypt_result {
        Ok(data) => {
            if let Some(secret_data) = data.data.as_object() {
                if let Some(decrypted_b64) = secret_data.get("plaintext").and_then(|v| v.as_str()) {
                    let decrypted_bytes = general_purpose::STANDARD.decode(decrypted_b64)?;
                    let decrypted_text = String::from_utf8(decrypted_bytes)?;

                    if decrypted_text == plaintext {
                        println!("✅ Decryption successful: '{}'", decrypted_text);
                    } else {
                        println!(
                            "❌ Decryption mismatch. Expected: '{}', Got: '{}'",
                            plaintext, decrypted_text
                        );
                    }
                } else {
                    println!("❌ Failed to extract plaintext from response");
                }
            } else {
                println!("❌ Invalid response format");
            }
        }
        Err(e) => println!("❌ Decryption failed: {}", e),
    }

    // Test 4: List keys
    println!("📝 Test 4: Listing keys...");
    let list_result = engine.list_secrets("transit/keys/").await;

    match list_result {
        Ok(keys) => {
            println!("✅ Key listing successful. Keys found: {:?}", keys);
        }
        Err(e) => println!("❌ Key listing failed: {}", e),
    }

    // Test 5: Read key metadata
    println!("📝 Test 5: Reading key metadata...");
    let key_result = engine.read_secret("transit/keys/test-key").await;

    match key_result {
        Ok(key_data) => {
            println!("✅ Key metadata retrieval successful: {:?}", key_data);
        }
        Err(e) => println!("❌ Key metadata retrieval failed: {}", e),
    }

    // Test 6: Key rotation
    println!("📝 Test 6: Testing key rotation...");
    let rotate_result = engine
        .create_secret("transit/keys/test-key/rotate", json!({}), None)
        .await;

    match rotate_result {
        Ok(_) => println!("✅ Key rotation successful"),
        Err(e) => println!("❌ Key rotation failed: {}", e),
    }

    // Test 7: Encrypt with rotated key
    println!("📝 Test 7: Encrypting with rotated key...");
    let new_encrypt_result = engine
        .create_secret("transit/encrypt/test-key", json!(encrypt_request), None)
        .await;

    match new_encrypt_result {
        Ok(data) => {
            if let Some(secret_data) = data.data.as_object() {
                if let Some(_new_ciphertext) =
                    secret_data.get("ciphertext").and_then(|v| v.as_str())
                {
                    println!("✅ Encryption with rotated key successful");

                    // Test that old ciphertext still decrypts
                    println!("📝 Test 7b: Verifying old ciphertext still decrypts...");
                    let old_decrypt_result = engine
                        .create_secret(
                            "transit/decrypt/test-key",
                            json!(DecryptRequest {
                                ciphertext: ciphertext,
                                context: None,
                                nonce: None,
                                associated_data: None,
                                batch_input: None,
                            }),
                            None,
                        )
                        .await;

                    match old_decrypt_result {
                        Ok(_) => println!("✅ Old ciphertext decryption successful"),
                        Err(e) => println!("❌ Old ciphertext decryption failed: {}", e),
                    }
                } else {
                    println!("❌ Failed to extract ciphertext from response");
                }
            } else {
                println!("❌ Invalid response format");
            }
        }
        Err(e) => println!("❌ Encryption with rotated key failed: {}", e),
    }

    println!("🎉 Transit Secrets Engine tests completed!");
    Ok(())
}
