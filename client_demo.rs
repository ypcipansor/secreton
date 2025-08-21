//! Brankas API Client Example
//!
//! Demonstrates how to interact with the Brankas Transit Engine API
//! including key management, encryption/decryption, and batch operations.

use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use tokio;
use tracing::{info, error};

const API_BASE_URL: &str = "http://127.0.0.1:8200";
const JWT_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwibmFtZSI6IlRlc3QgVXNlciIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsInJvbGVzIjpbImNyeXB0by11c2VyIl0sInBlcm1pc3Npb25zIjpbImVuY3J5cHQiLCJkZWNyeXB0IiwiY3JlYXRlLWtleSJdLCJleHAiOjk5OTk5OTk5OTksImlhdCI6MTYwMDAwMDAwMCwiaXNzIjoiYnJhbmthcy12YXVsdCIsImF1ZCI6ImJyYW5rYXMtYXBpIiwianRpIjoidGVzdC1qd3QtaWQifQ.test-signature";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::init();
    
    info!("🚀 Starting Brankas API Client Demo");
    
    let client = Client::new();
    
    // Test health endpoint
    test_health_check(&client).await?;
    
    // Test version endpoint
    test_version_info(&client).await?;
    
    // Test key management
    test_key_management(&client).await?;
    
    // Test encryption/decryption
    test_encryption_operations(&client).await?;
    
    // Test batch operations
    test_batch_operations(&client).await?;
    
    // Test random generation
    test_random_generation(&client).await?;
    
    info!("✅ All API tests completed successfully!");
    
    Ok(())
}

async fn test_health_check(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Health Check ===");
    
    let response = client
        .get(&format!("{}/health", API_BASE_URL))
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("Health check status: {}", status);
    info!("Health check response: {}", serde_json::to_string_pretty(&body)?);
    
    Ok(())
}

async fn test_version_info(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Version Info ===");
    
    let response = client
        .get(&format!("{}/version", API_BASE_URL))
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("Version info status: {}", status);
    info!("Version info response: {}", serde_json::to_string_pretty(&body)?);
    
    Ok(())
}

async fn test_key_management(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Key Management ===");
    
    // Create AES key
    let create_key_request = json!({
        "key_type": "aes256-gcm",
        "exportable": false,
        "usage": ["encrypt", "decrypt"]
    });
    
    let response = client
        .post(&format!("{}/v1/transit/keys/test-aes-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&create_key_request)
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("Create AES key status: {}", status);
    info!("Create AES key response: {}", serde_json::to_string_pretty(&body)?);
    
    // Create ChaCha20 key
    let create_chacha_request = json!({
        "key_type": "chacha20-poly1305",
        "exportable": false
    });
    
    let response = client
        .post(&format!("{}/v1/transit/keys/test-chacha-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&create_chacha_request)
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("Create ChaCha20 key status: {}", status);
    info!("Create ChaCha20 key response: {}", serde_json::to_string_pretty(&body)?);
    
    // List keys
    let response = client
        .get(&format!("{}/v1/transit/keys", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("List keys status: {}", status);
    info!("List keys response: {}", serde_json::to_string_pretty(&body)?);
    
    // Get key info
    let response = client
        .get(&format!("{}/v1/transit/keys/test-aes-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .send()
        .await?;
    
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    
    info!("Get key info status: {}", status);
    info!("Get key info response: {}", serde_json::to_string_pretty(&body)?);
    
    Ok(())
}

async fn test_encryption_operations(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Encryption Operations ===");
    
    let plaintext = "This is sensitive data that needs to be encrypted!";
    let plaintext_b64 = base64::encode(plaintext.as_bytes());
    
    // Encrypt with AES
    let encrypt_request = json!({
        "plaintext": plaintext_b64,
        "encoding": "base64"
    });
    
    let response = client
        .post(&format!("{}/v1/transit/encrypt/test-aes-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&encrypt_request)
        .send()
        .await?;
    
    let status = response.status();
    let encrypt_body: serde_json::Value = response.json().await?;
    
    info!("AES encrypt status: {}", status);
    info!("AES encrypt response: {}", serde_json::to_string_pretty(&encrypt_body)?);
    
    // Extract ciphertext for decryption test
    let ciphertext = encrypt_body["ciphertext"].as_str().unwrap();
    
    // Decrypt with AES
    let decrypt_request = json!({
        "ciphertext": ciphertext,
        "encoding": "base64"
    });
    
    let response = client
        .post(&format!("{}/v1/transit/decrypt/test-aes-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&decrypt_request)
        .send()
        .await?;
    
    let status = response.status();
    let decrypt_body: serde_json::Value = response.json().await?;
    
    info!("AES decrypt status: {}", status);
    info!("AES decrypt response: {}", serde_json::to_string_pretty(&decrypt_body)?);
    
    // Verify decrypted data
    let decrypted_b64 = decrypt_body["plaintext"].as_str().unwrap();
    let decrypted_bytes = base64::decode(decrypted_b64)?;
    let decrypted_text = String::from_utf8(decrypted_bytes)?;
    
    if decrypted_text == plaintext {
        info!("✅ Encryption/decryption roundtrip successful!");
    } else {
        error!("❌ Encryption/decryption roundtrip failed!");
        error!("  Expected: {}", plaintext);
        error!("  Got: {}", decrypted_text);
    }
    
    // Test with ChaCha20
    let response = client
        .post(&format!("{}/v1/transit/encrypt/test-chacha-key", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&encrypt_request)
        .send()
        .await?;
    
    let status = response.status();
    let chacha_encrypt_body: serde_json::Value = response.json().await?;
    
    info!("ChaCha20 encrypt status: {}", status);
    info!("ChaCha20 encrypt response: {}", serde_json::to_string_pretty(&chacha_encrypt_body)?);
    
    Ok(())
}

async fn test_batch_operations(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Batch Operations ===");
    
    // Prepare batch encrypt request
    let batch_items = vec![
        json!({
            "key_name": "test-aes-key",
            "plaintext": base64::encode("Batch item 1"),
            "encoding": "base64"
        }),
        json!({
            "key_name": "test-chacha-key", 
            "plaintext": base64::encode("Batch item 2"),
            "encoding": "base64"
        }),
        json!({
            "key_name": "test-aes-key",
            "plaintext": base64::encode("Batch item 3"),
            "encoding": "base64"
        }),
    ];
    
    let batch_encrypt_request = json!({
        "batch_input": batch_items
    });
    
    let response = client
        .post(&format!("{}/v1/transit/encrypt", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&batch_encrypt_request)
        .send()
        .await?;
    
    let status = response.status();
    let batch_encrypt_body: serde_json::Value = response.json().await?;
    
    info!("Batch encrypt status: {}", status);
    info!("Batch encrypt response: {}", serde_json::to_string_pretty(&batch_encrypt_body)?);
    
    // Extract ciphertexts for batch decryption
    let batch_results = &batch_encrypt_body["batch_results"];
    let mut decrypt_items = Vec::new();
    
    for (i, result) in batch_results.as_array().unwrap().iter().enumerate() {
        if let Some(ciphertext) = result["ciphertext"].as_str() {
            let key_name = if i == 1 { "test-chacha-key" } else { "test-aes-key" };
            decrypt_items.push(json!({
                "key_name": key_name,
                "ciphertext": ciphertext,
                "encoding": "base64"
            }));
        }
    }
    
    let batch_decrypt_request = json!({
        "batch_input": decrypt_items
    });
    
    let response = client
        .post(&format!("{}/v1/transit/decrypt", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&batch_decrypt_request)
        .send()
        .await?;
    
    let status = response.status();
    let batch_decrypt_body: serde_json::Value = response.json().await?;
    
    info!("Batch decrypt status: {}", status);
    info!("Batch decrypt response: {}", serde_json::to_string_pretty(&batch_decrypt_body)?);
    
    Ok(())
}

async fn test_random_generation(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    info!("=== Testing Random Generation ===");
    
    let random_request = json!({
        "encoding": "base64"
    });
    
    // Generate 32 bytes of random data
    let response = client
        .post(&format!("{}/v1/transit/random/32", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&random_request)
        .send()
        .await?;
    
    let status = response.status();
    let random_body: serde_json::Value = response.json().await?;
    
    info!("Random generation (32 bytes) status: {}", status);
    info!("Random generation response: {}", serde_json::to_string_pretty(&random_body)?);
    
    // Generate hex-encoded random data
    let hex_request = json!({
        "encoding": "hex"
    });
    
    let response = client
        .post(&format!("{}/v1/transit/random/16", API_BASE_URL))
        .header("Authorization", format!("Bearer {}", JWT_TOKEN))
        .header("Content-Type", "application/json")
        .json(&hex_request)
        .send()
        .await?;
    
    let status = response.status();
    let hex_random_body: serde_json::Value = response.json().await?;
    
    info!("Random generation (16 bytes, hex) status: {}", status);
    info!("Random generation (hex) response: {}", serde_json::to_string_pretty(&hex_random_body)?);
    
    Ok(())
}
