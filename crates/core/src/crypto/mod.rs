pub mod pki;

pub use pki::{Certificate, PrivateKey, SignatureAlgorithm};

// Basic crypto functions needed by MFA
pub fn encrypt_data(
    data: &str,
    _key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Placeholder implementation - in production, use actual crypto
    Ok(format!("encrypted:{}", data))
}

pub fn decrypt_data(
    encrypted: &str,
    _key: &str,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Placeholder implementation - in production, use actual crypto
    if let Some(data) = encrypted.strip_prefix("encrypted:") {
        Ok(data.to_string())
    } else {
        Err("Invalid encrypted data format".into())
    }
}
