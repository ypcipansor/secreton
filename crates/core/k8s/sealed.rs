use axum::{Json, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SealedSecretRequest {
    pub plaintext: String,
    pub public_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SealedSecretResponse {
    pub encrypted: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsealSecretRequest {
    pub encrypted: String,
    pub private_key: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct UnsealSecretResponse {
    pub plaintext: String,
}

// Dummy: base64 public key encryption (bukan RSA asli)
pub async fn encrypt_sealed_secret(Json(req): Json<SealedSecretRequest>) -> impl IntoResponse {
    // TODO: Ganti dengan RSA asli, sekarang hanya base64 encode
    let encrypted = base64::encode(format!("{}:{}", req.public_key, req.plaintext));
    Json(SealedSecretResponse { encrypted })
}

pub async fn decrypt_sealed_secret(Json(req): Json<UnsealSecretRequest>) -> impl IntoResponse {
    // TODO: Ganti dengan RSA asli, sekarang hanya base64 decode
    let decoded = base64::decode(&req.encrypted).ok().and_then(|v| String::from_utf8(v).ok()).unwrap_or_default();
    let parts: Vec<&str> = decoded.splitn(2, ':').collect();
    let plaintext = if parts.len() == 2 { parts[1].to_string() } else { "".to_string() };
    Json(UnsealSecretResponse { plaintext })
} 