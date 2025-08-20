use anyhow::{Result, bail, Context};
use serde::Deserialize;
use std::fs;

pub trait AuthMethod {
    async fn login(&self) -> Result<String>; // return token
}

pub enum AuthConfig {
    Userpass { username: String, password: String },
    AppRole { role_id: String, secret_id: String },
    K8s { jwt_path: String, role: String },
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
    expires_in: Option<i64>,
}

pub async fn login_userpass(username: &str, password: &str, server_url: &str) -> Result<String> {
    let url = format!("{}/v1/auth/login", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({"username": username, "password": password}))
        .send()
        .await?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        bail!("Login userpass gagal: {}", err);
    }
    let login: LoginResponse = resp.json().await?;
    Ok(login.token)
}

pub async fn login_approle(role_id: &str, secret_id: &str, server_url: &str) -> Result<(String, Option<u64>)> {
    let url = format!("{}/v1/auth/approle/login", server_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({"role_id": role_id, "secret_id": secret_id}))
        .send()
        .await?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        bail!("Login approle gagal: {}", err);
    }
    let login: serde_json::Value = resp.json().await?;
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let expires_in = login.get("expires_in").and_then(|v| v.as_u64());
    Ok((token, expires_in))
}

pub async fn login_k8s(jwt_path: &str, role: &str, server_url: &str) -> Result<(String, Option<u64>)> {
    let url = format!("{}/v1/auth/k8s/login", server_url.trim_end_matches('/'));
    let jwt = fs::read_to_string(jwt_path).context("Gagal baca JWT service account K8s")?;
    let client = reqwest::Client::new();
    let resp = client.post(&url)
        .json(&serde_json::json!({"jwt": jwt, "role": role}))
        .send()
        .await?;
    if !resp.status().is_success() {
        let err = resp.text().await.unwrap_or_default();
        bail!("Login k8s gagal: {}", err);
    }
    let login: serde_json::Value = resp.json().await?;
    let token = login.get("token").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let expires_in = login.get("expires_in").and_then(|v| v.as_u64());
    Ok((token, expires_in))
} 