use serde::{Deserialize, Serialize};
use thiserror::Error;
use gloo_storage::{LocalStorage, Storage};
use reqwest::{Client, Method, StatusCode};

const API_BASE_URL: &str = "/api/v1";

#[derive(Error, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApiError {
    #[error("Network error")]
    Network,
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Forbidden: {0}")]
    Forbidden(String),
    #[error("Not Found: {0}")]
    NotFound(String),
    #[error("Server Error: {0}")]
    ServerError(String),
    #[error("Client Error: {0}")]
    ClientError(String),
    #[error("Deserialization Error: {0}")]
    Deserialization(String),
    #[error("Unknown Error: {0}")]
    Unknown(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
    // timestamp field might be present but we can ignore it if we don't need it
    #[serde(default)]
    pub timestamp: Option<String>,
}

pub async fn request<T, B>(
    method: Method,
    path: &str,
    body: Option<B>,
) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
    B: Serialize,
{
    let client = Client::new();
    let url = format!("{}{}", API_BASE_URL, path);

    let mut builder = client.request(method, &url)
        .header("Content-Type", "application/json");

    if let Ok(token) = LocalStorage::get::<String>("secreton_token") {
        builder = builder.header("Authorization", format!("Bearer {}", token));
    }

    if let Some(b) = body {
        builder = builder.json(&b);
    }

    let response = builder.send().await.map_err(|_| ApiError::Network)?;
    let status = response.status();

    if status == StatusCode::UNAUTHORIZED {
        let _ = LocalStorage::delete("secreton_token");
        // We could dispatch a custom event here if we wanted to notify the app immediately
        return Err(ApiError::Unauthorized("Session expired".to_string()));
    }

    // Try to parse as ApiResponse first
    let text = response.text().await.map_err(|_| ApiError::Network)?;

    // Attempt to deserialize into ApiResponse<T>
    match serde_json::from_str::<ApiResponse<T>>(&text) {
        Ok(api_response) => {
            if api_response.success {
                // Return data if present, or try to deserialize T from Null if T allows it (e.g. Option)
                // If data is None but success is true, it might be a T=() case or T=Option<..>
                match api_response.data {
                    Some(data) => Ok(data),
                    None => {
                        // If T is (), return it. Hacky way to check?
                        // Actually, if T is deserializable from Null/None, we can try that.
                        // But usually we expect data.
                        serde_json::from_value(serde_json::Value::Null)
                            .map_err(|_| ApiError::ServerError("No data in successful response".to_string()))
                    }
                }
            } else {
                let msg = api_response.error.unwrap_or_else(|| "Unknown API error".to_string());
                match status {
                    s if s == StatusCode::FORBIDDEN => Err(ApiError::Forbidden(msg)),
                    s if s == StatusCode::NOT_FOUND => Err(ApiError::NotFound(msg)),
                    s if s.is_server_error() => Err(ApiError::ServerError(msg)),
                    _ => Err(ApiError::ClientError(msg)),
                }
            }
        },
        Err(_e) => {
            // Fallback: If parsing ApiResponse failed, maybe it's a raw error or legacy endpoint?
            // Or maybe the T structure didn't match.
            // Check if status implies error
            if !status.is_success() {
                 match status {
                    StatusCode::FORBIDDEN => Err(ApiError::Forbidden("Access denied".to_string())),
                    StatusCode::NOT_FOUND => Err(ApiError::NotFound("Resource not found".to_string())),
                    _ => Err(ApiError::ServerError(format!("Request failed with status {}: {}", status, text))),
                }
            } else {
                // It was success 200 OK but failed to parse ApiResponse wrapper.
                // Maybe it returned raw T?
                 serde_json::from_str::<T>(&text).map_err(|de| {
                    ApiError::Deserialization(format!("{} (Raw: {})", de, text))
                 })
            }
        }
    }
}

pub async fn get<T>(path: &str) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
{
    request(Method::GET, path, None::<()>).await
}

pub async fn post<T, B>(path: &str, body: B) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
    B: Serialize,
{
    request(Method::POST, path, Some(body)).await
}

pub async fn put<T, B>(path: &str, body: B) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
    B: Serialize,
{
    request(Method::PUT, path, Some(body)).await
}

pub async fn delete<T>(path: &str) -> Result<T, ApiError>
where
    T: for<'de> Deserialize<'de>,
{
    request(Method::DELETE, path, None::<()>).await
}
