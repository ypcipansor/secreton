use serde::{Deserialize, Serialize};
use thiserror::Error;
use gloo_storage::{LocalStorage, Storage};
use reqwest::{Client, Method, RequestBuilder};

const API_BASE_URL: &str = "/api/v1";

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum ApiError {
    #[error("Network error")]
    Network,
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Forbidden")]
    Forbidden,
    #[error("Not Found")]
    NotFound,
    #[error("Server Error: {0}")]
    ServerError(String),
    #[error("Client Error: {0}")]
    ClientError(String),
    #[error("Deserialization Error")]
    Deserialization,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
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

    if status.as_u16() == 401 {
        // Clear token on 401?
        let _ = LocalStorage::delete("secreton_token");
        return Err(ApiError::Unauthorized);
    }

    if status.as_u16() == 403 {
        return Err(ApiError::Forbidden);
    }

    let api_response: ApiResponse<T> = response.json().await.map_err(|_| ApiError::Deserialization)?;

    if api_response.success {
        api_response.data.ok_or_else(|| ApiError::ServerError("No data in successful response".to_string()))
    } else {
        let msg = api_response.error.unwrap_or_else(|| "Unknown error".to_string());
        if status.is_server_error() {
            Err(ApiError::ServerError(msg))
        } else {
            Err(ApiError::ClientError(msg))
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
