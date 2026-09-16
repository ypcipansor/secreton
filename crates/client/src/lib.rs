//! # Secreton Client
//!
//! A typed HTTP client for the Secreton REST API, shared by the CLI, the agent and the
//! end-to-end tests.
//!
//! Request and response types come from `secreton-domain`, the same crate the server uses,
//! so a change to a payload breaks compilation here rather than producing a runtime
//! deserialisation error in production. The previous CLI and agent each hand-rolled their
//! own `reqwest` calls and their own copies of the payload structs.

#![forbid(unsafe_code)]

use std::time::Duration;

use secreton_domain::{ApiResponse, SecretonError};
use serde::Serialize;
use serde::de::DeserializeOwned;

pub mod secrets;

/// Errors a client call can fail with.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("could not reach {url}: {source}")]
    Transport {
        url: String,
        #[source]
        source: reqwest::Error,
    },

    /// The server answered, and said no.
    #[error("{status}: {message}")]
    Api {
        status: reqwest::StatusCode,
        message: String,
    },

    #[error("could not decode the response: {0}")]
    Decode(String),

    #[error("not authenticated: call `login` or set a token first")]
    NotAuthenticated,
}

impl ClientError {
    /// Whether retrying the same request could plausibly succeed.
    ///
    /// Transport failures and 5xx are retryable; 4xx are not — retrying a rejected
    /// credential or a malformed body just burns the rate limit.
    pub fn is_retryable(&self) -> bool {
        match self {
            ClientError::Transport { .. } => true,
            ClientError::Api { status, .. } => status.is_server_error(),
            _ => false,
        }
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Client for one Secreton server.
#[derive(Debug, Clone)]
pub struct Client {
    http: reqwest::Client,
    base_url: url::Url,
    token: Option<String>,
}

impl Client {
    /// Build a client for `base_url`, e.g. `https://secreton.internal`.
    pub fn new(base_url: &str) -> Result<Self> {
        let base_url = normalise(base_url)?;
        let http = reqwest::Client::builder()
            // A secrets client that hangs forever on a wedged server is worse than one
            // that fails: the agent would stop renewing leases without saying why.
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .user_agent(concat!("secreton-client/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|source| ClientError::Transport {
                url: base_url.to_string(),
                source,
            })?;

        Ok(Self {
            http,
            base_url,
            token: None,
        })
    }

    /// Attach a bearer token to subsequent requests.
    pub fn with_token(mut self, token: impl Into<String>) -> Self {
        self.token = Some(token.into());
        self
    }

    pub fn is_authenticated(&self) -> bool {
        self.token.is_some()
    }

    pub fn base_url(&self) -> &url::Url {
        &self.base_url
    }

    pub(crate) async fn request<T, B>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<T>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .map_err(|e| ClientError::Decode(format!("invalid path {path}: {e}")))?;

        let mut req = self.http.request(method, url.clone());
        if let Some(token) = &self.token {
            req = req.bearer_auth(token);
        }
        if let Some(body) = body {
            req = req.json(body);
        }

        let response = req.send().await.map_err(|source| ClientError::Transport {
            url: url.to_string(),
            source,
        })?;

        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|source| ClientError::Transport {
                url: url.to_string(),
                source,
            })?;

        // One envelope, parsed once. The old UI client tried `ApiResponse<T>` and then
        // fell back to bare `T`, because the warp and Axum halves of the API disagreed
        // about the shape. There is one server now, and one shape.
        let envelope: ApiResponse<T> = serde_json::from_str(&text).map_err(|e| {
            if status.is_success() {
                ClientError::Decode(format!("{e}; body was: {}", truncate(&text)))
            } else {
                ClientError::Api {
                    status,
                    message: truncate(&text),
                }
            }
        })?;

        if !status.is_success() || !envelope.success {
            return Err(ClientError::Api {
                status,
                message: envelope
                    .error
                    .unwrap_or_else(|| format!("request failed with {status}")),
            });
        }

        envelope
            .data
            .ok_or_else(|| ClientError::Decode("successful response carried no data".into()))
    }

    pub(crate) async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request::<T, ()>(reqwest::Method::GET, path, None)
            .await
    }

    pub(crate) async fn post<T: DeserializeOwned, B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T> {
        self.request(reqwest::Method::POST, path, Some(body)).await
    }

    pub(crate) async fn delete<T: DeserializeOwned>(&self, path: &str) -> Result<T> {
        self.request::<T, ()>(reqwest::Method::DELETE, path, None)
            .await
    }
}

/// Normalise a base URL so `join` behaves.
///
/// `Url::join` replaces the last path segment unless the base ends in `/`, so
/// `http://host/api/v1` + `secret/x` would silently become `http://host/api/secret/x`.
fn normalise(base: &str) -> Result<url::Url> {
    let mut s = base.trim().to_string();
    if !s.ends_with('/') {
        s.push('/');
    }
    let url = url::Url::parse(&s)
        .map_err(|e| ClientError::Decode(format!("invalid base url {base}: {e}")))?;
    Ok(url)
}

/// Cap an error body so a hostile or enormous response cannot flood a terminal or a log.
fn truncate(s: &str) -> String {
    const MAX: usize = 512;
    if s.len() <= MAX {
        return s.to_string();
    }
    let cut = s
        .char_indices()
        .map(|(i, _)| i)
        .take_while(|i| *i <= MAX)
        .last()
        .unwrap_or(0);
    format!("{}… ({} bytes total)", &s[..cut], s.len())
}

impl From<ClientError> for SecretonError {
    fn from(e: ClientError) -> Self {
        match e {
            ClientError::Transport { url, .. } => SecretonError::Network {
                message: format!("could not reach {url}"),
            },
            ClientError::Api { message, .. } => SecretonError::Internal { message },
            ClientError::Decode(message) => SecretonError::Parse { message },
            ClientError::NotAuthenticated => SecretonError::MissingAuthHeader,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_url_without_a_trailing_slash_still_joins_correctly() {
        // Without normalisation `join` replaces the last segment, so this would resolve
        // to /api/secret/kv/app and every request would 404.
        let client = Client::new("http://localhost:3000/api/v1").expect("client");
        let joined = client.base_url().join("secret/kv/app").expect("join");
        assert_eq!(
            joined.as_str(),
            "http://localhost:3000/api/v1/secret/kv/app"
        );
    }

    #[test]
    fn a_base_url_with_a_trailing_slash_is_unchanged() {
        let client = Client::new("http://localhost:3000/api/v1/").expect("client");
        assert_eq!(client.base_url().as_str(), "http://localhost:3000/api/v1/");
    }

    #[test]
    fn an_invalid_base_url_is_rejected_at_construction() {
        assert!(Client::new("not a url").is_err());
    }

    #[test]
    fn only_transport_and_server_errors_are_retryable() {
        assert!(
            ClientError::Api {
                status: reqwest::StatusCode::BAD_GATEWAY,
                message: String::new()
            }
            .is_retryable()
        );
        assert!(
            !ClientError::Api {
                status: reqwest::StatusCode::UNAUTHORIZED,
                message: String::new()
            }
            .is_retryable(),
            "retrying a rejected credential just burns the rate limit"
        );
        assert!(!ClientError::NotAuthenticated.is_retryable());
    }

    #[test]
    fn oversized_error_bodies_are_truncated() {
        let out = truncate(&"x".repeat(10_000));
        assert!(out.len() < 600, "an error body must not flood a terminal");
        assert!(out.contains("10000 bytes total"));
    }

    #[test]
    fn a_token_is_only_present_once_set() {
        let client = Client::new("http://localhost:3000/api/v1").unwrap();
        assert!(!client.is_authenticated());
        assert!(client.with_token("t").is_authenticated());
    }
}
