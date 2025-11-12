//! Axum middleware for audit logging

use axum::{
    body::{Body, HttpBody},
    http::Request,
    middleware::Next,
    response::Response,
};
use std::{collections::HashMap, time::Instant};
use uuid::Uuid;

// Placeholder Claims struct for audit logging (contains minimal user identity info)
#[derive(Debug, Clone)]
pub struct Claims {
    pub sub: String,
}

use super::*;

/// Extension trait for adding audit logging to requests
#[async_trait::async_trait]
pub trait AuditExt {
    /// Log an audit event for this request
    async fn audit_log(
        &self,
        action: impl Into<String> + Send,
        resource_type: impl Into<String> + Send,
        resource_id: impl Into<String> + Send,
        status: AuditStatus,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<(), AuditError>;
}

#[async_trait::async_trait]
impl<B> AuditExt for Request<B>
where
    B: Send + Sync + 'static,
{
    async fn audit_log(
        &self,
        action: impl Into<String> + Send,
        resource_type: impl Into<String> + Send,
        resource_id: impl Into<String> + Send,
        status: AuditStatus,
        metadata: Option<HashMap<String, String>>,
    ) -> Result<(), AuditError> {
        let extensions = self.extensions();
        let logger = extensions.get::<AuditLogger>().ok_or_else(|| {
            AuditError::LoggingError("AuditLogger not found in request extensions".into())
        })?;

        let request_id = extensions
            .get::<String>()
            .cloned()
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let claims = extensions.get::<Claims>();

        let mut metadata = metadata.unwrap_or_default();
        metadata.insert("request_id".into(), request_id);

        let entry = AuditLog {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            action: action.into(),
            actor: claims.map(|c| c.sub.clone()),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            status,
            ip: self
                .headers()
                .get("x-forwarded-for")
                .or_else(|| self.headers().get("x-real-ip"))
                .and_then(|h| h.to_str().ok())
                .map(|s| s.split(',').next().unwrap_or(s).trim().to_string()),
            user_agent: self
                .headers()
                .get("user-agent")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            metadata,
        };

        logger.log(entry).await
    }
}

/// Middleware for request logging
pub async fn audit_middleware(
    request: Request<Body>,
    next: Next,
) -> Result<Response, std::convert::Infallible> {
    let start = Instant::now();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    let response = next.run(request).await;

    let duration = start.elapsed();
    let status = response.status();

    // Log the request
    if let Some(logger) = response.extensions().get::<AuditLogger>() {
        let status_code = status.as_u16();
        let success = status_code < 400;
        let status = if status_code >= 500 {
            AuditStatus::Failure
        } else if status_code >= 400 {
            AuditStatus::Denied
        } else {
            AuditStatus::Success
        };

        let mut metadata = HashMap::new();
        metadata.insert("method".into(), method.to_string());
        metadata.insert("path".into(), path.clone());
        metadata.insert("status".into(), status_code.to_string());
        metadata.insert("duration_ms".into(), duration.as_millis().to_string());

        // Try to extract error details
        if !success {
            if let Some(body) = response.body().size_hint().exact() {
                // If we can get the body size, we could log it
                metadata.insert("response_size".into(), body.to_string());
            }
        }

        // Log the request
        let _ = logger
            .log(AuditLog {
                id: Uuid::new_v4(),
                timestamp: Utc::now(),
                action: format!("http_{}", method).to_lowercase(),
                actor: None, // Will be set by the auth middleware if available
                resource_type: "http_request".into(),
                resource_id: path,
                status,
                ip: None,         // Will be set by the AuditExt
                user_agent: None, // Will be set by the AuditExt
                metadata,
            })
            .await;
    }

    Ok(response)
}
