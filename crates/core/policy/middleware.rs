//! Axum middleware for policy-based access control

use axum::{
    body::HttpBody,
    extract::{FromRequest, RequestParts},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use std::{collections::HashMap, sync::Arc};

use super::*;
use crate::auth::Claims;

/// Extension trait for adding policy checks to requests
#[async_trait::async_trait]
pub trait PolicyExt {
    /// Check if the request is allowed by the policy
    async fn check_policy<B>(&mut self, action: &str, resource: &str) -> PolicyResult<()>
    where
        B: HttpBody + Send + 'static,
        B::Data: Send,
        B::Error: std::fmt::Display;
}

#[async_trait::async_trait]
impl<B> PolicyExt for Request<B>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: std::fmt::Display,
{
    async fn check_policy<B2>(&mut self, action: &str, resource: &str) -> PolicyResult<()>
    where
        B2: HttpBody + Send + 'static,
        B2::Data: Send,
        B2::Error: std::fmt::Display,
    {
        let (mut parts, _) = self.into_parts();
        let policy_engine = parts
            .extensions()
            .get::<Arc<PolicyEngine>>()
            .ok_or_else(|| PolicyError::Other(anyhow::anyhow!("Policy engine not found")))?;

        let claims = Claims::from_request(&mut parts)
            .await
            .map_err(|_| PolicyError::PermissionDenied)?;

        let subject = Subject::new(claims.sub)
            .with_role(claims.role);

        let context = parts
            .extensions()
            .get::<HashMap<String, String>>()
            .cloned()
            .unwrap_or_default();

        if !policy_engine.is_allowed(&subject, action, resource, &context) {
            return Err(PolicyError::PermissionDenied);
        }

        *self = Request::from_parts(parts, self.body());
        Ok(())
    }
}

/// Middleware for policy-based access control
pub async fn policy_middleware<B>(
    mut request: Request<B>,
    next: Next<B>,
    action: &'static str,
    resource: &'static str,
) -> Result<Response, impl IntoResponse>
where
    B: HttpBody + Send + 'static,
    B::Data: Send,
    B::Error: std::fmt::Display,
{
    if let Err(err) = request.check_policy::<B>(action, resource).await {
        return Err((
            StatusCode::FORBIDDEN,
            format!("Access denied: {}", err),
        ));
    }

    Ok(next.run(request).await)
}

/// Macro for creating policy-protected routes
#[macro_export]
macro_rules! policy_route {
    ($router:expr, $method:ident, $path:expr, $handler:expr, $action:expr, $resource:expr) => {
        $router.route(
            $path,
            axum::routing::method_matching::MethodFilter::$method
                .guard(&axum::routing::on(move |request| async move {
                    policy_middleware(request, $handler, $action, $resource).await
                })),
        )
    };
}
