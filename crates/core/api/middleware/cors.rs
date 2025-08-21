//! CORS middleware

use axum::{
    http::{header, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
};

/// Middleware to handle CORS
pub async fn cors_middleware<B>(
    request: axum::extract::Request,
    next: axum::middleware::Next<B>,
) -> Result<Response, StatusCode> {
    // Handle preflight requests
    if request.method() == Method::OPTIONS {
        let mut response = (StatusCode::NO_CONTENT).into_response();
        let headers = response.headers_mut();
        
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("*"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Content-Type, Authorization, X-Requested-With"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("86400"), // 24 hours
        );
        
        return Ok(response);
    }

    // Process the request
    let mut response = next.run(request).await;
    
    // Add CORS headers to the response
    let headers = response.headers_mut();
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    headers.insert(
        header::ACCESS_CONTROL_EXPOSE_HEADERS,
        HeaderValue::from_static("Content-Type, Authorization"),
    );
    
    Ok(response)
}
