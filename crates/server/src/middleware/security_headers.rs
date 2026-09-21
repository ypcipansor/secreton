//! Response security headers.
//!
//! The application renders secrets in a browser, so the headers that constrain what the
//! page may load and where it may be embedded are part of the security boundary, not
//! decoration.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;

use secreton_domain::csp::csp_without_nonce;

pub async fn apply(request: Request, next: Next) -> Response {
    // Whether the client reached us over TLS. HSTS on a plain-HTTP response is ignored by
    // browsers anyway, and asserting it in local development breaks `http://localhost`
    // for a year in the developer's browser.
    let is_https = request
        .uri()
        .scheme_str()
        .map(|s| s == "https")
        .unwrap_or(false)
        || request
            .headers()
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.eq_ignore_ascii_case("https"))
            .unwrap_or(false);

    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    // A rendered document has already set a policy naming its nonce. Overwriting it here
    // would announce a value the scripts in that document do not carry — which is the
    // failure this whole path exists to avoid, so the existing header wins.
    if !headers.contains_key(CONTENT_SECURITY_POLICY) {
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_str(&csp_without_nonce()).expect("CSP is a valid header value"),
        );
    }

    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    headers.insert(
        "cross-origin-opener-policy",
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=(), payment=()"),
    );

    if is_https {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::{Router, middleware};
    use tower::ServiceExt;

    async fn response_for(header: Option<(&str, &str)>) -> Response {
        let app = Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(apply));
        let mut builder = Request::builder().uri("/");
        if let Some((k, v)) = header {
            builder = builder.header(k, v);
        }
        app.oneshot(builder.body(Body::empty()).unwrap())
            .await
            .expect("response")
    }

    #[tokio::test]
    async fn sets_the_headers_that_constrain_the_page() {
        let resp = response_for(None).await;
        let h = resp.headers();
        assert_eq!(h[X_CONTENT_TYPE_OPTIONS], "nosniff");
        assert_eq!(h[X_FRAME_OPTIONS], "DENY");
        assert_eq!(h[REFERRER_POLICY], "no-referrer");
        let csp = h[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("object-src 'none'"));
    }

    #[tokio::test]
    async fn csp_allows_wasm_but_not_arbitrary_inline_script() {
        let resp = response_for(None).await;
        let csp = resp.headers()[CONTENT_SECURITY_POLICY].to_str().unwrap();
        assert!(
            csp.contains("script-src 'self' 'wasm-unsafe-eval'"),
            "the Leptos WASM bundle needs wasm-unsafe-eval: {csp}"
        );
        assert!(
            !csp.contains("script-src 'self' 'unsafe-inline'"),
            "inline script must stay blocked: {csp}"
        );
    }

    #[tokio::test]
    async fn hsts_is_only_asserted_over_tls() {
        let plain = response_for(None).await;
        assert!(
            !plain.headers().contains_key(STRICT_TRANSPORT_SECURITY),
            "HSTS on plain HTTP would pin http://localhost in the developer's browser"
        );

        let tls = response_for(Some(("x-forwarded-proto", "https"))).await;
        assert!(tls.headers().contains_key(STRICT_TRANSPORT_SECURITY));
    }
}
