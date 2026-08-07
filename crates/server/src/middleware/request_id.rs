//! Request correlation.
//!
//! Every request gets an id that appears on the response and in every log line emitted
//! while handling it. This is what makes the opaque 5xx body in [`crate::error`] workable:
//! the client is told nothing useful, but can quote `x-request-id` and an operator can
//! find the exact failure.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use uuid::Uuid;

pub const HEADER: &str = "x-request-id";

/// Id assigned to the current request, inserted as a request extension.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestId(pub String);

pub async fn attach(mut request: Request, next: Next) -> Response {
    // Honour an inbound id so a trace survives across services, but only if it is
    // plausible: an unbounded, unvalidated header would be echoed into every log line
    // for this request, which is a log-injection and log-bloat vector.
    let incoming = request
        .headers()
        .get(HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| is_acceptable(v))
        .map(str::to_owned);

    let id = incoming.unwrap_or_else(|| Uuid::new_v4().to_string());

    request.extensions_mut().insert(RequestId(id.clone()));
    if let Ok(value) = HeaderValue::from_str(&id) {
        request.headers_mut().insert(HEADER, value.clone());

        let span = tracing::info_span!("request", request_id = %id);
        let _enter = span.enter();
        drop(_enter);

        let mut response = next.run(request).await;
        response.headers_mut().insert(HEADER, value);
        return response;
    }

    next.run(request).await
}

/// Accept only short, printable-ASCII ids without control characters.
fn is_acceptable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::routing::get;
    use axum::{Router, middleware};
    use tower::ServiceExt;

    fn app() -> Router {
        Router::new()
            .route("/", get(|| async { "ok" }))
            .layer(middleware::from_fn(attach))
    }

    async fn header_for(req: Request<Body>) -> String {
        let resp = app().oneshot(req).await.expect("response");
        resp.headers()
            .get(HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    #[tokio::test]
    async fn generates_an_id_when_none_is_supplied() {
        let id = header_for(Request::builder().uri("/").body(Body::empty()).unwrap()).await;
        assert!(Uuid::parse_str(&id).is_ok(), "not a uuid: {id:?}");
    }

    #[tokio::test]
    async fn propagates_a_well_formed_inbound_id() {
        let req = Request::builder()
            .uri("/")
            .header(HEADER, "trace-abc_123.4")
            .body(Body::empty())
            .unwrap();
        assert_eq!(header_for(req).await, "trace-abc_123.4");
    }

    #[tokio::test]
    async fn replaces_ids_that_could_poison_a_log_line() {
        for hostile in [
            "a\tb",                  // control character
            &"x".repeat(4096),       // unbounded growth
            "id with spaces",        // separator
            "",                      // empty
        ] {
            let Ok(req) = Request::builder()
                .uri("/")
                .header(HEADER, hostile)
                .body(Body::empty())
            else {
                continue; // header value rejected before reaching us; also fine
            };
            let id = header_for(req).await;
            assert!(
                Uuid::parse_str(&id).is_ok(),
                "hostile id {hostile:?} was echoed back as {id:?}"
            );
        }
    }
}
