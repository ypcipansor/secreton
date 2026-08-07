//! The single Axum router.
//!
//! Everything the process serves is assembled here: the Leptos application and its server
//! functions, the REST API under `/api/v1`, static assets, health and metrics, and — when
//! the `grpc` feature is on — the gRPC services. One router means one listener, one TLS
//! configuration, one middleware stack and one port to expose in Kubernetes.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::FromRef;
use axum::routing::get;
use axum::{Router, middleware as axum_middleware};
use leptos::prelude::*;
use leptos_axum::{LeptosRoutes, generate_route_list};
use secreton_engines::Services;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;
use tower_http::trace::TraceLayer;

use crate::handlers;
use crate::middleware;

/// State shared by every handler and server function.
///
/// `Services` is a typed struct, so a handler that asks for the wrong service does not
/// compile. This replaces the previous string-keyed `Box<dyn Any>` registry, where the
/// same mistake surfaced as a runtime `None` — or worse, as the wrong service downcast
/// successfully.
#[derive(Clone, Debug)]
pub struct AppState {
    pub services: Services,
    pub leptos_options: LeptosOptions,
}

impl FromRef<AppState> for LeptosOptions {
    fn from_ref(state: &AppState) -> Self {
        state.leptos_options.clone()
    }
}

impl FromRef<AppState> for Services {
    fn from_ref(state: &AppState) -> Self {
        state.services.clone()
    }
}

/// Build the complete application router.
pub fn build_router(state: AppState) -> Router {
    let cfg = Arc::clone(&state.services.config);
    let leptos_options = state.leptos_options.clone();
    let routes = generate_route_list(secreton_ui::App);

    // Routes that must answer before authentication: a liveness probe that requires a
    // token is useless to Kubernetes, and a login endpoint that requires a session is a
    // deadlock.
    let public = Router::new()
        .route("/health", get(handlers::health::liveness))
        .route("/health/ready", get(handlers::health::readiness))
        .route("/metrics", get(handlers::health::metrics))
        .nest("/api/v1/auth", handlers::auth::public_routes())
        .route(
            "/api-docs/openapi.json",
            get(crate::openapi::openapi_document),
        );

    let api = Router::new()
        .nest("/secret", handlers::secret::routes())
        .nest("/database", handlers::database::routes())
        .nest("/pki", handlers::pki::routes())
        .nest("/ssh", handlers::ssh::routes())
        .nest("/totp", handlers::totp_engine::routes())
        .nest("/transit", handlers::transit::routes())
        .nest("/lifecycle", handlers::lifecycle::routes())
        .nest("/admin", handlers::admin::routes())
        .nest("/sys", handlers::sys::routes())
        .nest("/auth", handlers::auth::authenticated_routes())
        // `route_layer` applies only to matched routes, so an unknown path under
        // /api/v1 returns 404 rather than 401 — a 401 there tells an unauthenticated
        // caller which paths exist.
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::auth::require_authentication,
        ))
        .route_layer(axum_middleware::from_fn_with_state(
            state.clone(),
            middleware::seal::reject_when_sealed,
        ));

    let leptos = Router::new()
        .leptos_routes(&state, routes, {
            let opts = leptos_options.clone();
            move || shell(opts.clone())
        })
        .fallback(leptos_axum::file_and_error_handler::<AppState, _>(shell));

    let app = Router::new()
        .merge(public)
        .nest("/api/v1", api)
        .merge(leptos);

    #[cfg(feature = "grpc")]
    let app = app.merge(crate::grpc::routes(&state.services));

    app.layer(
        ServiceBuilder::new()
            // Outermost: every request gets an id, and it is on the response and in
            // every log line for that request.
            .layer(axum_middleware::from_fn(middleware::request_id::attach))
            .layer(TraceLayer::new_for_http())
            .layer(axum_middleware::from_fn(
                middleware::security_headers::apply,
            ))
            .layer(cors_layer(&cfg))
            .layer(TimeoutLayer::new(Duration::from_secs(cfg.http.timeout)))
            .layer(RequestBodyLimitLayer::new(cfg.http.max_body_size))
            .layer(CompressionLayer::new()),
    )
    .with_state(state)
}

/// The HTML shell Leptos hydrates into.
fn shell(options: LeptosOptions) -> impl IntoView {
    use leptos::prelude::*;
    use leptos_meta::MetaTags;

    view! {
        <!DOCTYPE html>
        <html lang="en">
            <head>
                <meta charset="utf-8"/>
                <meta name="viewport" content="width=device-width, initial-scale=1"/>
                // Tailwind is compiled locally by cargo-leptos into this stylesheet.
                // It used to be pulled from cdn.tailwindcss.com at runtime, which is a
                // dev-only build and an uncontrolled third-party script in a page that
                // renders secrets.
                <AutoReload options=options.clone()/>
                <HydrationScripts options islands=true/>
                <MetaTags/>
            </head>
            <body>
                <App/>
            </body>
        </html>
    }
}

use secreton_ui::App;

/// CORS policy.
///
/// The previous router used `allow_origin(Any).allow_methods(Any).allow_headers(Any)` on a
/// secrets manager, which lets any site on the internet script the API with the caller's
/// credentials. Origins are now an explicit allowlist, and an empty list means same-origin
/// only — which is the correct default now that the UI is served by this same process.
fn cors_layer(cfg: &secreton_engines::ServerConfig) -> CorsLayer {
    use axum::http::{HeaderName, HeaderValue, Method};

    if cfg.cors.allowed_origins.is_empty() {
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = cfg
        .cors
        .allowed_origins
        .iter()
        .filter_map(|o| match o.parse::<HeaderValue>() {
            Ok(v) => Some(v),
            Err(_) => {
                tracing::warn!(origin = %o, "ignoring unparseable CORS origin");
                None
            }
        })
        .collect();

    let methods: Vec<Method> = cfg
        .cors
        .allowed_methods
        .iter()
        .filter_map(|m| m.parse::<Method>().ok())
        .collect();

    let headers: Vec<HeaderName> = cfg
        .cors
        .allowed_headers
        .iter()
        .filter_map(|h| h.parse::<HeaderName>().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods(methods)
        .allow_headers(headers)
        // Session cookies only travel cross-origin when this is on, and it is only sound
        // because the origin list above is explicit — `Any` plus credentials is rejected
        // by browsers and by tower-http.
        .allow_credentials(true)
}
