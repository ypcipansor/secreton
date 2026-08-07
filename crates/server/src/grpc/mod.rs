//! gRPC services, mounted into the same Axum router as everything else.
//!
//! `tonic` 0.14 builds its router on `axum` 0.8 and `hyper` 1, so `Routes` converts
//! straight into an `axum::Router` and merges. Under 0.12 that was impossible — it
//! depended on an older major version of axum, which is what forced gRPC onto a third
//! listener and pulled two versions of axum into the tree.
//!
//! Consequences of sharing the router: one port to expose in Kubernetes, one TLS
//! configuration, one NetworkPolicy, and the same tracing, request-id and rate-limit
//! layers over REST and gRPC alike. `axum::serve` uses hyper-util's auto builder, which
//! handles the HTTP/2 prior-knowledge upgrade a tonic client makes over `http://`, so
//! h2c and ordinary browser HTTP/1.1 coexist on the port.

pub mod server;

use axum::Router;
use secreton_engines::Services;

use crate::proto::secreton::v1::auth_service_server::AuthServiceServer;
use crate::proto::secreton::v1::secret_service_server::SecretServiceServer;
use crate::router::AppState;
use server::{GrpcAuthService, GrpcSecretService};

/// Descriptor set produced by the build script, used by the reflection service.
const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("secreton_descriptor");

/// Build the gRPC routes as an `axum::Router`.
///
/// Each service is mounted with `route_service` at its own gRPC path prefix rather than
/// by merging `Routes::into_axum_router()` wholesale. That matters: tonic's router carries
/// a catch-all fallback, and merging it made *every* unmatched path in the application —
/// a typo'd API route, a missing page — answer `200 OK` with an empty body instead of 404.
/// `route_service` passes the original URI through unchanged, which tonic requires, and
/// introduces no fallback.
pub fn routes(services: &Services) -> Router<AppState> {
    let secret = SecretServiceServer::new(GrpcSecretService::new(
        services.secret.clone(),
        services.auth.clone(),
    ));
    let auth = AuthServiceServer::new(GrpcAuthService::new(services.auth.clone()));

    // Health and reflection were both absent. Without health there is no gRPC probe for
    // Kubernetes; without reflection `grpcurl` cannot describe the service, so debugging
    // means carrying the .proto around.
    let (health_reporter, health_service) = tonic_health::server::health_reporter();
    // Detached: the reporter is only needed to flip a service to NOT_SERVING during
    // draining, which the graceful-shutdown path does not yet do.
    drop(health_reporter);

    let mut router = Router::new()
        .route_service("/secreton.v1.SecretService/{*method}", secret)
        .route_service("/secreton.v1.AuthService/{*method}", auth)
        .route_service("/grpc.health.v1.Health/{*method}", health_service);

    match tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()
    {
        Ok(reflection) => {
            router =
                router.route_service("/grpc.reflection.v1.ServerReflection/{*method}", reflection);
        }
        Err(e) => {
            tracing::warn!(error = %e, "gRPC reflection unavailable; grpcurl will need the .proto file");
        }
    }

    router
}
