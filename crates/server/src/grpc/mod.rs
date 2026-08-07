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
const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("secreton_descriptor");

/// Build the gRPC routes as an `axum::Router`.
pub fn routes(services: &Services) -> Router<AppState> {
    let secret = SecretServiceServer::new(GrpcSecretService::new(
        services.secret.clone(),
        services.auth.clone(),
    ));
    let auth = AuthServiceServer::new(GrpcAuthService::new(services.auth.clone()));

    // Health and reflection were both missing. Without health there is no gRPC probe for
    // Kubernetes; without reflection `grpcurl` cannot describe the service, so debugging
    // means carrying the .proto around.
    let mut health_reporter = tonic_health::server::HealthReporter::default();
    health_reporter.set_serving::<SecretServiceServer<GrpcSecretService>>();
    health_reporter.set_serving::<AuthServiceServer<GrpcAuthService>>();

    let reflection = tonic_reflection::server::Builder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1();

    let mut routes = tonic::service::Routes::default();
    routes = routes.add_service(secret).add_service(auth);
    routes = routes.add_service(tonic_health::server::health_reporter().1);
    if let Ok(reflection) = reflection {
        routes = routes.add_service(reflection);
    } else {
        tracing::warn!("gRPC reflection unavailable; grpcurl will need the .proto file");
    }

    // `Routes::into_axum_router()` yields a `Router<()>`; the outer router is
    // `Router<AppState>`, and a stateless sub-router merges into a stateful one.
    routes.into_axum_router().with_state(())
}
