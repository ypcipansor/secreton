//! Liveness, readiness and metrics.
//!
//! These are mounted outside the auth and seal layers. A liveness probe that requires a
//! bearer token is useless to Kubernetes, and a readiness probe that fails while sealed
//! would make the orchestrator restart a pod that is waiting, correctly, to be unsealed.

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use secreton_domain::ServiceHealth;
use secreton_engines::Services;
use serde::{Deserialize, Serialize};

/// Liveness: is the process running and able to answer?
///
/// Deliberately does no I/O. A liveness probe that touches the database restarts the pod
/// when the *database* is down, which turns one outage into two.
pub async fn liveness() -> impl IntoResponse {
    Json(LivenessResponse {
        status: "ok",
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LivenessResponse {
    pub status: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReadinessResponse {
    /// True when the process can serve requests.
    pub ready: bool,
    /// Sealed is reported but does not make the service unready — see below.
    pub sealed: bool,
    pub checks: Vec<Check>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub health: ServiceHealth,
}

/// Readiness: can this instance serve traffic?
///
/// Checks the dependencies it actually needs. Being sealed is reported but does **not**
/// make the instance unready: a sealed node is waiting for an operator to present unseal
/// keys, and removing it from the load balancer makes it unreachable for exactly the
/// request that would unseal it.
pub async fn readiness(State(services): State<Services>) -> impl IntoResponse {
    let storage = match services.storage.health_check().await {
        Ok(h) if h.is_healthy => ServiceHealth::Healthy,
        Ok(h) => ServiceHealth::Degraded(h.last_error.unwrap_or_else(|| "degraded".into())),
        Err(e) => ServiceHealth::Unhealthy(e.to_string()),
    };

    let checks = vec![Check {
        name: "storage".to_string(),
        health: storage.clone(),
    }];

    let ready = checks.iter().all(|c| c.health.is_serving());
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            ready,
            sealed: services.seal.is_sealed().await,
            checks,
        }),
    )
}

/// Prometheus exposition.
///
/// The previous implementation returned a hardcoded string with every counter at zero,
/// which is worse than no endpoint at all: a dashboard built on it looks healthy while
/// showing nothing real.
pub async fn metrics(State(services): State<Services>) -> impl IntoResponse {
    let sealed = u8::from(services.seal.is_sealed().await);
    let secrets = services
        .storage
        .count(&Default::default())
        .await
        .unwrap_or(0);
    let uptime = services.telemetry.uptime_seconds();

    let body = format!(
        "# HELP secreton_sealed Whether the barrier is sealed (1) or unsealed (0).\n\
         # TYPE secreton_sealed gauge\n\
         secreton_sealed {sealed}\n\
         # HELP secreton_secrets_total Number of secret entries in storage.\n\
         # TYPE secreton_secrets_total gauge\n\
         secreton_secrets_total {secrets}\n\
         # HELP secreton_uptime_seconds Seconds since the process started.\n\
         # TYPE secreton_uptime_seconds counter\n\
         secreton_uptime_seconds {uptime}\n"
    );

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn liveness_does_not_touch_any_dependency() {
        // No `Services` argument at all: the type system enforces that a liveness probe
        // cannot be made to depend on the database.
        let resp = liveness().await.into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
    }
}
