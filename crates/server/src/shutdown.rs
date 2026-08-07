//! Graceful shutdown.

use tokio::signal;

/// Resolve on `Ctrl+C` or, on Unix, `SIGTERM`.
///
/// Returns rather than hanging if a handler cannot be installed: a process that ignores
/// SIGTERM because signal registration failed is killed by the orchestrator after the
/// grace period, which is strictly worse than shutting down immediately.
pub async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::warn!("failed to install Ctrl+C handler: {e}");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            }
            Err(e) => tracing::warn!("failed to install SIGTERM handler: {e}"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}
