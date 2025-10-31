//! # Secreton Infrastructure Services
//!
//! System infrastructure components including API gateways, observability,
//! monitoring, plugin systems, and request forwarding services.

pub mod advanced_observability;
pub mod api_gateway;
pub mod connection_pooling;
pub mod distributed_tracing;
pub mod end_to_end_observability_pipeline;
pub mod events;
pub mod health;
pub mod log_streaming;
pub mod metrics;
pub mod monitoring;
pub mod namespaces;
pub mod performance_standby;
pub mod plugin_system;
pub mod request_forwarding;
pub mod rotation_scheduler;
pub mod webhooks;

// Re-export main types
pub use health::HealthService;
pub use metrics::MetricsRegistry;
pub use monitoring::MonitoringEngine;
pub use plugin_system::PluginSystem;
