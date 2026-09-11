//! # Secreton Server
//!
//! The transport layer: one Axum router that serves the Leptos application, the REST API
//! under `/api/v1`, and — with the `grpc` feature — gRPC, all on a single listener.
//!
//! Before this refactor the process ran two HTTP stacks side by side: warp on the
//! configured port and Axum on that port plus ten, because warp is built on hyper 0.14 and
//! Axum on hyper 1.0. That forced two TLS configurations, two sets of middleware, a
//! hardcoded port offset duplicated into the frontend's proxy config, and pulled two major
//! versions of Axum into the dependency tree. There is now one router and one listener.

#![forbid(unsafe_code)]

pub mod error;
pub mod extractors;
pub mod handlers;
pub mod middleware;
pub mod openapi;
pub mod router;
pub mod shutdown;

#[cfg(feature = "grpc")]
pub mod grpc;
#[cfg(feature = "grpc")]
pub mod proto;
#[cfg(feature = "ui")]
pub mod ui;

pub use router::{AppState, build_router};
pub use shutdown::shutdown_signal;
