//! # Secreton UI
//!
//! The Leptos application, compiled twice: once into the server binary (`ssr`) to render
//! HTML, and once to WebAssembly (`hydrate`) to take over in the browser. The components
//! are written once and used by both.
//!
//! The previous version was client-side only. It shipped an empty `<body>`, built the page
//! in WebAssembly after load, pulled Tailwind from a CDN at runtime, and kept the session
//! JWT in `localStorage` where any injected script could read it — in an application whose
//! whole purpose is holding secrets.

pub mod api;
pub mod app;
pub mod auth;
pub mod components;
pub mod pages;

pub use app::App;

/// Entry point for the WebAssembly bundle.
///
/// `cargo-leptos` names this as the hydration entry; it takes over the server-rendered
/// markup rather than rebuilding it.
#[cfg(feature = "hydrate")]
#[wasm_bindgen::prelude::wasm_bindgen]
pub fn hydrate() {
    console_error_panic_hook::set_once();
    leptos::mount::hydrate_body(App);
}
