//! Pages, one per route in [`crate::app::App`].
//!
//! Each page fetches through a typed server function in [`crate::api`], never through a
//! hand-written HTTP call. Adding a page is: a module here, a `#[server]` function for its
//! data, and a `<Route>` in `app.rs`. A page that is not routed is dead code — the previous
//! `lifecycle.rs` sat unrouted while still being compiled.

pub mod dashboard;
pub mod login;
pub mod not_found;
