//! Brankas UI Library
//!
//! Provides web UI, authentication, and session management

pub mod auth;
pub mod models;

// TODO: Fix template issues - need HTML template files
// pub mod handlers;
// pub mod templates;

pub use auth::{AuthError, AuthService, PasswordPolicy, Session, User};
// TODO: Re-export handlers when fixed
// pub use handlers::*;

// TODO: Assets need rust-embed trait implementation
// pub mod assets;

// TODO: Pages need Leptos framework - add dependency or refactor
// pub mod pages;
