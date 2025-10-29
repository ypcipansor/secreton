//! Brankas UI Library
//!
//! Provides web UI, authentication, and session management

pub mod auth;
pub mod models;
pub mod handlers;
pub mod assets;
// TODO: Implement web UI pages when needed
// pub mod pages;

pub use auth::{AuthError, SessionService, PasswordPolicy, Session, User};
pub use handlers::*;
