//! Secreton UI Library
//!
//! Provides web UI, authentication, and session management

pub mod assets;
pub mod auth;
pub mod handlers;
pub mod models;
pub mod pages;

pub use auth::{AuthError, PasswordPolicy, Session, SessionService, User};
pub use handlers::*;
pub use pages::{Breadcrumb, PageMeta, PageResponse, PageUtils};
