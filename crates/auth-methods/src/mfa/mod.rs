//! Multi-factor authentication (MFA) module

pub mod email;
pub mod hardware;
pub mod service;
pub mod sms;
pub mod totp;

pub use email::*;
pub use hardware::*;
pub use service::*;
pub use sms::*;
pub use totp::*;
