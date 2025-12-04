//! Multi-factor authentication (MFA) module

pub mod email;
pub mod hardware;
pub mod push;
pub mod recovery;
pub mod service;
pub mod sms;
pub mod totp;
pub mod webauthn;

pub use email::*;
pub use hardware::*;
pub use push::*;
pub use recovery::*;
pub use service::*;
pub use sms::*;
pub use totp::*;
pub use webauthn::*;
