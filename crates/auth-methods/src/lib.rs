//! # Secreton Authentication Methods
//!
//! This crate provides comprehensive authentication and identity management for the Secreton system.
//! It consolidates all authentication methods, identity management, MFA, tokens, and revocation into a single domain.
//!
//! ## Supported Authentication Methods
//!
//! - **Token**: Token-based authentication (builtin)
//! - **UserPass**: Username/password authentication
//! - **LDAP**: LDAP directory authentication
//! - **OIDC**: OpenID Connect authentication
//! - **OAuth2**: OAuth 2.0 authentication flows
//! - **AppRole**: Machine-to-machine authentication
//! - **Kubernetes**: Kubernetes service account authentication
//! - **AWS IAM**: AWS IAM role authentication
//! - **GitHub**: GitHub OAuth authentication
//! - **Okta**: Okta identity provider integration
//! - **RADIUS**: RADIUS protocol authentication
//! - **SAML**: SAML 2.0 authentication (enterprise)
//! - **Certificate**: X.509 certificate authentication
//!
//! ## Additional Features
//!
//! - **Multi-Factor Authentication (MFA)**: TOTP, SMS, Email, Hardware tokens
//! - **Identity Management**: User entities, aliases, groups
//! - **Token Management**: Token creation, renewal, revocation
//! - **Revocation**: Certificate revocation, token revocation
//! - **Agent Authentication**: Template-based authentication for agents
//!
//! ## Architecture
//!
//! The auth-methods crate follows domain-driven design principles:
//!
//! - `method/`: Individual authentication method implementations
//! - `identity/`: Identity and user management
//! - `mfa/`: Multi-factor authentication
//! - `token/`: Token management and lifecycle
//! - `revocation/`: Revocation registries and management
//! - `agent/`: Agent authentication and templating
//! - `model/`: Authentication data models and DTOs
//! - `service/`: Authentication service orchestration
//! - `error/`: Authentication-specific error types

pub mod agent;
pub mod error;
pub mod identity;
pub mod method;
pub mod mfa;
pub mod model;
pub mod revocation;
pub mod service;
pub mod token;

pub use agent::*;
pub use error::*;
pub use identity::*;
pub use method::{
    AppRoleAuthMethod, CertAuth, GithubAuthMethod, OktaAuthMethod, UserPassAuthMethod,
};
pub use mfa::{
    CombinedMfaService, EmailService, HardwareService, InMemoryEmailService,
    InMemoryHardwareService, InMemorySmsService, InMemoryTotpService, MfaService, SmsService,
    TotpService,
};
pub use model::{
    AuthCredentials, AuthMethod, AuthMethodType, AuthRequest, AuthResponse, AuthResult,
    LegacyToken, LoginRequest, LoginResponse, MfaConfig, MfaLoginRequest, MfaRecoveryCodesResponse,
    MfaSetupRequest, MfaSetupResponse, MfaStatusResponse, MfaVerificationResult, MfaVerifyRequest,
    RefreshTokenRequest, User, UserInfo,
};
pub use revocation::{
    CombinedRevocationService, InMemoryRevocationRegistry, RevocationRegistry, RevocationService,
};
pub use service::*;
pub use token::{
    CombinedTokenService, InMemoryTokenRenewalService, InMemoryTokenRevocationService,
    TokenRenewalService, TokenRevocationService, TokenService,
};
