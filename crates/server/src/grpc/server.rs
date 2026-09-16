//! gRPC service implementations.
//!
//! Each method resolves the caller from the `authorization` metadata entry, then delegates
//! to the same service in `secreton-engines` that backs the REST handler — so REST and
//! gRPC cannot drift in behaviour or in authorisation.

use std::sync::Arc;

use secreton_auth::User;
use secreton_engines::services::auth::{ApiLoginRequest, AuthenticationService};
use secreton_engines::services::secret::SecretService;
use tonic::{Request, Response, Status};

use crate::proto::secreton::v1::auth_service_server::AuthService;
use crate::proto::secreton::v1::secret_service_server::SecretService as SecretServiceTrait;
use crate::proto::secreton::v1::{
    DeleteSecretRequest, DeleteSecretResponse, GetSecretRequest, GetSecretResponse, LoginRequest,
    LoginResponse, PutSecretRequest, PutSecretResponse,
};

/// Resolve the bearer token in request metadata to a principal.
async fn authenticate(
    auth: &AuthenticationService,
    metadata: &tonic::metadata::MetadataMap,
) -> Result<User, Status> {
    let raw = metadata
        .get("authorization")
        .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?
        .to_str()
        .map_err(|_| Status::unauthenticated("malformed authorization metadata"))?;

    let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
    if token.is_empty() {
        return Err(Status::unauthenticated("empty bearer token"));
    }

    auth.validate_token(token).await.map_err(|e| {
        // The reason is logged but not returned: distinguishing "expired" from "forged"
        // hands an attacker a probe.
        tracing::debug!(error = %e, "gRPC token validation failed");
        Status::unauthenticated("invalid token")
    })
}

/// Map a service error onto a gRPC status.
///
/// Everything used to become `Status::internal`, so a caller could not tell a missing
/// secret from a permission denial from a genuine fault, and no client could retry
/// correctly.
fn to_status(e: secreton_engines::services::secret::SecretError) -> Status {
    use secreton_engines::services::secret::SecretError as E;
    match e {
        E::SecretNotFound { path } => Status::not_found(format!("no secret at {path}")),
        E::KeyNotFound { key_id } => Status::not_found(format!("no key {key_id}")),
        E::PermissionDenied(_) => Status::permission_denied("access denied"),
        E::InvalidOperation(message) => Status::invalid_argument(message),
        other => {
            tracing::error!(error = %other, "gRPC internal error");
            Status::internal("internal error")
        }
    }
}

pub struct GrpcSecretService {
    secrets: Arc<SecretService>,
    auth: Arc<AuthenticationService>,
}

// The wrapped services hold key material, so these print nothing about their contents.
impl std::fmt::Debug for GrpcSecretService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrpcSecretService")
    }
}

impl std::fmt::Debug for GrpcAuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GrpcAuthService")
    }
}

impl GrpcSecretService {
    pub fn new(secrets: Arc<SecretService>, auth: Arc<AuthenticationService>) -> Self {
        Self { secrets, auth }
    }
}

#[tonic::async_trait]
impl SecretServiceTrait for GrpcSecretService {
    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        let user = authenticate(&self.auth, request.metadata()).await?;
        let req = request.into_inner();

        let secret = self
            .secrets
            .get_secret(&req.path, &user, None)
            .await
            .map_err(to_status)?;

        Ok(Response::new(GetSecretResponse {
            data: secret.data,
            version: u64::from(secret.version),
        }))
    }

    async fn put_secret(
        &self,
        request: Request<PutSecretRequest>,
    ) -> Result<Response<PutSecretResponse>, Status> {
        let user = authenticate(&self.auth, request.metadata()).await?;
        let req = request.into_inner();

        let secret = self
            .secrets
            .put_secret(&req.path, req.data, None, &user, None)
            .await
            .map_err(to_status)?;

        Ok(Response::new(PutSecretResponse {
            path: secret.path,
            version: u64::from(secret.version),
        }))
    }

    async fn delete_secret(
        &self,
        request: Request<DeleteSecretRequest>,
    ) -> Result<Response<DeleteSecretResponse>, Status> {
        let user = authenticate(&self.auth, request.metadata()).await?;
        let req = request.into_inner();

        self.secrets
            .delete_secret(&req.path, &user)
            .await
            .map_err(to_status)?;

        Ok(Response::new(DeleteSecretResponse { deleted: true }))
    }
}

/// Token issuance for service-to-service callers.
///
/// The proto declared this service from the start but no implementation existed, so a
/// generated client compiled and then failed at runtime with `Unimplemented`.
pub struct GrpcAuthService {
    auth: Arc<AuthenticationService>,
}

impl GrpcAuthService {
    pub fn new(auth: Arc<AuthenticationService>) -> Self {
        Self { auth }
    }
}

#[tonic::async_trait]
impl AuthService for GrpcAuthService {
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<LoginResponse>, Status> {
        // Recorded on the session for auditing, same as the REST path.
        let peer = request
            .remote_addr()
            .map(|a| a.ip().to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let req = request.into_inner();

        let response = self
            .auth
            .login(
                ApiLoginRequest {
                    username: req.username,
                    password: req.password,
                    mfa_code: req.mfa_code.filter(|c| !c.is_empty()),
                },
                peer,
                "grpc".to_string(),
            )
            .await
            .map_err(|e| {
                // Never distinguish "no such user" from "wrong password": that turns
                // login into a username oracle.
                tracing::warn!(error = %e, "gRPC login failed");
                Status::unauthenticated("invalid credentials")
            })?;

        Ok(Response::new(LoginResponse {
            access_token: response.token.access_token,
            expires_in: response.token.expires_in,
        }))
    }
}
