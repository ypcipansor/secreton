use crate::services::auth::AuthenticationService;
use crate::services::secret::SecretService as CoreSecretService;
use secreton_grpc::secreton::v1::secret_service_server::SecretService;
use secreton_grpc::secreton::v1::{
    GetSecretRequest, GetSecretResponse, PutSecretRequest, PutSecretResponse,
};
use std::sync::Arc;
use tonic::{Request, Response, Status};

pub struct GrpcSecretService {
    core_service: Arc<CoreSecretService>,
    auth_service: Arc<AuthenticationService>,
}

impl GrpcSecretService {
    pub fn new(
        core_service: Arc<CoreSecretService>,
        auth_service: Arc<AuthenticationService>,
    ) -> Self {
        Self {
            core_service,
            auth_service,
        }
    }

    // Helper to extract user from metadata by verifying token with AuthenticationService
    async fn authenticate_user(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<secreton_auth::User, Status> {
        let token_str = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("Missing authorization header"))?
            .to_str()
            .map_err(|_| Status::invalid_argument("Invalid authorization header"))?;

        let token = token_str.strip_prefix("Bearer ").unwrap_or(token_str);

        match self.auth_service.validate_token(token).await {
            Ok(user) => Ok(user),
            Err(e) => {
                // Determine status code based on error type
                // Assuming simple mapping for now
                Err(Status::unauthenticated(format!(
                    "Authentication failed: {}",
                    e
                )))
            }
        }
    }
}

#[tonic::async_trait]
impl SecretService for GrpcSecretService {
    async fn get_secret(
        &self,
        request: Request<GetSecretRequest>,
    ) -> Result<Response<GetSecretResponse>, Status> {
        // Authenticate using the real service
        let user = self.authenticate_user(request.metadata()).await?;

        let req = request.into_inner();

        // Call Core Service with the authenticated user
        match self.core_service.get_secret(&req.path, &user).await {
            Ok(secret) => Ok(Response::new(GetSecretResponse { data: secret.data })),
            Err(e) => {
                // We should map SecretError to Status codes
                // For simplified error handling:
                Err(Status::internal(e.to_string()))
            }
        }
    }

    async fn put_secret(
        &self,
        request: Request<PutSecretRequest>,
    ) -> Result<Response<PutSecretResponse>, Status> {
        // Authenticate
        let user = self.authenticate_user(request.metadata()).await?;

        let req = request.into_inner();

        match self
            .core_service
            .put_secret(&req.path, req.data, &user)
            .await
        {
            Ok(secret) => Ok(Response::new(PutSecretResponse {
                path: secret.path,
                version: secret.version.to_string(),
            })),
            Err(e) => Err(Status::internal(e.to_string())),
        }
    }
}
