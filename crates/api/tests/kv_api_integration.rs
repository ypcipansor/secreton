use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use tower::ServiceExt; // for `oneshot`
use secreton_api::kv::{create_kv_router, KVApiState, CreateSecretRequest, CreateSecretResponse, ListSecretsResponse, GetSecretResponse};
use secreton_common::models::api_response::ApiResponse;
use axum::Extension;

#[tokio::test]
async fn test_kv_api_end_to_end() {
    // 1. Setup State
    let kv_state = KVApiState::default(); // Uses InMemorySecretStorage

    // 2. Setup Router
    // We only test the KV sub-router.
    // We need to provide the Extension that the handler expects.
    let app = create_kv_router()
        .layer(Extension(kv_state));

    // 3. Test: List Secrets (Should be empty initially)
    let response = app.clone()
        .oneshot(Request::builder().uri("/secrets").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let api_resp: ApiResponse<ListSecretsResponse> = serde_json::from_slice(&body_bytes).unwrap();

    assert!(api_resp.success);
    assert!(api_resp.data.unwrap().keys.is_empty());

    // 4. Test: Create Secret
    let secret_data = serde_json::json!({"username": "admin", "password": "password123"});
    let create_req = CreateSecretRequest { data: secret_data.clone() };
    let req_body = Body::from(serde_json::to_vec(&create_req).unwrap());

    let response = app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/secret/data/app/db")
                .header("content-type", "application/json")
                .body(req_body)
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let api_resp: ApiResponse<CreateSecretResponse> = serde_json::from_slice(&body_bytes).unwrap();
    assert!(api_resp.success);
    assert!(api_resp.data.unwrap().version >= 1);

    // 5. Test: Get Secret
    let response = app.clone()
        .oneshot(
             Request::builder()
                .uri("/secret/data/app/db")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body_bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let api_resp: ApiResponse<GetSecretResponse> = serde_json::from_slice(&body_bytes).unwrap();
    assert!(api_resp.success);
    assert_eq!(api_resp.data.unwrap().data, secret_data);
}
