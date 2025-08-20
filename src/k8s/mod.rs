use axum::{extract::State, Json, response::IntoResponse};
use std::sync::Arc;
use crate::core::AppState;
use crate::storage::StorageBackend;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct AdmissionReview {
    pub request: Option<AdmissionRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdmissionRequest {
    pub uid: String,
    pub object: serde_json::Value,
    // ... bisa ditambah field lain sesuai kebutuhan
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdmissionResponse {
    pub uid: String,
    pub allowed: bool,
    pub patch: Option<String>,
    pub patchType: Option<String>,
    // ... bisa ditambah field lain sesuai kebutuhan
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AdmissionReviewResponse {
    pub response: AdmissionResponse,
}

pub mod crd;
pub mod sealed;

// Handler untuk webhook mutasi (inject secrets ke pod)
pub async fn k8s_webhook(State(state): State<Arc<AppState>>, Json(payload): Json<serde_json::Value>) -> impl IntoResponse {
    let review: AdmissionReview = match serde_json::from_value(payload) {
        Ok(r) => r,
        Err(_) => {
            return Json(serde_json::json!({
                "response": {
                    "allowed": false,
                    "status": { "message": "Invalid AdmissionReview" }
                }
            }));
        }
    };
    let uid = review.request.as_ref().map(|r| r.uid.clone()).unwrap_or_default();
    let mut patch = None;
    let mut patch_type = None;
    // Cek annotation pada pod
    if let Some(req) = &review.request {
        if let Some(meta) = req.object.get("metadata") {
            if let Some(annotations) = meta.get("annotations") {
                if annotations.get("vault.adhyaksa/inject").and_then(|v| v.as_str()) == Some("true") {
                    // Ambil nama pod
                    let pod_name = meta.get("name").and_then(|v| v.as_str()).unwrap_or("");
                    // Path secret di Vault
                    let secret_path = format!("/k8s/{}", pod_name);
                    // Ambil secret dari storage Vault
                    let secret = match state.storage.get_secret(&secret_path).await {
                        Ok(Some(s)) => s.value,
                        _ => "dummy_secret".to_string(),
                    };
                    // Inject env ke container pertama
                    let patch_ops = serde_json::json!([
                        {
                            "op": "add",
                            "path": "/spec/containers/0/env/-",
                            "value": { "name": "VAULT_SECRET", "value": secret }
                        }
                    ]);
                    let patch_bytes = serde_json::to_vec(&patch_ops).unwrap();
                    patch = Some(base64::encode(&patch_bytes));
                    patch_type = Some("JSONPatch".to_string());
                }
            }
        }
    }
    let response = AdmissionReviewResponse {
        response: AdmissionResponse {
            uid,
            allowed: true,
            patch,
            patchType: patch_type,
        },
    };
    Json(response)
}

// TODO: Handler CRD VaultSecret, sealed secrets, dsb. 