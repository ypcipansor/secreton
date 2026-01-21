use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use gloo_storage::{LocalStorage, Storage};
use crate::api;
use leptos::task::spawn_local;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct UserInfo {
    pub id: Option<String>,
    pub username: String,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AuthState {
    pub user: Option<UserInfo>,
    pub token: Option<String>,
    pub loading: bool,
}

impl Default for AuthState {
    fn default() -> Self {
        Self {
            user: None,
            token: None,
            loading: true,
        }
    }
}

#[derive(Clone, Copy)]
pub struct AuthContext(pub RwSignal<AuthState>);

pub fn provide_auth() {
    let state = RwSignal::new(AuthState::default());
    provide_context(AuthContext(state));

    // Initialize auth
    Effect::new(move |_| {
        spawn_local(async move {
            if let Ok(token) = LocalStorage::get::<String>("secreton_token") {
                // Verify token
                #[derive(Serialize)]
                struct VerifyRequest {
                    token: String,
                }

                match api::post::<UserInfo, _>("/auth/verify", VerifyRequest { token: token.clone() }).await {
                    Ok(user) => {
                         state.update(|s| {
                            s.user = Some(user);
                            s.token = Some(token);
                            s.loading = false;
                        });
                    },
                    Err(_) => {
                         // Token invalid
                         let _ = LocalStorage::delete("secreton_token");
                         state.update(|s| s.loading = false);
                    }
                }
            } else {
                state.update(|s| s.loading = false);
            }
        });
    });
}

pub fn use_auth() -> RwSignal<AuthState> {
    use_context::<AuthContext>().expect("AuthContext not found").0
}

pub fn logout() {
    let auth = use_auth();
    spawn_local(async move {
        let _ = api::post::<serde_json::Value, _>("/auth/logout", ()).await;
        let _ = LocalStorage::delete("secreton_token");
        auth.update(|s| {
            s.user = None;
            s.token = None;
        });
    });
}
