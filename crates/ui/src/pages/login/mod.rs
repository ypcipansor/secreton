#![cfg(feature = "client")]
use leptos::prelude::*;
use reqwest::Client;
use secreton_auth::model::LoginRequest;
use serde::Deserialize;
use wasm_bindgen_futures::spawn_local;

#[derive(Deserialize)]
struct LoginResponse {
    access_token: Option<String>,
    _refresh_token: Option<String>,
    _token_type: String,
    _expires_in: i64,
    _user: secreton_auth::model::UserInfo,
    _mfa_required: bool,
}

// Define LoginResponse locally to match API response

#[component]
pub fn login() -> impl IntoView {
    let username = RwSignal::new(String::new());
    let password = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    // let nav = leptos_router::use_navigate();

    let on_login = move |_| {
        let username = username.get().to_string();
        let password = password.get().to_string();
        let error_clone = error.clone();
        // let nav = nav.clone();
        spawn_local(async move {
            let client = Client::new();
            let res = client
                .post("http://localhost:8080/v1/auth/login")
                .json(&LoginRequest {
                    username,
                    password,
                    mfa_code: None,
                    remember_me: None,
                })
                .send()
                .await;
            match res {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let login: LoginResponse = resp.json().await.unwrap();
                        web_sys::window()
                            .unwrap()
                            .local_storage()
                            .unwrap()
                            .unwrap()
                            .set_item("token", login.access_token.as_ref().unwrap())
                            .unwrap();
                        error_clone.set(String::new());
                        // nav("/", Default::default());
                        web_sys::window().unwrap().location().assign("/").unwrap();
                    } else {
                        error_clone.set("Login failed".to_string());
                    }
                }
                Err(_) => error_clone.set("Network error".to_string()),
            }
        });
    };

    view! {
        <form on:submit=move |ev| { ev.prevent_default(); on_login(()) }>
            <input type="text" placeholder="Username" bind:value=username />
            <input type="password" placeholder="Password" bind:value=password />
            <button type="submit">"Login"</button>
            <div style="color:red;">{move || error.get()}</div>
        </form>
    }
}
