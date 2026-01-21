use leptos::prelude::*;
use leptos_router::hooks::use_navigate;
use gloo_storage::{LocalStorage, Storage};
use serde::{Deserialize, Serialize};
use crate::api;
use crate::auth::use_auth;
use leptos::task::spawn_local;

#[derive(Serialize)]
struct LoginRequest {
    username: String,
    password: String,
    mfa_code: Option<String>,
    remember_me: Option<bool>,
}

#[derive(Deserialize)]
struct LoginResponse {
    access_token: Option<String>,
    // refresh_token: Option<String>,
    user: crate::auth::UserInfo,
}

#[component]
pub fn Login() -> impl IntoView {
    let auth = use_auth();
    let navigate = use_navigate();

    let (username, set_username) = signal("".to_string());
    let (password, set_password) = signal("".to_string());
    let (error, set_error) = signal(Option::<String>::None);
    let (loading, set_loading) = signal(false);

    let on_submit = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        set_loading.set(true);
        set_error.set(None);

        let navigate = navigate.clone(); // Clone for async block if needed, though use_navigate returns copy-able type usually
        spawn_local(async move {
            let req = LoginRequest {
                username: username.get_untracked(),
                password: password.get_untracked(),
                mfa_code: None, // TODO: MFA support
                remember_me: Some(true),
            };

            match api::post::<LoginResponse, _>("/auth/login", req).await {
                Ok(resp) => {
                    if let Some(token) = resp.access_token {
                        let _ = LocalStorage::set("secreton_token", token.clone());
                        auth.update(|s| {
                            s.token = Some(token);
                            s.user = Some(resp.user);
                        });
                        navigate("/", Default::default());
                    } else {
                         set_error.set(Some("Login successful but no token received.".to_string()));
                    }
                }
                Err(e) => {
                    set_error.set(Some(e.to_string()));
                }
            }
            set_loading.set(false);
        });
    };

    view! {
        <div class="flex items-center justify-center min-h-screen bg-gray-100">
            <div class="w-full max-w-md p-8 space-y-8 bg-white rounded-lg shadow-lg">
                <div class="text-center">
                    <h2 class="text-3xl font-bold text-gray-900">"Sign in"</h2>
                    <p class="mt-2 text-sm text-gray-600">"Access your Secreton vault"</p>
                </div>

                <form class="mt-8 space-y-6" on:submit=on_submit>
                    <div class="space-y-4 rounded-md shadow-sm">
                        <div>
                            <label for="username" class="sr-only">"Username"</label>
                            <input
                                id="username"
                                name="username"
                                type="text"
                                required
                                class="relative block w-full px-3 py-2 text-gray-900 placeholder-gray-500 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                                placeholder="Username"
                                prop:value=username
                                on:input=move |ev| set_username.set(event_target_value(&ev))
                                disabled=loading
                            />
                        </div>
                        <div>
                            <label for="password" class="sr-only">"Password"</label>
                            <input
                                id="password"
                                name="password"
                                type="password"
                                required
                                class="relative block w-full px-3 py-2 text-gray-900 placeholder-gray-500 border border-gray-300 rounded-md focus:outline-none focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                                placeholder="Password"
                                prop:value=password
                                on:input=move |ev| set_password.set(event_target_value(&ev))
                                disabled=loading
                            />
                        </div>
                    </div>

                    <Show when=move || error.get().is_some()>
                        <div class="p-3 text-sm text-red-700 bg-red-100 rounded-md">
                            {move || error.get().unwrap()}
                        </div>
                    </Show>

                    <div>
                        <button
                            type="submit"
                            disabled=loading
                            class="relative flex justify-center w-full px-4 py-2 text-sm font-medium text-white bg-blue-600 border border-transparent rounded-md group hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
                        >
                            {move || if loading.get() { "Signing in..." } else { "Sign in" }}
                        </button>
                    </div>
                </form>
            </div>
        </div>
    }
}
