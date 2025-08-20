use leptos::*;
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginResponse {
    token: String,
    expires_in: i64,
}

#[component]
pub fn Login(cx: Scope) -> impl IntoView {
    let username = create_signal(cx, String::new());
    let password = create_signal(cx, String::new());
    let error = create_signal(cx, String::new());
    let nav = leptos_router::use_navigate(cx);

    let on_login = move |_| {
        let username = username.get().to_string();
        let password = password.get().to_string();
        let error = error.clone();
        let nav = nav.clone();
        spawn_local(async move {
            let client = Client::new();
            let res = client
                .post("http://localhost:8080/v1/auth/login")
                .json(&LoginRequest { username, password })
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
                            .set_item("token", &login.token)
                            .unwrap();
                        error.set(String::new());
                        nav("/", Default::default());
                    } else {
                        error.set("Login failed".to_string());
                    }
                }
                Err(_) => error.set("Network error".to_string()),
            }
        });
    };

    view! { cx,
        <form on:submit=move |ev| { ev.prevent_default(); on_login(()) }>
            <input type="text" placeholder="Username" bind:value=username />
            <input type="password" placeholder="Password" bind:value=password />
            <button type="submit">"Login"</button>
            <div style="color:red;">{move || error.get()}</div>
        </form>
    }
} 