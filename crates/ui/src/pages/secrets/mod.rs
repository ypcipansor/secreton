use leptos::prelude::*;
use reqwest::Client;
use serde_json::Value;
use std::sync::Arc;
use wasm_bindgen_futures::spawn_local;

#[component]
pub fn secrets() -> impl IntoView {
    let token = web_sys::window()
        .unwrap()
        .local_storage()
        .unwrap()
        .unwrap()
        .get_item("token")
        .unwrap()
        .unwrap_or_default();
    let token = Arc::new(token);
    let token_for_resource = Arc::clone(&token);
    let token_for_on_add = Arc::clone(&token);
    let secrets = Resource::new(
        move || Arc::clone(&token_for_resource),
        |token| async move {
            let client = Client::new();
            let resp = client
                .get("http://localhost:8080/v1/secrets")
                .header("Authorization", format!("Bearer {}", *token))
                .send()
                .await
                .ok()?;
            resp.json::<Vec<String>>().await.ok()
        },
    );
    let path = RwSignal::new(String::new());
    let data = RwSignal::new(String::new());
    let error = RwSignal::new(String::new());
    let on_add = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let path = path.get().to_string();
        let data = data.get().to_string();
        let error_clone = error.clone();
        let token = Arc::clone(&token_for_on_add);
        let secrets = secrets.clone();
        spawn_local(async move {
            let client = Client::new();
            let parsed: Result<Value, _> = serde_json::from_str(&data);
            if let Ok(json_data) = parsed {
                let resp = client
                    .post(format!("http://localhost:8080/v1/secrets/{}", path))
                    .header("Authorization", format!("Bearer {}", *token))
                    .json(&serde_json::json!({"data": json_data}))
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        error_clone.set(String::new());
                        secrets.refetch();
                    }
                    Ok(r) => {
                        error_clone.set(format!("Error: {}", r.status()));
                    }
                    Err(e) => error_clone.set(format!("Network error: {}", e)),
                }
            } else {
                error_clone.set("Invalid JSON data".to_string());
            }
        });
    };
    view! {
        <h2>"Secrets"</h2>
        <ul>
            {move || secrets.get().map(|list| list.as_ref().map(|secrets| secrets.iter().map(|s| view! {
                <li>
                    <a href={format!("/secrets/{}", s)}>{s.clone()}</a>
                </li>
            }).collect_view()).unwrap_or_default())}
        </ul>
        <h3>"Add Secret"</h3>
        <form on:submit=on_add>
            <input type="text" placeholder="Path" bind:value=path />
            <textarea placeholder="Data (JSON)" bind:value=data />
            <button type="submit">"Add"</button>
            <div style="color:red;">{move || error.get()}</div>
        </form>
    }
}

#[component]
pub fn secret_detail() -> impl IntoView {
    let path = web_sys::window()
        .unwrap()
        .location()
        .pathname()
        .unwrap()
        .strip_prefix("/secrets/")
        .unwrap_or("")
        .to_string();
    let path = Arc::new(path);
    let token = web_sys::window()
        .unwrap()
        .local_storage()
        .unwrap()
        .unwrap()
        .get_item("token")
        .unwrap()
        .unwrap_or_default();
    let token = Arc::new(token);
    let secret = Resource::new(
        move || (Arc::clone(&path), Arc::clone(&token)),
        |(path, token)| async move {
            let client = Client::new();
            let resp = client
                .get(format!("http://localhost:8080/v1/secrets/{}", *path))
                .header("Authorization", format!("Bearer {}", *token))
                .send()
                .await
                .ok()?;
            resp.json::<Value>().await.ok()
        },
    );
    view! {
        <h2>"Secret Detail"</h2>
        <div>{move || secret.get().map(|s| s.as_ref().map(|s| s.to_string()).unwrap_or("-".to_string()))}</div>
    }
}
