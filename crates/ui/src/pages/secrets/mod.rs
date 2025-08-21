use leptos::*;
use reqwest::Client;
use serde_json::Value;

#[component]
pub fn Secrets(cx: Scope) -> impl IntoView {
    let token = web_sys::window()
        .unwrap()
        .local_storage()
        .unwrap()
        .unwrap()
        .get_item("token")
        .unwrap_or_default();
    let secrets = create_resource(cx, || (), move |_| async move {
        let client = Client::new();
        let resp = client
            .get("http://localhost:8080/v1/secrets")
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .ok()?;
        resp.json::<Vec<String>>().await.ok()
    });
    let path = create_signal(cx, String::new());
    let data = create_signal(cx, String::new());
    let error = create_signal(cx, String::new());
    let on_add = move |ev: leptos::ev::SubmitEvent| {
        ev.prevent_default();
        let path = path.get().to_string();
        let data = data.get().to_string();
        let error = error.clone();
        let token = token.clone();
        let secrets = secrets.clone();
        spawn_local(async move {
            let client = Client::new();
            let parsed: Result<Value, _> = serde_json::from_str(&data);
            if let Ok(json_data) = parsed {
                let resp = client
                    .post(format!("http://localhost:8080/v1/secrets/{}", path))
                    .header("Authorization", format!("Bearer {}", token))
                    .json(&serde_json::json!({"data": json_data}))
                    .send()
                    .await;
                match resp {
                    Ok(r) if r.status().is_success() => {
                        error.set(String::new());
                        secrets.refetch();
                    }
                    Ok(r) => {
                        error.set(format!("Error: {}", r.status()));
                    }
                    Err(e) => error.set(format!("Network error: {}", e)),
                }
            } else {
                error.set("Invalid JSON data".to_string());
            }
        });
    };
    view! { cx,
        <h2>"Secrets"</h2>
        <ul>
            {move || secrets.read().map(|list| list.as_ref().map(|secrets| secrets.iter().map(|s| view! { cx,
                <li>
                    <a href={format!("/secrets/{}", s)}>{s}</a>
                </li>
            }).collect_view(cx)).unwrap_or_default())}
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
pub fn SecretDetail(cx: Scope) -> impl IntoView {
    let path = leptos_router::use_params_map(cx)
        .with(|params| params.get("path").cloned().unwrap_or_default());
    let token = web_sys::window()
        .unwrap()
        .local_storage()
        .unwrap()
        .unwrap()
        .get_item("token")
        .unwrap_or_default();
    let secret = create_resource(cx, move || path.clone(), move |path| async move {
        let client = Client::new();
        let resp = client
            .get(format!("http://localhost:8080/v1/secrets/{}", path))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .ok()?;
        resp.json::<Value>().await.ok()
    });
    view! { cx,
        <h2>"Secret Detail"</h2>
        <div>{move || secret.read().map(|s| s.as_ref().map(|s| s.to_string()).unwrap_or("-".to_string()))}</div>
    }
} 