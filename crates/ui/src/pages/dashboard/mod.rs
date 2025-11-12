use leptos::prelude::*;
use reqwest::Client;
use serde::Deserialize;

#[derive(Deserialize, Default, Clone)]
struct Health {
    status: String,
}

#[derive(Deserialize, Default, Clone)]
struct Leader {
    is_leader: bool,
    host: String,
    port: u16,
}

#[component]
pub fn dashboard() -> impl IntoView {
    let health = LocalResource::new(|| async move {
        let client = Client::new();
        let resp = client
            .get("http://localhost:8080/v1/sys/health")
            .send()
            .await
            .ok()?;
        resp.json::<Health>().await.ok()
    });
    let leader = LocalResource::new(|| async move {
        let client = Client::new();
        let resp = client
            .get("http://localhost:8080/v1/sys/leader")
            .send()
            .await
            .ok()?;
        resp.json::<Leader>().await.ok()
    });
    view! {
        <h2>"Dashboard"</h2>
        <div>
            <b>Health:</b>
            {move || health.get().map(|h| h.as_ref().map(|h| h.status.clone()).unwrap_or("-".to_string()))}
        </div>
        <div>
            <b>Leader:</b>
            {move || leader.get().map(|l| l.as_ref().map(|l| if l.is_leader {"(this node)".to_string()} else {format!("{}:{}", l.host, l.port)}).unwrap_or("-".to_string()))}
        </div>
        <div>
            <a href="/metrics" target="_blank">"Metrics (Prometheus)"</a> |
            <a href="/swagger-ui" target="_blank">"Swagger UI"</a>
        </div>
    }
}
