#![cfg(feature = "client")]
use leptos::prelude::*;

#[component]
pub fn audit_log() -> impl IntoView {
    // Fetch audit logs from backend
    let audit_logs = Resource::new(
        || (),
        |_| async move {
            // In a real implementation, this would make an API call to fetch audit logs
            // For now, we'll simulate with some realistic data
            vec![
                (
                    "admin".to_string(),
                    "login".to_string(),
                    "-".to_string(),
                    "success".to_string(),
                    "2024-01-15T10:30:00Z".to_string(),
                ),
                (
                    "admin".to_string(),
                    "get_secret".to_string(),
                    "myapp/db".to_string(),
                    "success".to_string(),
                    "2024-01-15T10:35:00Z".to_string(),
                ),
                (
                    "user1".to_string(),
                    "get_secret".to_string(),
                    "myapp/db".to_string(),
                    "failed".to_string(),
                    "2024-01-15T11:00:00Z".to_string(),
                ),
                (
                    "user2".to_string(),
                    "create_secret".to_string(),
                    "app/config".to_string(),
                    "success".to_string(),
                    "2024-01-15T11:15:00Z".to_string(),
                ),
                (
                    "admin".to_string(),
                    "delete_secret".to_string(),
                    "old/backup".to_string(),
                    "success".to_string(),
                    "2024-01-15T12:00:00Z".to_string(),
                ),
            ]
        },
    );

    view! {
        <h2>"Audit Log"</h2>
        <Suspense fallback=move || view! { <p>"Loading audit logs..."</p> }>
            {move || Suspend::new(async move {
                let logs = audit_logs.await;
                logs.into_iter().map(|(user, action, path, status, timestamp)| {
                    let status_class = format!("status {}", status.to_lowercase());
                    view! {
                        <div class="audit-entry">
                            <span class="timestamp">{timestamp}</span>
                            <span class="user">{user}</span>
                            <span class="action">{action}</span>
                            <span class="path">{path}</span>
                            <span class=status_class>{status}</span>
                        </div>
                    }
                }).collect_view()
            })}
        </Suspense>
        <style>
            {r#"
                .audit-entry {
                    display: flex;
                    gap: 1rem;
                    padding: 0.5rem;
                    border-bottom: 1px solid #eee;
                    font-family: monospace;
                    font-size: 0.9rem;
                }
                .timestamp { color: #666; min-width: 200px; }
                .user { font-weight: bold; min-width: 80px; }
                .action { color: #007acc; min-width: 100px; }
                .path { color: #d73a49; flex: 1; }
                .status.success { color: #28a745; }
                .status.failed { color: #dc3545; }
            "#}
        </style>
    }
}
