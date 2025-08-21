use leptos::*;

#[component]
pub fn AuditLog(cx: Scope) -> impl IntoView {
    // Dummy data
    let logs = vec![
        ("admin", "login", "-", "success"),
        ("admin", "get_secret", "myapp/db", "success"),
        ("user1", "get_secret", "myapp/db", "failed"),
    ];
    view! { cx,
        <h2>"Audit Log"</h2>
        <table border="1">
            <tr><th>User</th><th>Action</th><th>Path</th><th>Status</th></tr>
            {logs.iter().map(|(u,a,p,s)| view! { cx,
                <tr><td>{u}</td><td>{a}</td><td>{p}</td><td>{s}</td></tr>
            }).collect_view(cx)}
        </table>
    }
} 