use leptos::*;
use leptos_router::*;

mod pages;

#[component]
pub fn App(cx: Scope) -> impl IntoView {
    view! { cx,
        <Router>
            <main>
                <h1>"Vault Adhyaksa UI (Rust/Leptos)"</h1>
                <nav>
                    <A href="/">"Dashboard"</A> |
                    <A href="/secrets">"Secrets"</A> |
                    <A href="/admin">"Admin"</A> |
                    <A href="/audit">"Audit Log"</A>
                </nav>
                <Routes>
                    <Route path="/" view=pages::dashboard::Dashboard/>
                    <Route path="/login" view=pages::login::Login/>
                    <Route path="/secrets" view=pages::secrets::Secrets/>
                    <Route path="/secrets/:path" view=pages::secrets::SecretDetail/>
                    <Route path="/admin" view=pages::admin::Admin/>
                    <Route path="/audit" view=pages::audit::AuditLog/>
                </Routes>
            </main>
        </Router>
    }
} 