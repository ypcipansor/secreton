use leptos::prelude::*;
use leptos_router::{components::{Router, Routes, Route, ParentRoute, Outlet}, path};
use leptos_router::hooks::use_navigate;
use crate::auth::{provide_auth, use_auth};
use crate::pages::login::Login;
use crate::pages::dashboard::Dashboard;
use crate::pages::secrets::SecretsList;
use crate::pages::database::DatabaseSecrets;
use crate::pages::pki::PkiPage;
use crate::pages::policies::PoliciesList;
use crate::pages::audit::AuditLog;
use crate::pages::not_found::NotFound;
use crate::pages::transit::TransitPage;
use crate::components::Layout;

#[component]
pub fn App() -> impl IntoView {
    provide_auth();

    view! {
        <Router>
            <div class="min-h-screen bg-gray-50 text-gray-900 font-sans">
                <Routes fallback=|| view! { <NotFound /> }>
                    <Route path=path!("/login") view=Login />
                    <ParentRoute path=path!("/") view=ProtectedRoute>
                        <Route path=path!("") view=Dashboard />
                        <Route path=path!("secrets") view=SecretsList />
                        <Route path=path!("secrets/*path") view=SecretsList />
                        <Route path=path!("database") view=DatabaseSecrets />
                        <Route path=path!("pki") view=PkiPage />
                        <Route path=path!("transit") view=TransitPage />
                        <Route path=path!("policies") view=PoliciesList />
                        <Route path=path!("audit") view=AuditLog />
                    </ParentRoute>
                </Routes>
            </div>
        </Router>
    }
}

#[component]
fn ProtectedRoute() -> impl IntoView {
    let auth_state = use_auth();

    let is_authenticated = move || {
        auth_state.with(|s| s.token.is_some())
    };

    let is_loading = move || {
        auth_state.with(|s| s.loading)
    };

    view! {
        <Show
            when=move || !is_loading()
            fallback=|| view! { <div class="flex items-center justify-center h-screen">"Loading..."</div> }
        >
            <Show
                when=is_authenticated
                fallback=|| view! { <Redirect path="/login"/> }
            >
                <Layout>
                    <Outlet/>
                </Layout>
            </Show>
        </Show>
    }
}

#[component]
// Dummy redirect component since Redirect is likely not exported or works differently.
// Actually leptos_router has Redirect.
fn Redirect(path: &'static str) -> impl IntoView {
    let navigate = use_navigate();
    request_animation_frame(move || {
        navigate(path, Default::default());
    });
    view! { }
}
