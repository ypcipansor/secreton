use leptos::prelude::*;
use leptos_router::components::{Router, Routes, Route, A, Outlet};
use leptos_router::hooks::use_navigate;
use crate::auth::{provide_auth, use_auth};
use crate::pages::login::Login;
use crate::pages::dashboard::Dashboard;
use crate::pages::secrets::SecretsList;
use crate::pages::policies::PoliciesList;
use crate::pages::audit::AuditLog;
use crate::pages::not_found::NotFound;

#[component]
pub fn App() -> impl IntoView {
    provide_auth();

    view! {
        <Router>
            <div class="min-h-screen bg-gray-50 text-gray-900 font-sans">
                <Routes>
                    <Route path="/login" view=Login />
                    <Route path="/" view=ProtectedRoute>
                        <Route path="" view=Dashboard />
                        <Route path="secrets" view=SecretsList />
                        <Route path="secrets/*path" view=SecretsList />
                        <Route path="policies" view=PoliciesList />
                        <Route path="audit" view=AuditLog />
                    </Route>
                    <Route path="/*any" view=NotFound />
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


#[component]
fn Layout(children: Children) -> impl IntoView {
    let auth_state = use_auth();

    let user_name = move || {
        auth_state.with(|s| s.user.as_ref().map(|u| u.username.clone()).unwrap_or_default())
    };

    view! {
        <div class="flex h-screen overflow-hidden">
            // Sidebar
            <aside class="w-64 bg-gray-900 text-white flex-shrink-0 hidden md:flex flex-col">
                <div class="p-4 border-b border-gray-800 flex items-center gap-2">
                    // <img src="/logo.png" class="w-8 h-8" alt="Secreton" onError="this.style.display='none'"/>
                    <span class="text-xl font-bold tracking-wider">"SECRETON"</span>
                </div>

                <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
                    <A href="/" attr:class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors" active_class="bg-gray-800 text-white">
                        // Icon placeholder (Home)
                        <span>"Dashboard"</span>
                    </A>
                    <A href="/secrets" attr:class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors" active_class="bg-gray-800 text-white">
                        // Icon placeholder (Lock)
                        <span>"Secrets"</span>
                    </A>
                    <A href="/policies" attr:class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors" active_class="bg-gray-800 text-white">
                        // Icon placeholder (Shield)
                        <span>"Policies"</span>
                    </A>
                    <A href="/audit" attr:class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors" active_class="bg-gray-800 text-white">
                        // Icon placeholder (List)
                        <span>"Audit"</span>
                    </A>
                </nav>

                <div class="p-4 border-t border-gray-800">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full bg-gray-700 flex items-center justify-center text-sm font-bold">
                            {move || user_name().chars().next().unwrap_or('?')}
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium truncate">{user_name}</p>
                            <button
                                class="text-xs text-gray-500 hover:text-gray-300"
                                on:click=move |_| crate::auth::logout()
                            >
                                "Sign out"
                            </button>
                        </div>
                    </div>
                </div>
            </aside>

            // Main Content
            <main class="flex-1 overflow-auto bg-gray-50 relative">
                <div class="max-w-7xl mx-auto p-6">
                    {children()}
                </div>
            </main>
        </div>
    }
}
