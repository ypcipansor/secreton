use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_location};
use crate::auth::use_auth;
use crate::api;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct HealthResponse {
    pub status: String,
    pub initialized: bool,
    pub sealed: bool,
    pub version: String,
}

#[component]
fn Link(
    #[prop(into)] href: String,
    #[prop(optional, into)] class: String,
    #[prop(optional, into)] active_class: String,
    children: Children,
) -> impl IntoView {
    let navigate = use_navigate();
    let location = use_location();
    let href_clone = href.clone();
    let href_for_click = href.clone();

    let is_active = move || {
        let path = location.pathname.get();
        if href == "/" {
            path == "/"
        } else {
            path.starts_with(&href)
        }
    };

    let computed_class = move || {
        if is_active() && !active_class.is_empty() {
            format!("{} {}", class, active_class)
        } else {
            class.clone()
        }
    };

    let on_click = move |ev: leptos::ev::MouseEvent| {
        ev.prevent_default();
        navigate(&href_for_click, Default::default());
    };

    view! {
        <a href=href_clone class=computed_class on:click=on_click>
            {children()}
        </a>
    }
}

#[component]
pub fn Layout(children: Children) -> impl IntoView {
    let auth_state = use_auth();
    let navigate = use_navigate();

    let user_name = move || {
        auth_state.with(|s| s.user.as_ref().map(|u| u.username.clone()).unwrap_or_default())
    };

    let logout_handler = move |_| {
        crate::auth::logout();
    };

    // Health Check Resource
    let health_resource = LocalResource::new(|| async move {
        api::get::<HealthResponse>("/sys/health").await
    });

    // Effect to redirect if uninitialized or sealed (optional, or just show warning)
    Effect::new(move |_| {
        if let Some(Ok(health)) = health_resource.get() {
             if !health.initialized {
                 // Maybe redirect to init? For now just show warning.
             }
        }
    });

    view! {
        <div class="flex h-screen overflow-hidden bg-gray-50">
            // Sidebar
            <aside class="w-64 bg-gray-900 text-white flex-shrink-0 hidden md:flex flex-col shadow-xl z-20">
                <div class="p-4 border-b border-gray-800 flex items-center gap-3">
                    <div class="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white">"S"</div>
                    <div class="flex flex-col">
                        <span class="text-xl font-bold tracking-wider leading-none">"SECRETON"</span>
                        <span class="text-[10px] text-gray-500 font-mono mt-1">
                            {move || health_resource.get().map(|r| r.map(|h| format!("v{}", h.version)).unwrap_or_default()).unwrap_or_default()}
                        </span>
                    </div>
                </div>

                // Status Indicator
                <div class="px-4 pt-4">
                    <Suspense fallback=|| view! { <div class="h-8 bg-gray-800 rounded animate-pulse"></div> }>
                        {move || {
                            let navigate = navigate.clone();
                            health_resource.get().map(move |res| {
                                match res {
                                    Ok(health) => {
                                        let (color, text, icon) = if !health.initialized {
                                            ("bg-orange-500", "Uninitialized", "⚠️")
                                        } else if health.sealed {
                                            ("bg-red-500", "Sealed", "🔒")
                                        } else {
                                            ("bg-green-500", "Active", "✅")
                                        };
                                        view! {
                                            <div class=format!("{} text-white text-xs font-bold px-3 py-2 rounded flex items-center justify-between shadow-sm", color)>
                                                <span class="flex items-center gap-2">
                                                    <span>{icon}</span>
                                                    <span>{text.to_uppercase()}</span>
                                                </span>
                                                <button
                                                    class="hover:bg-white/20 rounded p-0.5 transition"
                                                    title="System Status"
                                                    on:click=move |_| navigate("/system", Default::default())
                                                >
                                                    "⚙️"
                                                </button>
                                            </div>
                                        }.into_any()
                                    },
                                    Err(_) => view! {
                                        <div class="bg-gray-800 text-gray-400 text-xs px-3 py-2 rounded border border-gray-700">
                                            "Offline"
                                        </div>
                                    }.into_any()
                                }
                            })
                        }}
                    </Suspense>
                </div>

                <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
                    <p class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 mt-2">"General"</p>
                    <Link
                        href="/"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"📊"</span>
                        <span>"Dashboard"</span>
                    </Link>
                    <Link
                        href="/secrets"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🔑"</span>
                        <span>"Secrets"</span>
                    </Link>

                    <p class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 mt-6">"Access"</p>
                    <Link
                        href="/policies"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🛡️"</span>
                        <span>"Policies"</span>
                    </Link>
                    <Link
                        href="/roles"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"👥"</span>
                        <span>"Roles"</span>
                    </Link>
                     <Link
                        href="/users"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"👤"</span>
                        <span>"Users"</span>
                    </Link>

                    <p class="px-3 text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2 mt-6">"System"</p>
                    <Link
                        href="/audit"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"📜"</span>
                        <span>"Audit"</span>
                    </Link>
                     <Link
                        href="/system"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"⚙️"</span>
                        <span>"System"</span>
                    </Link>
                </nav>

                <div class="p-4 border-t border-gray-800 bg-gray-900">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-sm font-bold shadow ring-2 ring-gray-800">
                            {move || user_name().chars().next().unwrap_or('?').to_ascii_uppercase()}
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium truncate text-white">{user_name}</p>
                            <button
                                class="text-xs text-gray-400 hover:text-white transition-colors flex items-center gap-1 mt-0.5 group"
                                on:click=logout_handler
                            >
                                <span class="group-hover:text-red-400 transition-colors">"Sign out"</span>
                                <span class="text-[10px] group-hover:translate-x-1 transition-transform">"➜"</span>
                            </button>
                        </div>
                    </div>
                </div>
            </aside>

            // Main Content
            <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
                // Mobile Header
                <header class="md:hidden bg-gray-900 text-white p-4 flex justify-between items-center shadow z-10">
                     <div class="flex items-center gap-2">
                         <div class="w-6 h-6 bg-blue-600 rounded flex items-center justify-center font-bold text-xs">"S"</div>
                         <span class="font-bold">"SECRETON"</span>
                     </div>
                     <button class="text-gray-300 hover:text-white">"☰"</button>
                </header>

                <main class="flex-1 overflow-auto bg-gray-50 relative focus:outline-none">
                     // Status banner for mobile or important alerts
                    <Suspense>
                        {move || {
                            health_resource.get().map(|res| {
                                if let Ok(health) = res {
                                    if !health.initialized {
                                        view! {
                                            <div class="bg-orange-600 text-white px-4 py-2 text-center text-sm font-bold shadow-md relative z-10">
                                                "⚠️ SYSTEM UNINITIALIZED - Setup Required"
                                            </div>
                                        }.into_any()
                                    } else if health.sealed {
                                        view! {
                                            <div class="bg-red-600 text-white px-4 py-2 text-center text-sm font-bold shadow-md relative z-10">
                                                "🔒 SYSTEM SEALED - Functionality Restricted"
                                            </div>
                                        }.into_any()
                                    } else {
                                        view! {}.into_any()
                                    }
                                } else {
                                    view! {}.into_any()
                                }
                            })
                        }}
                    </Suspense>

                    <div class="max-w-7xl mx-auto p-4 md:p-8 pb-20">
                        {children()}
                    </div>
                </main>
            </div>
        </div>
    }
}
