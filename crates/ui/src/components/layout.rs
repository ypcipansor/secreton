use leptos::prelude::*;
use leptos_router::hooks::{use_navigate, use_location};
use crate::auth::use_auth;

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

    let user_name = move || {
        auth_state.with(|s| s.user.as_ref().map(|u| u.username.clone()).unwrap_or_default())
    };

    let logout_handler = move |_| {
        crate::auth::logout();
    };

    view! {
        <div class="flex h-screen overflow-hidden bg-gray-50">
            // Sidebar
            <aside class="w-64 bg-gray-900 text-white flex-shrink-0 hidden md:flex flex-col shadow-xl z-20">
                <div class="p-4 border-b border-gray-800 flex items-center gap-3">
                    <div class="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center font-bold text-white">"S"</div>
                    <span class="text-xl font-bold tracking-wider">"SECRETON"</span>
                </div>

                <nav class="flex-1 p-4 space-y-1 overflow-y-auto">
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
                        <span class="text-lg">"🔒"</span>
                        <span>"Secrets"</span>
                    </Link>
                    <Link
                        href="/database"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🗄️"</span>
                        <span>"Database"</span>
                    </Link>
                    <Link
                        href="/pki"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🔑"</span>
                        <span>"PKI"</span>
                    </Link>
                    <Link
                        href="/transit"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🔐"</span>
                        <span>"Transit"</span>
                    </Link>
                    <Link
                        href="/ssh"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🖥️"</span>
                        <span>"SSH"</span>
                    </Link>
                    <Link
                        href="/totp"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"⏲️"</span>
                        <span>"TOTP"</span>
                    </Link>
                    <Link
                        href="/policies"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"🛡️"</span>
                        <span>"Policies"</span>
                    </Link>
                    <Link
                        href="/users"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"👥"</span>
                        <span>"Users"</span>
                    </Link>
                    <Link
                        href="/audit"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"📜"</span>
                        <span>"Audit"</span>
                    </Link>
                    <Link
                        href="/backups"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"💾"</span>
                        <span>"Backups"</span>
                    </Link>
                    <Link
                        href="/settings"
                        class="flex items-center gap-3 px-3 py-2 text-gray-300 hover:bg-gray-800 hover:text-white rounded-md transition-colors"
                        active_class="bg-gray-800 text-white shadow-inner"
                    >
                        <span class="text-lg">"⚙️"</span>
                        <span>"Settings"</span>
                    </Link>
                </nav>

                <div class="p-4 border-t border-gray-800 bg-gray-900">
                    <div class="flex items-center gap-3">
                        <div class="w-8 h-8 rounded-full bg-blue-500 flex items-center justify-center text-sm font-bold shadow">
                            {move || user_name().chars().next().unwrap_or('?').to_ascii_uppercase()}
                        </div>
                        <div class="flex-1 min-w-0">
                            <p class="text-sm font-medium truncate text-white">{user_name}</p>
                            <button
                                class="text-xs text-gray-400 hover:text-white transition-colors flex items-center gap-1 mt-0.5"
                                on:click=logout_handler
                            >
                                <span>"Sign out"</span>
                                <span class="text-[10px]">"➜"</span>
                            </button>
                        </div>
                    </div>
                </div>
            </aside>

            // Main Content
            <div class="flex-1 flex flex-col min-w-0 overflow-hidden">
                // Mobile Header
                <header class="md:hidden bg-gray-900 text-white p-4 flex justify-between items-center shadow">
                     <span class="font-bold">"SECRETON"</span>
                     <button class="text-gray-300 hover:text-white">"☰"</button>
                </header>

                <main class="flex-1 overflow-auto bg-gray-50 relative focus:outline-none">
                    <div class="max-w-7xl mx-auto p-6 md:p-8">
                        {children()}
                    </div>
                </main>
            </div>
        </div>
    }
}
