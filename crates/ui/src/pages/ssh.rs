use crate::api::{get, post};
use crate::components::{Button, Card, Input};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignKeyRequest {
    pub public_key: String,
    pub valid_principals: Option<Vec<String>>,
    pub ttl: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignedKeyResponse {
    pub signed_key: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CaResponse {
    pub public_key: String,
}

#[component]
pub fn SshPage() -> impl IntoView {
    let (active_tab, set_active_tab) = signal("sign".to_string());

    // Sign State
    let (public_key, set_public_key) = signal("".to_string());
    let (principals, set_principals) = signal("ubuntu,root".to_string());
    let (ttl, set_ttl) = signal("3600".to_string());
    let (sign_loading, set_sign_loading) = signal(false);
    let (sign_result, set_sign_result) = signal(Option::<String>::None);
    let (sign_error, set_sign_error) = signal(Option::<String>::None);

    // CA State
    let (ca_key, set_ca_key) = signal(Option::<String>::None);
    let (ca_loading, set_ca_loading) = signal(false);
    let (ca_error, set_ca_error) = signal(Option::<String>::None);

    // Initial CA Fetch
    let fetch_ca = move || {
        spawn_local(async move {
            match get::<CaResponse>("/ssh/config/ca").await {
                Ok(res) => set_ca_key.set(Some(res.public_key)),
                Err(_) => set_ca_key.set(None), // Not configured
            }
        });
    };

    fetch_ca();

    let sign_action = move |_| {
        set_sign_loading.set(true);
        set_sign_error.set(None);
        set_sign_result.set(None);

        let pk = public_key.get();
        let princ_str = principals.get();
        let ttl_val = ttl.get().parse::<u64>().unwrap_or(3600);

        let princ_vec: Vec<String> = princ_str
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();

        spawn_local(async move {
            let req = SignKeyRequest {
                public_key: pk,
                valid_principals: Some(princ_vec),
                ttl: Some(ttl_val),
            };

            match post::<SignedKeyResponse, _>("/ssh/sign", req).await {
                Ok(res) => set_sign_result.set(Some(res.signed_key)),
                Err(e) => set_sign_error.set(Some(format!("Error: {}", e))),
            }
            set_sign_loading.set(false);
        });
    };

    let generate_ca_action = move |_| {
        set_ca_loading.set(true);
        set_ca_error.set(None);

        spawn_local(async move {
            // Empty body to trigger generation
            match post::<CaResponse, _>("/ssh/config/ca", serde_json::json!({})).await {
                Ok(res) => set_ca_key.set(Some(res.public_key)),
                Err(e) => set_ca_error.set(Some(format!("Error: {}", e))),
            }
            set_ca_loading.set(false);
        });
    };

    // Tab Class Helper
    let tab_class = move |tab_name: &'static str| {
        let base = "px-4 py-2 font-medium text-sm rounded-t-lg focus:outline-none";
        move || {
            if active_tab.get() == tab_name {
                format!(
                    "{} bg-white text-blue-600 border-t border-l border-r border-gray-200",
                    base
                )
            } else {
                format!("{} text-gray-500 hover:text-gray-700 bg-gray-50", base)
            }
        }
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold text-gray-900">"SSH Engine"</h1>
                <div class="flex space-x-2">
                    <span class="px-2 py-1 text-xs font-semibold bg-green-100 text-green-800 rounded-full">"BETA"</span>
                </div>
            </div>

            <Card>
                <div class="border-b border-gray-200">
                    <nav class="-mb-px flex space-x-1" aria-label="Tabs">
                        <button class=tab_class("sign") on:click=move |_| set_active_tab.set("sign".to_string())>
                            "Sign Key"
                        </button>
                        <button class=tab_class("ca") on:click=move |_| set_active_tab.set("ca".to_string())>
                            "CA Management"
                        </button>
                    </nav>
                </div>

                <div class="p-6">
                    <Show when=move || active_tab.get() == "sign">
                        <div class="space-y-6">
                            <div class="space-y-4">
                                <h3 class="text-lg font-medium text-gray-900">"Sign SSH Public Key"</h3>

                                <div class="space-y-1">
                                    <label class="block text-sm font-medium text-gray-700">"Public Key"</label>
                                    <textarea
                                        class="block w-full px-3 py-2 sm:text-sm rounded-md shadow-sm border border-gray-300 focus:ring-blue-500 focus:border-blue-500 h-24 font-mono text-xs"
                                        placeholder="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA..."
                                        on:input=move |ev| set_public_key.set(event_target_value(&ev))
                                        prop:value=public_key
                                    ></textarea>
                                </div>

                                <Input
                                    label="Valid Principals (comma separated)"
                                    value=principals
                                    on_input=Box::new(move |v| set_principals.set(v))
                                />

                                <Input
                                    label="TTL (seconds)"
                                    value=ttl
                                    type_="number"
                                    on_input=Box::new(move |v| set_ttl.set(v))
                                />

                                <div class="pt-2">
                                    <Button
                                        loading=sign_loading
                                        on_click=Box::new(sign_action)
                                    >
                                        "Sign Key"
                                    </Button>
                                </div>

                                <Show when=move || sign_error.get().is_some()>
                                    <div class="p-4 rounded-md bg-red-50 text-red-700 text-sm">
                                        {move || sign_error.get()}
                                    </div>
                                </Show>
                            </div>

                            <Show when=move || sign_result.get().is_some()>
                                {move || {
                                    let cert = sign_result.get().unwrap();
                                    view! {
                                        <div class="mt-4 p-4 rounded-md bg-green-50 border border-green-200">
                                            <h4 class="text-sm font-medium text-green-800 mb-2">"Signed Certificate"</h4>
                                            <div class="relative group">
                                                <textarea
                                                    readonly
                                                    class="block w-full px-3 py-2 text-xs font-mono bg-white border border-green-200 rounded-md h-32 focus:ring-0 focus:border-green-300 resize-none"
                                                >
                                                    {cert.clone()}
                                                </textarea>
                                                <button
                                                    class="absolute top-2 right-2 p-1 bg-white border border-gray-300 rounded hover:bg-gray-50 opacity-0 group-hover:opacity-100 transition shadow-sm"
                                                    title="Copy"
                                                    on:click=move |_| { let _ = web_sys::window().unwrap().navigator().clipboard().write_text(&cert); }
                                                >
                                                    "📋"
                                                </button>
                                            </div>
                                            <p class="mt-2 text-xs text-green-700">
                                                "Save this as 'id_ed25519-cert.pub' alongside your private key."
                                            </p>
                                        </div>
                                    }
                                }}
                            </Show>
                        </div>
                    </Show>

                    <Show when=move || active_tab.get() == "ca">
                        <div class="space-y-4 max-w-2xl">
                            <h3 class="text-lg font-medium text-gray-900">"Certificate Authority"</h3>

                            <Show
                                when=move || ca_key.get().is_some()
                                fallback=move || view! {
                                    <div class="p-4 bg-yellow-50 text-yellow-800 rounded-md border border-yellow-200 mb-4">
                                        "CA is not configured."
                                    </div>
                                }
                            >
                                {move || {
                                    let key = ca_key.get().unwrap();
                                    view! {
                                        <div class="space-y-1">
                                            <label class="block text-sm font-medium text-gray-700">"CA Public Key"</label>
                                            <div class="text-xs font-mono bg-gray-50 p-3 rounded border border-gray-200 break-all select-all">
                                                {key}
                                            </div>
                                            <p class="text-xs text-gray-500 mt-1">
                                                "Add this line to your servers' /etc/ssh/sshd_config as TrustedUserCAKeys."
                                            </p>
                                        </div>
                                    }
                                }}
                            </Show>

                            <div class="pt-4 border-t border-gray-100">
                                <h4 class="text-sm font-medium text-gray-900 mb-2">"Actions"</h4>
                                <Button
                                    loading=ca_loading
                                    variant=crate::components::ButtonVariant::Outline
                                    on_click=Box::new(generate_ca_action)
                                >
                                    {move || if ca_key.get().is_some() { "Rotate CA Key" } else { "Generate CA Key" }}
                                </Button>
                                <p class="text-xs text-red-500 mt-2">
                                    "Warning: Rotating the CA key will invalidate all previously signed certificates."
                                </p>
                            </div>

                            <Show when=move || ca_error.get().is_some()>
                                <div class="p-4 rounded-md bg-red-50 text-red-700 text-sm">
                                    {move || ca_error.get()}
                                </div>
                            </Show>
                        </div>
                    </Show>
                </div>
            </Card>
        </div>
    }
}
