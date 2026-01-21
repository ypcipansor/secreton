use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::card::Card;
use crate::components::modal::Modal;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InitResponse {
    keys: Vec<String>,
    keys_base64: Vec<String>,
    root_token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct UnsealResponse {
    sealed: bool,
    t: usize,
    n: usize,
    progress: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SealStatus {
    status: String,
    initialized: bool,
    sealed: bool,
    version: String,
}

#[derive(Clone, Debug, Serialize)]
struct InitRequest {
    shares: u8,
    threshold: u8,
}

#[derive(Clone, Debug, Serialize)]
struct UnsealRequest {
    key: String,
}

#[component]
pub fn SystemManagement() -> impl IntoView {
    // Resources
    let status_resource = LocalResource::new(|| async move {
        api::get::<SealStatus>("/sys/health").await
    });

    let unseal_status_resource = LocalResource::new(|| async move {
        api::get::<UnsealResponse>("/sys/seal-status").await
    });

    // States
    let (shares, set_shares) = signal("5".to_string());
    let (threshold, set_threshold) = signal("3".to_string());
    let (unseal_key, set_unseal_key) = signal("".to_string());

    // Init Result Modal
    let (show_init_modal, set_show_init_modal) = signal(false);
    let (init_result, set_init_result) = signal::<Option<InitResponse>>(None);

    // Actions
    let handle_init = move || {
        let s = shares.get().parse::<u8>().unwrap_or(5);
        let t = threshold.get().parse::<u8>().unwrap_or(3);

        spawn_local(async move {
            let req = InitRequest { shares: s, threshold: t };
            match api::post::<InitResponse, _>("/sys/init", req).await {
                Ok(res) => {
                    set_init_result.set(Some(res));
                    set_show_init_modal.set(true);
                    status_resource.refetch();
                    unseal_status_resource.refetch();
                },
                Err(e) => {
                    web_sys::window().unwrap().alert_with_message(&format!("Initialization failed: {}", e)).unwrap();
                }
            }
        });
    };

    let handle_unseal = move || {
        let key = unseal_key.get().trim().to_string();
        if key.is_empty() { return; }

        spawn_local(async move {
            let req = UnsealRequest { key };
            match api::post::<UnsealResponse, _>("/sys/unseal", req).await {
                Ok(_) => {
                    set_unseal_key.set("".to_string());
                    status_resource.refetch();
                    unseal_status_resource.refetch();
                },
                Err(e) => {
                    web_sys::window().unwrap().alert_with_message(&format!("Unseal failed: {}", e)).unwrap();
                }
            }
        });
    };

    let handle_seal = move || {
        if !web_sys::window().unwrap().confirm_with_message("Are you sure you want to SEAL the vault? All services will stop.").unwrap_or(false) {
            return;
        }

        spawn_local(async move {
            // Using raw request or ignoring response since it returns 204
            let _ = api::post::<serde_json::Value, _>("/sys/seal", serde_json::Value::Null).await;
            status_resource.refetch();
            unseal_status_resource.refetch();
        });
    };

    view! {
        <div class="space-y-8">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"System Management"</h1>
                <p class="text-gray-500 text-sm mt-1">"Manage Vault lifecycle, initialization and sealing."</p>
            </header>

            // Main Status Card
            <Suspense fallback=|| view! { <div class="animate-pulse h-32 bg-gray-200 rounded"></div> }>
                {move || {
                    status_resource.get().map(|res| {
                         match res {
                            Ok(status) => {
                                view! {
                                    <div class="grid gap-6 md:grid-cols-3">
                                        <Card>
                                            <div class="text-sm font-medium text-gray-500 uppercase">"Status"</div>
                                            <div class="mt-2 flex items-center gap-2">
                                                {if !status.initialized {
                                                    view! { <span class="text-2xl font-bold text-orange-600">"Uninitialized"</span> }
                                                } else if status.sealed {
                                                    view! { <span class="text-2xl font-bold text-red-600">"Sealed"</span> }
                                                } else {
                                                    view! { <span class="text-2xl font-bold text-green-600">"Active"</span> }
                                                }}
                                            </div>
                                        </Card>
                                        <Card>
                                            <div class="text-sm font-medium text-gray-500 uppercase">"Version"</div>
                                            <div class="mt-2 text-2xl font-bold text-gray-900">{status.version}</div>
                                        </Card>
                                        <Card>
                                             <div class="text-sm font-medium text-gray-500 uppercase">"Server Time"</div>
                                             <div class="mt-2 text-lg font-mono text-gray-700">"UTC"</div>
                                        </Card>
                                    </div>

                                    // Action Area
                                    <div class="mt-8">
                                        {if !status.initialized {
                                            view! {
                                                <Card title="Initialize Vault".to_string()>
                                                    <div class="max-w-md space-y-4">
                                                        <p class="text-gray-600">"This vault is not initialized. Please set the number of key shares and the threshold required to unseal."</p>
                                                        <div class="grid grid-cols-2 gap-4">
                                                            <Input label="Key Shares".to_string() value=shares on_input=Box::new(move |v| set_shares.set(v)) type_="number".to_string() />
                                                            <Input label="Threshold".to_string() value=threshold on_input=Box::new(move |v| set_threshold.set(v)) type_="number".to_string() />
                                                        </div>
                                                        <Button variant=ButtonVariant::Primary on_click=Box::new(move |_| handle_init())>
                                                            "Initialize Vault"
                                                        </Button>
                                                    </div>
                                                </Card>
                                            }.into_any()
                                        } else if status.sealed {
                                            view! {
                                                <Card title="Unseal Vault".to_string()>
                                                    <div class="max-w-md space-y-6">
                                                        <Suspense fallback=|| view! { "Loading status..." }>
                                                            {move || unseal_status_resource.get().map(|r| {
                                                                if let Ok(us) = r {
                                                                    let pct = if us.t > 0 { (us.progress as f64 / us.t as f64) * 100.0 } else { 0.0 };
                                                                    view! {
                                                                        <div>
                                                                            <div class="flex justify-between text-sm font-medium text-gray-700 mb-1">
                                                                                <span>"Progress"</span>
                                                                                <span>{us.progress} " / " {us.t} " (" {us.n} " shares)"</span>
                                                                            </div>
                                                                            <div class="w-full bg-gray-200 rounded-full h-2.5">
                                                                                <div class="bg-blue-600 h-2.5 rounded-full transition-all duration-500" style=format!("width: {}%", pct)></div>
                                                                            </div>
                                                                        </div>
                                                                    }.into_any()
                                                                } else {
                                                                    view! {}.into_any()
                                                                }
                                                            })}
                                                        </Suspense>

                                                        <div class="space-y-4">
                                                            <Input
                                                                label="Unseal Key Share".to_string()
                                                                placeholder="Paste key share (hex or base64)".to_string()
                                                                value=unseal_key
                                                                on_input=Box::new(move |v| set_unseal_key.set(v))
                                                                type_="password".to_string()
                                                            />
                                                            <Button variant=ButtonVariant::Primary on_click=Box::new(move |_| handle_unseal())>
                                                                "Submit Share"
                                                            </Button>
                                                        </div>
                                                    </div>
                                                </Card>
                                            }.into_any()
                                        } else {
                                            view! {
                                                 <Card title="Vault Operations".to_string()>
                                                    <div class="space-y-4">
                                                        <p class="text-gray-600">"The vault is currently active and operational. Sealing the vault will stop all operations and clear the master key from memory."</p>
                                                        <Button variant=ButtonVariant::Danger on_click=Box::new(move |_| handle_seal())>
                                                            "Seal Vault"
                                                        </Button>
                                                    </div>
                                                </Card>
                                            }.into_any()
                                        }}
                                    </div>
                                }.into_any()
                            },
                            Err(e) => view! {
                                <div class="bg-red-50 text-red-700 p-4 rounded border border-red-200">
                                    "Error connecting to system API: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>

            // Initialization Result Modal
            <Modal
                show=show_init_modal
                on_close=move || set_show_init_modal.set(false)
                title="Initialization Successful".to_string()
            >
                <div class="space-y-4">
                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                        <div class="flex">
                            <div class="flex-shrink-0">
                                <span class="text-xl">"⚠️"</span>
                            </div>
                            <div class="ml-3">
                                <p class="text-sm text-yellow-700">
                                    "Save these keys immediately! They are the ONLY way to unseal your vault. They will NOT be shown again."
                                </p>
                            </div>
                        </div>
                    </div>

                    {move || init_result.get().map(|res| {
                        view! {
                            <div class="space-y-4">
                                <div>
                                    <h4 class="text-sm font-bold text-gray-900 uppercase tracking-wide mb-2">"Root Token"</h4>
                                    <div class="flex gap-2">
                                        <code class="block w-full bg-gray-800 text-green-400 p-3 rounded font-mono text-xs break-all select-all">
                                            {res.root_token.clone()}
                                        </code>
                                        <button
                                            class="bg-gray-100 hover:bg-gray-200 px-3 rounded border border-gray-300 text-sm"
                                            on:click=move |_| { let _ = web_sys::window().unwrap().navigator().clipboard().write_text(&res.root_token); }
                                        >
                                            "Copy"
                                        </button>
                                    </div>
                                </div>

                                <div>
                                    <h4 class="text-sm font-bold text-gray-900 uppercase tracking-wide mb-2">"Unseal Shares"</h4>
                                    <div class="space-y-2">
                                        {res.keys.iter().enumerate().map(|(i, key)| {
                                            let k = key.clone();
                                            view! {
                                                <div class="flex items-center gap-2">
                                                    <span class="text-xs text-gray-500 w-6 font-mono">"#" {i + 1}</span>
                                                    <code class="flex-1 bg-gray-100 p-2 rounded font-mono text-xs break-all select-all border border-gray-200 text-gray-800">
                                                        {k.clone()}
                                                    </code>
                                                </div>
                                            }
                                        }).collect_view()}
                                    </div>
                                </div>
                            </div>
                        }
                    })}

                    <div class="flex justify-end pt-4">
                        <Button
                            variant=ButtonVariant::Primary
                            on_click=Box::new(move |_| set_show_init_modal.set(false))
                        >
                            "I have safely saved these keys"
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
