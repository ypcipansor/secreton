use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use crate::components::{Button, Card, Input};
use crate::api::{post, get, delete};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key: String,
    pub issuer: Option<String>,
    pub account_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CodeResponse {
    pub code: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

#[component]
pub fn TotpPage() -> impl IntoView {
    // List State
    let (keys, set_keys) = signal(Vec::<String>::new());
    let (loading_keys, set_loading_keys) = signal(false);

    // Create State
    let (new_key_name, set_new_key_name) = signal("".to_string());
    let (new_key_secret, set_new_key_secret) = signal("".to_string());
    let (new_key_issuer, set_new_key_issuer) = signal("Secreton".to_string());
    let (create_msg, set_create_msg) = signal(Option::<String>::None);

    // Code Generation State
    let (generated_codes, set_generated_codes) = signal(std::collections::HashMap::<String, String>::new());

    let fetch_keys = move || {
        set_loading_keys.set(true);
        spawn_local(async move {
            match get::<ListKeysResponse>("/totp/keys").await {
                Ok(res) => set_keys.set(res.keys),
                Err(_) => set_keys.set(vec![]),
            }
            set_loading_keys.set(false);
        });
    };

    fetch_keys();

    let create_action = move |_| {
        let name = new_key_name.get();
        let secret = new_key_secret.get();
        let issuer = new_key_issuer.get();

        if name.is_empty() || secret.is_empty() {
            set_create_msg.set(Some("Name and Secret are required".to_string()));
            return;
        }

        spawn_local(async move {
            let req = CreateKeyRequest {
                key: secret,
                issuer: Some(issuer),
                account_name: Some(name.clone()),
            };

            match post::<String, _>(&format!("/totp/keys/{}", name), req).await {
                Ok(_) => {
                    set_create_msg.set(Some("Key created".to_string()));
                    set_new_key_name.set("".to_string());
                    set_new_key_secret.set("".to_string());
                    fetch_keys();
                }
                Err(e) => set_create_msg.set(Some(format!("Error: {}", e))),
            }
        });
    };

    let delete_action = move |name: String| {
        spawn_local(async move {
            let _ = delete::<String>(&format!("/totp/keys/{}", name)).await;
            fetch_keys();
        });
    };

    let generate_action = move |name: String| {
        spawn_local(async move {
            match get::<CodeResponse>(&format!("/totp/code/{}", name)).await {
                Ok(res) => {
                    set_generated_codes.update(|map| {
                        map.insert(name, res.code);
                    });
                }
                Err(_) => {}
            }
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold text-gray-900">"TOTP Engine"</h1>
                <div class="flex space-x-2">
                    <span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">"BETA"</span>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                // Create Key Form
                <div class="lg:col-span-1">
                    <Card>
                        <div class="p-6 space-y-4">
                            <h3 class="text-lg font-medium text-gray-900">"Add TOTP Key"</h3>
                            <Input
                                label="Key Name"
                                value=new_key_name
                                on_input=Box::new(move |v| set_new_key_name.set(v))
                                placeholder="e.g. my-server-mfa"
                            />
                            <Input
                                label="Secret (Base32)"
                                value=new_key_secret
                                on_input=Box::new(move |v| set_new_key_secret.set(v))
                                placeholder="JBSWY3DPEHPK3PXP"
                            />
                            <Input
                                label="Issuer"
                                value=new_key_issuer
                                on_input=Box::new(move |v| set_new_key_issuer.set(v))
                            />
                            <div class="pt-2">
                                <Button on_click=Box::new(create_action)>"Add Key"</Button>
                            </div>
                            <Show when=move || create_msg.get().is_some()>
                                <div class="p-2 text-sm text-gray-600 bg-gray-50 rounded">
                                    {move || create_msg.get()}
                                </div>
                            </Show>
                        </div>
                    </Card>
                </div>

                // List Keys
                <div class="lg:col-span-2">
                    <Card>
                        <div class="p-6">
                            <div class="flex justify-between items-center mb-4">
                                <h3 class="text-lg font-medium text-gray-900">"Managed Keys"</h3>
                                <button
                                    class="text-sm text-blue-600 hover:text-blue-800"
                                    on:click=move |_| fetch_keys()
                                >
                                    "Refresh"
                                </button>
                            </div>

                            <div class="space-y-3">
                                {move || {
                                    let list = keys.get();
                                    if list.is_empty() {
                                        view! { <p class="text-gray-500 italic">"No keys found."</p> }.into_any()
                                    } else {
                                        view! {
                                            <ul class="divide-y divide-gray-100">
                                                {list.into_iter().map(|k| {
                                                    let k_clone = k.clone();
                                                    let k_del = k.clone();
                                                    let k_gen = k.clone();
                                                    view! {
                                                        <li class="py-3 flex justify-between items-center">
                                                            <div>
                                                                <span class="font-medium text-gray-800">{k_clone.clone()}</span>
                                                                <div class="mt-1 h-6">
                                                                    {move || {
                                                                        let codes = generated_codes.get();
                                                                        if let Some(code) = codes.get(&k_clone) {
                                                                            view! {
                                                                                <span class="text-xl font-mono font-bold text-blue-600 tracking-widest">
                                                                                    {code.clone()}
                                                                                </span>
                                                                            }.into_any()
                                                                        } else {
                                                                            view! { <span class="text-xs text-gray-400">"Click generate"</span> }.into_any()
                                                                        }
                                                                    }}
                                                                </div>
                                                            </div>
                                                            <div class="flex gap-2">
                                                                <Button
                                                                    variant=crate::components::ButtonVariant::Outline
                                                                    class="px-3 py-1 text-xs"
                                                                    on_click=Box::new(move |_| generate_action(k_gen.clone()))
                                                                >
                                                                    "Generate"
                                                                </Button>
                                                                <button
                                                                    class="text-red-500 hover:text-red-700 px-2"
                                                                    on:click=move |_| delete_action(k_del.clone())
                                                                >
                                                                    "🗑️"
                                                                </button>
                                                            </div>
                                                        </li>
                                                    }
                                                }).collect::<Vec<_>>()}
                                            </ul>
                                        }.into_any()
                                    }
                                }}
                            </div>
                        </div>
                    </Card>
                </div>
            </div>
        </div>
    }
}
