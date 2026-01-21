use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_navigate};
use leptos_router::components::A;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::modal::Modal;
use crate::components::card::Card;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecretData {
    #[serde(flatten)]
    fields: HashMap<String, serde_json::Value>,
}

#[component]
pub fn SecretsList() -> impl IntoView {
    let params = use_params_map();
    let navigate = use_navigate();

    // Derived path from router
    let path = move || {
        params.with(|p| p.get("path").unwrap_or_default())
    };

    let secret_resource = LocalResource::new(
        move || {
            let current_path = path();
            async move {
                let url = if current_path.is_empty() {
                    "/secrets/data/".to_string()
                } else {
                    format!("/secrets/data/{}", current_path)
                };

                api::get::<serde_json::Value>(&url).await
            }
        },
    );

    let (show_modal, set_show_modal) = signal(false);
    let (edit_key, set_edit_key) = signal("".to_string());
    let (edit_value, set_edit_value) = signal("".to_string());
    let (new_secret_path, set_new_secret_path) = signal("".to_string());

    let navigate_save = navigate.clone();
    let handle_save = move || {
        let current_path = path();
        let navigate = navigate_save.clone();
        spawn_local(async move {
            let target_path = if current_path.is_empty() {
                new_secret_path.get()
            } else {
                current_path.clone()
            };

            if target_path.is_empty() {
                return;
            }

            let mut map = HashMap::new();
            map.insert(edit_key.get(), edit_value.get());

            let payload = serde_json::json!({
                "data": map
            });

            let url = format!("/secrets/data/{}", target_path);
            if let Ok(_) = api::post::<serde_json::Value, _>(&url, payload).await {
                set_show_modal.set(false);
                set_edit_key.set("".to_string());
                set_edit_value.set("".to_string());
                set_new_secret_path.set("".to_string());
                secret_resource.refetch();

                if current_path.is_empty() {
                    navigate(&format!("/secrets/{}", target_path), Default::default());
                }
            }
        });
    };

    let navigate_delete = navigate.clone();
    let handle_delete = move || {
        let current_path = path();
        if current_path.is_empty() { return; }

        let confirm = web_sys::window().unwrap().confirm_with_message(&format!("Delete secret at {}?", current_path)).unwrap_or(false);
        if !confirm { return; }

        let navigate = navigate_delete.clone();
        spawn_local(async move {
            let url = format!("/secrets/data/{}", current_path);
            let _ = api::delete::<serde_json::Value>(&url).await;
            navigate("/secrets", Default::default());
        });
    };

    let handle_save_modal = handle_save.clone();
    let handle_delete_btn = handle_delete.clone();

    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <div class="flex flex-col">
                    <h1 class="text-3xl font-bold text-gray-900">"Secrets"</h1>
                    <div class="flex items-center gap-1 text-sm text-gray-500 mt-1 font-mono bg-gray-100 px-2 py-1 rounded w-fit">
                        <A href="/secrets" attr:class="hover:text-blue-600 hover:underline">"root"</A>
                        {move || {
                            let p = path();
                            if !p.is_empty() {
                                view! {
                                    <span>"/"</span>
                                    <span class="font-bold text-gray-800">{p}</span>
                                }.into_any()
                            } else {
                                view! {}.into_any()
                            }
                        }}
                    </div>
                </div>
                <div class="flex gap-2">
                    <Button
                        variant=ButtonVariant::Primary
                        on_click=Box::new(move |_| set_show_modal.set(true))
                    >
                        {move || if path().is_empty() { "Create Secret" } else { "Add Key/Value" }}
                    </Button>
                    <Show when=move || !path().is_empty()>
                        {
                            let handle_delete = handle_delete_btn.clone();
                            view! {
                                <Button
                                    variant=ButtonVariant::Danger
                                    on_click=Box::new(move |_| handle_delete())
                                >
                                    "Delete Secret"
                                </Button>
                            }
                        }
                    </Show>
                </div>
            </header>

            <Suspense fallback=|| view! { <div class="flex justify-center p-12"><div class="animate-spin h-8 w-8 border-4 border-blue-500 rounded-full border-t-transparent"></div></div> }>
                {move || {
                    secret_resource.get().map(|res| {
                        match res {
                            Ok(data) => {
                                let data = data.clone();
                                match data {
                                    serde_json::Value::Object(map) => {
                                        if map.is_empty() {
                                             view! {
                                                <Card>
                                                    <div class="text-center py-8 text-gray-500">
                                                        "No data found at this path. Create a secret to get started."
                                                    </div>
                                                </Card>
                                             }.into_any()
                                        } else {
                                            view! {
                                                <div class="grid gap-4">
                                                    {map.iter().map(|(k, v)| {
                                                        let val_str = if v.is_string() { v.as_str().unwrap().to_string() } else { v.to_string() };
                                                        view! {
                                                            <div class="bg-white p-4 rounded shadow-sm border border-gray-200 flex justify-between items-center hover:bg-gray-50 transition">
                                                                <div class="font-mono text-sm font-medium text-gray-700">{k.clone()}</div>
                                                                <div class="font-mono text-sm bg-gray-100 px-2 py-1 rounded text-gray-800 select-all">{val_str}</div>
                                                            </div>
                                                        }
                                                    }).collect_view()}
                                                </div>
                                            }.into_any()
                                        }
                                    },
                                    _ => view! {
                                        <Card>
                                            <div class="p-4 font-mono text-sm whitespace-pre-wrap">{data.to_string()}</div>
                                        </Card>
                                    }.into_any()
                                }
                            },
                            Err(e) => {
                                let error_msg = e.to_string();
                                view! {
                                    <div class="p-8 text-center bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
                                        <p class="text-gray-500">"No secret found at this path."</p>
                                        <p class="text-xs text-gray-400 mt-2">{error_msg}</p>
                                    </div>
                                }.into_any()
                            }
                        }
                    })
                }}
            </Suspense>

            <Modal
                show=show_modal
                on_close=move || set_show_modal.set(false)
                title=if path().is_empty() { "Create New Secret".to_string() } else { "Add Key-Value Pair".to_string() }
            >
                {
                    let handle_save = handle_save_modal.clone();
                    view! {
                        <div class="space-y-4">
                            <Show when=move || path().is_empty()>
                                 <Input
                                    label="Path (e.g. my-app/config)".to_string()
                                    placeholder="path/to/secret".to_string()
                                    value=new_secret_path
                                    on_input=Box::new(move |v| set_new_secret_path.set(v))
                                />
                            </Show>

                            <div class="grid grid-cols-2 gap-4">
                                <Input
                                    label="Key".to_string()
                                    placeholder="API_KEY".to_string()
                                    value=edit_key
                                    on_input=Box::new(move |v| set_edit_key.set(v))
                                />
                                <Input
                                    label="Value".to_string()
                                    placeholder="secret-value-123".to_string()
                                    value=edit_value
                                    type_="password".to_string()
                                    on_input=Box::new(move |v| set_edit_value.set(v))
                                />
                            </div>

                            <div class="flex justify-end pt-4">
                                <Button
                                    variant=ButtonVariant::Primary
                                    on_click=Box::new(move |_| handle_save())
                                >
                                    "Save Secret"
                                </Button>
                            </div>
                        </div>
                    }
                }
            </Modal>
        </div>
    }
}
