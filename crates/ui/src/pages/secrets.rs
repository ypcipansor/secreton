use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::Card;
use crate::components::Modal;
use leptos::prelude::*;
use leptos::task::spawn_local;
use leptos_router::components::A;
use leptos_router::hooks::{use_navigate, use_params_map};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ListSecretsResponse {
    keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GetSecretResponse {
    data: serde_json::Value,
    version: u32,
}

#[derive(Clone, Debug)]
enum SecretViewMode {
    List(Vec<String>),
    View(serde_json::Value, u32), // data, version
    NotFound,
    Error(String),
}

#[derive(Clone, Debug)]
struct KvRow {
    id: usize,
    key: String,
    value: String,
}

#[component]
pub fn SecretsList() -> impl IntoView {
    let params = use_params_map();
    let navigate = use_navigate();

    // Derived path from router
    let path = move || params.with(|p| p.get("path").unwrap_or_default());

    let secret_resource = LocalResource::new(move || {
        let current_path = path();
        async move {
            // If root, always list
            if current_path.is_empty() {
                let url = "/kv/secrets";
                match api::get::<ListSecretsResponse>(url).await {
                    Ok(res) => return SecretViewMode::List(res.keys),
                    Err(e) => return SecretViewMode::Error(e.to_string()),
                }
            }

            // Try to get as secret first
            let secret_url = format!("/kv/secret/data/{}", current_path);
            match api::get::<GetSecretResponse>(&secret_url).await {
                Ok(secret) => SecretViewMode::View(secret.data, secret.version),
                Err(api::ApiError::NotFound(_)) => {
                    // Only if 404, try to list as folder
                    // Note: Backend expects prefix to end with / for folders if we want robust filtering,
                    // but let's see how the backend handles 'app' vs 'app/'
                    // We'll append / to be safe for directory listing
                    let list_path = if current_path.ends_with('/') {
                        current_path.clone()
                    } else {
                        format!("{}/", current_path)
                    };
                    // Construct query param manually since api::get doesn't support query params helper yet
                    let list_url = format!("/kv/secrets?path={}", list_path);

                    match api::get::<ListSecretsResponse>(&list_url).await {
                        Ok(res) => {
                            if res.keys.is_empty() {
                                SecretViewMode::NotFound
                            } else {
                                SecretViewMode::List(res.keys)
                            }
                        }
                        Err(e) => SecretViewMode::Error(format!("Error listing folder: {}", e)),
                    }
                }
                Err(e) => SecretViewMode::Error(e.to_string()),
            }
        }
    });

    // Modal State
    let (show_modal, set_show_modal) = signal(false);
    let (new_secret_path, set_new_secret_path) = signal("".to_string());

    // Editor State (KV pairs)
    let (kv_rows, set_kv_rows) = signal::<Vec<KvRow>>(vec![]);
    let (next_id, set_next_id) = signal(0);

    // Helper to add a row
    let add_row = move || {
        set_kv_rows.update(|rows| {
            rows.push(KvRow {
                id: next_id.get(),
                key: "".to_string(),
                value: "".to_string(),
            });
        });
        set_next_id.update(|n| *n += 1);
    };

    // Helper to remove a row
    let remove_row = move |id: usize| {
        set_kv_rows.update(|rows| {
            rows.retain(|r| r.id != id);
        });
    };

    // Helper to update a row
    let update_row_key = move |id: usize, val: String| {
        set_kv_rows.update(|rows| {
            if let Some(r) = rows.iter_mut().find(|r| r.id == id) {
                r.key = val;
            }
        });
    };

    let update_row_value = move |id: usize, val: String| {
        set_kv_rows.update(|rows| {
            if let Some(r) = rows.iter_mut().find(|r| r.id == id) {
                r.value = val;
            }
        });
    };

    // Open Modal for Create (New)
    let open_create = move |_| {
        set_new_secret_path.set("".to_string());
        set_kv_rows.set(vec![KvRow {
            id: 0,
            key: "".to_string(),
            value: "".to_string(),
        }]);
        set_next_id.set(1);
        set_show_modal.set(true);
    };

    // Open Modal for Edit (Existing)
    let open_edit = move |_| {
        if let Some(SecretViewMode::View(data, _)) = secret_resource.get() {
            if let serde_json::Value::Object(map) = data {
                let mut rows = Vec::new();
                let mut id = 0;
                for (k, v) in map {
                    let val_str = if v.is_string() {
                        v.as_str().unwrap().to_string()
                    } else {
                        v.to_string()
                    };
                    rows.push(KvRow {
                        id,
                        key: k.clone(),
                        value: val_str,
                    });
                    id += 1;
                }
                set_kv_rows.set(rows);
                set_next_id.set(id);
                set_new_secret_path.set("".to_string()); // Not used for edit
                set_show_modal.set(true);
            }
        }
    };

    let navigate_save = navigate.clone();
    let handle_save = move || {
        let current_path = path();
        let navigate = navigate_save.clone();

        // Validate new secret name if creating
        if (current_path.is_empty()
            || matches!(
                secret_resource.get(),
                Some(SecretViewMode::List(_)) | Some(SecretViewMode::NotFound)
            ))
            && new_secret_path.get().is_empty()
        {
            // TODO: Show error message
            return;
        }

        spawn_local(async move {
            // If we are creating new, use input path. If editing, use current path.
            let target_path = if current_path.is_empty()
                || matches!(
                    secret_resource.get(),
                    Some(SecretViewMode::List(_)) | Some(SecretViewMode::NotFound)
                ) {
                // If we are in a subfolder (List mode), we append the new secret name to current path
                if !current_path.is_empty() {
                    // Basic join logic
                    let suffix = new_secret_path.get();
                    if suffix.is_empty() {
                        return;
                    }
                    if current_path.ends_with('/') {
                        format!("{}{}", current_path, suffix)
                    } else {
                        format!("{}/{}", current_path, suffix)
                    }
                } else {
                    new_secret_path.get()
                }
            } else {
                current_path.clone()
            };

            if target_path.is_empty() {
                return;
            }

            let mut map = HashMap::new();
            // Collect rows
            for row in kv_rows.get() {
                if !row.key.is_empty() {
                    map.insert(row.key, row.value);
                }
            }

            let payload = serde_json::json!({
                "data": map
            });

            let url = format!("/kv/secret/data/{}", target_path);
            if (api::post::<serde_json::Value, _>(&url, payload).await).is_ok() {
                set_show_modal.set(false);
                secret_resource.refetch();

                // If we created a new secret, navigate to it
                if target_path != current_path {
                    navigate(&format!("/secrets/{}", target_path), Default::default());
                }
            }
        });
    };

    let navigate_delete = navigate.clone();
    let handle_delete = move || {
        let current_path = path();
        if current_path.is_empty() {
            return;
        }

        let confirm = web_sys::window()
            .unwrap()
            .confirm_with_message(&format!("Delete secret at {}?", current_path))
            .unwrap_or(false);
        if !confirm {
            return;
        }

        let navigate = navigate_delete.clone();
        spawn_local(async move {
            let url = format!("/kv/secret/data/{}", current_path);
            let _ = api::delete::<serde_json::Value>(&url).await;

            // Navigate up one level
            let parts: Vec<&str> = current_path.split('/').collect();
            if parts.len() > 1 {
                let parent = parts[0..parts.len() - 1].join("/");
                navigate(&format!("/secrets/{}", parent), Default::default());
            } else {
                navigate("/secrets", Default::default());
            }
        });
    };

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
                                // Split path and create breadcrumbs could be better, but simple for now
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
                    <Button variant=ButtonVariant::Primary on_click=Box::new(open_create)>
                        "Create Secret"
                    </Button>

                    {move || {
                        if let Some(SecretViewMode::View(_, _)) = secret_resource.get() {
                            let handle_delete = handle_delete.clone();
                            view! {
                                <Button variant=ButtonVariant::Primary on_click=Box::new(open_edit)>
                                    "Edit Secret"
                                </Button>
                                <Button variant=ButtonVariant::Danger on_click=Box::new(move |_| handle_delete())>
                                    "Delete Secret"
                                </Button>
                            }.into_any()
                        } else {
                             view! {}.into_any()
                        }
                    }}
                </div>
            </header>

            <Suspense fallback=|| view! { <div class="flex justify-center p-12"><div class="animate-spin h-8 w-8 border-4 border-blue-500 rounded-full border-t-transparent"></div></div> }>
                {move || {
                    secret_resource.get().map(|mode| {
                        match mode {
                            SecretViewMode::List(keys) => {
                                if keys.is_empty() {
                                     view! {
                                        <Card>
                                            <div class="text-center py-8 text-gray-500">
                                                "No secrets found in this folder."
                                            </div>
                                        </Card>
                                     }.into_any()
                                } else {
                                     let current = path();
                                     view! {
                                        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                            {keys.into_iter().map(|key| {
                                                let is_folder = true; // In this naive implementation, we don't know for sure without checking trailing slash behavior of backend
                                                // Actually backend returns "folder" (no slash) usually with current impl, need to be careful.
                                                // But let's just link to it.

                                                let href = if current.is_empty() {
                                                    format!("/secrets/{}", key)
                                                } else if current.ends_with('/') {
                                                     format!("/secrets/{}{}", current, key)
                                                } else {
                                                     format!("/secrets/{}/{}", current, key)
                                                };

                                                view! {
                                                    <A href=href attr:class="block">
                                                        <div class="bg-white p-4 rounded shadow-sm border border-gray-200 hover:border-blue-500 hover:shadow-md transition flex items-center gap-3">
                                                            <div class="text-2xl text-gray-400">
                                                                // Use an icon or emoji
                                                                "📄"
                                                            </div>
                                                            <div class="font-mono font-medium text-gray-700 truncate">
                                                                {key}
                                                            </div>
                                                        </div>
                                                    </A>
                                                }
                                            }).collect_view()}
                                        </div>
                                     }.into_any()
                                }
                            },
                            SecretViewMode::View(data, version) => {
                                match data {
                                    serde_json::Value::Object(map) => {
                                        view! {
                                            <div class="space-y-4">
                                                <div class="flex justify-end text-xs text-gray-400 uppercase font-bold tracking-wider">
                                                    {format!("Version: {}", version)}
                                                </div>
                                                <div class="grid gap-4">
                                                    {map.iter().map(|(k, v)| {
                                                        let val_str = if v.is_string() { v.as_str().unwrap().to_string() } else { v.to_string() };
                                                        view! {
                                                            <div class="bg-white p-4 rounded shadow-sm border border-gray-200 flex flex-col md:flex-row md:items-center justify-between hover:bg-gray-50 transition group">
                                                                <div class="font-mono text-sm font-medium text-gray-700 mb-2 md:mb-0">{k.clone()}</div>
                                                                <div class="flex items-center gap-2 max-w-full">
                                                                     <div class="font-mono text-sm bg-gray-100 px-3 py-1.5 rounded text-gray-800 select-all overflow-hidden text-ellipsis whitespace-nowrap max-w-xs md:max-w-md lg:max-w-xl">
                                                                        {val_str.clone()}
                                                                     </div>
                                                                     <button
                                                                        class="text-gray-400 hover:text-blue-600 opacity-0 group-hover:opacity-100 transition px-2"
                                                                        title="Copy"
                                                                        on:click=move |_| { let _ = web_sys::window().unwrap().navigator().clipboard().write_text(&val_str); }
                                                                     >
                                                                        "📋"
                                                                     </button>
                                                                </div>
                                                            </div>
                                                        }
                                                    }).collect_view()}
                                                </div>
                                            </div>
                                        }.into_any()
                                    },
                                    _ => view! {
                                        <Card>
                                            <div class="p-4 font-mono text-sm whitespace-pre-wrap">{data.to_string()}</div>
                                        </Card>
                                    }.into_any()
                                }
                            },
                            SecretViewMode::NotFound => {
                                view! {
                                    <div class="p-12 text-center bg-gray-50 rounded-lg border-2 border-dashed border-gray-300">
                                        <p class="text-xl text-gray-600 font-semibold">"Nothing here"</p>
                                        <p class="text-gray-500 mt-2 mb-6">"This path does not exist as a secret or a folder."</p>
                                        <Button variant=ButtonVariant::Primary on_click=Box::new(open_create)>
                                            "Create Secret Here"
                                        </Button>
                                    </div>
                                }.into_any()
                            },
                            SecretViewMode::Error(e) => {
                                view! {
                                    <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                                        <p class="font-bold">"Error loading secret"</p>
                                        <p class="text-sm font-mono mt-1">{e}</p>
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
                title=if matches!(secret_resource.get(), Some(SecretViewMode::View(_, _))) {
                    format!("Edit Secret: {}", path())
                } else {
                    "Create New Secret".to_string()
                }
            >
                {
                    let handle_save = handle_save.clone();
                    view! {
                        <div class="space-y-4 max-h-[70vh] flex flex-col">
                             <Show when=move || !matches!(secret_resource.get(), Some(SecretViewMode::View(_, _)))>
                                 <div class="bg-blue-50 p-3 rounded text-sm text-blue-800 mb-2">
                                    "Creating secret at: "
                                    <span class="font-mono font-bold">
                                        {move || {
                                            let p = path();
                                            if p.is_empty() { "root/".to_string() } else { format!("{}/", p) }
                                        }}
                                    </span>
                                 </div>
                                 <Input
                                    label="Secret Name".to_string()
                                    placeholder="my-secret".to_string()
                                    value=new_secret_path
                                    on_input=Box::new(move |v| set_new_secret_path.set(v))
                                />
                                <hr class="border-gray-200"/>
                            </Show>

                            <div class="flex-1 overflow-y-auto pr-2 space-y-3">
                                 <div class="flex justify-between items-center mb-2">
                                     <h4 class="text-sm font-bold text-gray-700 uppercase tracking-wide">"Key-Value Pairs"</h4>
                                     <button class="text-xs text-blue-600 hover:text-blue-800 font-medium" on:click=move |_| add_row() >
                                        "+ Add Row"
                                     </button>
                                 </div>

                                 {move || kv_rows.get().into_iter().map(|row| {
                                     let id = row.id;
                                     view! {
                                        <div class="flex gap-2 items-start bg-gray-50 p-2 rounded border border-gray-200">
                                            <div class="flex-1">
                                                <input
                                                    type="text"
                                                    class="w-full text-sm border-gray-300 rounded focus:ring-blue-500 focus:border-blue-500 font-mono"
                                                    placeholder="Key"
                                                    value=row.key
                                                    on:input=move |ev| update_row_key(id, event_target_value(&ev))
                                                />
                                            </div>
                                            <div class="flex-1">
                                                <input
                                                    type="text"
                                                    class="w-full text-sm border-gray-300 rounded focus:ring-blue-500 focus:border-blue-500 font-mono"
                                                    placeholder="Value"
                                                    value=row.value
                                                    on:input=move |ev| update_row_value(id, event_target_value(&ev))
                                                />
                                            </div>
                                            <button
                                                class="text-red-500 hover:text-red-700 px-1 mt-1.5"
                                                title="Remove"
                                                on:click=move |_| remove_row(id)
                                            >
                                                "✕"
                                            </button>
                                        </div>
                                     }
                                 }).collect_view()}
                            </div>

                            <div class="flex justify-end pt-4 border-t border-gray-100">
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
