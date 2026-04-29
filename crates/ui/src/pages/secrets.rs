use leptos::prelude::*;
use leptos_router::hooks::{use_params_map, use_navigate};
use leptos_router::components::A;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::Modal;
use crate::components::Card;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecretListItem {
    path: String,
    // Other fields ignored for now
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct GetSecretResponse {
    data: serde_json::Value,
    version: u32,
    #[serde(default)]
    expires_at: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct SecretVersionInfo {
    version: u32,
    created_at: String,
}

#[derive(Clone, Debug)]
enum SecretViewMode {
    List(Vec<String>),
    View {
        data: serde_json::Value,
        version: u32,
        expires_at: Option<String>,
    },
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
    let path = move || {
        params.with(|p| p.get("path").unwrap_or_default())
    };

    // View specific version state
    let (view_version, set_view_version) = signal::<Option<u32>>(None);

    let path_for_reset = path.clone();
    Effect::new(move || {
        let _ = path_for_reset(); // subscribe to path changes
        set_view_version.set(None);
    });

    let secret_resource = LocalResource::new(
        move || {
            let current_path = path();
            let version_opt = view_version.get();

            async move {
                // If root, always list
                if current_path.is_empty() {
                    let url = "/secret/secrets";
                    match api::get::<Vec<SecretListItem>>(url).await {
                        Ok(res) => {
                            let keys = res.into_iter().map(|item| item.path).collect();
                            return SecretViewMode::List(keys);
                        },
                        Err(e) => return SecretViewMode::Error(e.to_string()),
                    }
                }

                // Try to get as secret first
                let secret_url = if let Some(v) = version_opt {
                    format!("/secret/secrets/{}?version={}", current_path, v)
                } else {
                    format!("/secret/secrets/{}", current_path)
                };

                match api::get::<GetSecretResponse>(&secret_url).await {
                    Ok(secret) => {
                         SecretViewMode::View {
                            data: secret.data,
                            version: secret.version,
                            expires_at: secret.expires_at,
                         }
                    },
                    Err(api::ApiError::NotFound(_)) => {
                        // If specific version requested and not found, it's an error (or deleted history)
                        if version_opt.is_some() {
                            return SecretViewMode::Error("Version not found".to_string());
                        }

                        // Only if 404 and no version specified, try to list as folder
                        // Note: Backend expects prefix to end with / for folders if we want robust filtering,
                        // but let's see how the backend handles 'app' vs 'app/'
                        // We'll append / to be safe for directory listing
                        let list_path = if current_path.ends_with('/') { current_path.clone() } else { format!("{}/", current_path) };
                        // Construct query param manually since api::get doesn't support query params helper yet
                        let list_url = format!("/secret/secrets?filter={}", list_path);

                        match api::get::<Vec<SecretListItem>>(&list_url).await {
                            Ok(res) => {
                                if res.is_empty() {
                                    SecretViewMode::NotFound
                                } else {
                                    let keys = res.into_iter().map(|item| item.path).collect();
                                    SecretViewMode::List(keys)
                                }
                            },
                            Err(e) => SecretViewMode::Error(format!("Error listing folder: {}", e)),
                        }
                    },
                    Err(e) => SecretViewMode::Error(e.to_string()),
                }
            }
        },
    );

    // Modal State
    let (show_modal, set_show_modal) = signal(false);
    let (show_history_modal, set_show_history_modal) = signal(false);
    let (history_versions, set_history_versions) = signal::<Vec<SecretVersionInfo>>(vec![]);
    let (new_secret_path, set_new_secret_path) = signal("".to_string());
    let (error_msg, set_error_msg) = signal::<Option<String>>(None);

    // Editor State (KV pairs)
    let (kv_rows, set_kv_rows) = signal::<Vec<KvRow>>(vec![]);
    let (next_id, set_next_id) = signal(0);

    // Helper to add a row
    let add_row = move || {
        set_kv_rows.update(|rows| {
            rows.push(KvRow { id: next_id.get(), key: "".to_string(), value: "".to_string() });
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

    // Helper to load history
    let load_history = move || {
        spawn_local(async move {
            let path = path();
            let url = format!("/secret/secret-versions/{}", path);
            if let Ok(res) = api::get::<Vec<SecretVersionInfo>>(&url).await {
                set_history_versions.set(res);
                set_show_history_modal.set(true);
            }
        });
    };

    // Helper to load specific version
    let load_specific_version = move |v: u32| {
        // If the requested version is the latest version, clear the view_version
        // so it's treated as the current (editable) version.
        // The history list is sorted descending, so first is latest.
        let is_latest = history_versions.get().first().map_or(false, |latest| latest.version == v);

        if is_latest {
            set_view_version.set(None);
        } else {
            set_view_version.set(Some(v));
        }
        set_show_history_modal.set(false);
        secret_resource.refetch();
    };

    // Helper to rollback to a specific version
    let rollback_to_version = move |v: u32| {
        spawn_local(async move {
            let current_path = path();
            let confirm = web_sys::window().and_then(|w| w.confirm_with_message(&format!("Rollback secret at {} to version {}? This will create a new version with the historical data.", current_path, v)).ok()).unwrap_or(false);
            if !confirm { return; }

            // Call the specialized rollback endpoint
            let rollback_url = format!("/secret/secret-rollback/{}?version={}", current_path, v);

            match api::post::<serde_json::Value, _>(&rollback_url, serde_json::json!({})).await {
                Ok(_) => {
                    set_error_msg.set(None);
                    set_view_version.set(None);
                    set_show_history_modal.set(false);
                    secret_resource.refetch();
                }
                Err(e) => set_error_msg.set(Some(format!("Rollback failed: {:?}", e))),
            }
        });
    };

    // Helper to clear version view (show latest)
    let clear_version_view = move || {
        set_view_version.set(None);
        secret_resource.refetch();
    };

    // Open Modal for Create (New)
    let open_create = move |_| {
        set_error_msg.set(None);
        set_new_secret_path.set("".to_string());
        set_kv_rows.set(vec![KvRow { id: 0, key: "".to_string(), value: "".to_string() }]);
        set_next_id.set(1);
        set_show_modal.set(true);
    };

    // Open Modal for Edit (Existing)
    let open_edit = move |_| {
        set_error_msg.set(None);
        if let Some(SecretViewMode::View { data, .. }) = secret_resource.get() {
             if let serde_json::Value::Object(map) = data {
                 let mut rows = Vec::new();
                 let mut id = 0;
                 for (k, v) in map {
                     let val_str = if v.is_string() { v.as_str().unwrap().to_string() } else { v.to_string() };
                     rows.push(KvRow { id, key: k.clone(), value: val_str });
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
        if (current_path.is_empty() || matches!(secret_resource.get(), Some(SecretViewMode::List(_)) | Some(SecretViewMode::NotFound))) && new_secret_path.get().is_empty() {
            set_error_msg.set(Some("Secret name cannot be empty".to_string()));
            return;
        }

        spawn_local(async move {
            // If we are creating new, use input path. If editing, use current path.
            let target_path = if current_path.is_empty() || matches!(secret_resource.get(), Some(SecretViewMode::List(_)) | Some(SecretViewMode::NotFound)) {
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

            let url = format!("/secret/secrets/{}", target_path);

            // Distinguish between create (POST) and update (PUT)
            // If target_path matches current_path AND we are in View mode, it's an edit.
            let is_edit = target_path == current_path && matches!(secret_resource.get(), Some(SecretViewMode::View { .. }));

            let result = if is_edit {
                api::put::<serde_json::Value, _>(&url, payload).await
            } else {
                api::post::<serde_json::Value, _>(&url, payload).await
            };

            match result {
                Ok(_) => {
                    set_error_msg.set(None);
                    set_show_modal.set(false);
                    secret_resource.refetch();

                    // If we created a new secret, navigate to it
                    if target_path != current_path {
                         navigate(&format!("/secrets/{}", target_path), Default::default());
                    }
                }
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to save secret: {:?}", e)));
                }
            }
        });
    };

    let navigate_delete = navigate.clone();
    let handle_delete = move || {
        let current_path = path();
        if current_path.is_empty() { return; }

        let confirm = web_sys::window().and_then(|w| w.confirm_with_message(&format!("Delete secret at {}?", current_path)).ok()).unwrap_or(false);
        if !confirm { return; }

        let navigate = navigate_delete.clone();
        spawn_local(async move {
            let url = format!("/secret/secrets/{}", current_path);
            let _ = api::delete::<serde_json::Value>(&url).await;

            // Navigate up one level
            let parts: Vec<&str> = current_path.split('/').collect();
            if parts.len() > 1 {
                 let parent = parts[0..parts.len()-1].join("/");
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
                        if let Some(SecretViewMode::View { .. }) = secret_resource.get() {
                            let handle_delete = handle_delete.clone();
                            let open_edit = open_edit.clone();
                            let load_history = load_history.clone();
                            view! {
                                <Button variant=ButtonVariant::Secondary on_click=Box::new(move |_| load_history())>
                                    "History"
                                </Button>
                                <Show when=move || view_version.get().is_none()>
                                    <Button variant=ButtonVariant::Primary on_click=Box::new({
                                        let open_edit = open_edit.clone();
                                        move |_| open_edit(())
                                    })>
                                        "Edit Secret"
                                    </Button>
                                    <Button variant=ButtonVariant::Danger on_click=Box::new({
                                        let handle_delete = handle_delete.clone();
                                        move |_| handle_delete()
                                    })>
                                        "Delete Secret"
                                    </Button>
                                </Show>
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
                            SecretViewMode::View { data, version, expires_at } => {
                                match data {
                                    serde_json::Value::Object(map) => {
                                        view! {
                                            <div class="space-y-4">
                                                <Show when=move || view_version.get().is_some()>
                                                    <div class="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                                                        <div class="flex items-center justify-between">
                                                            <div class="flex">
                                                                <div class="ml-3">
                                                                    <p class="text-sm text-yellow-700">
                                                                        "You are viewing a past version of this secret (v" {version} ")."
                                                                    </p>
                                                                </div>
                                                            </div>
                                                            <button class="text-sm font-medium underline text-yellow-700 hover:text-yellow-600" on:click=move |_| clear_version_view()>
                                                                "View Latest"
                                                            </button>
                                                        </div>
                                                    </div>
                                                </Show>
                                                <div class="flex justify-between items-center text-xs uppercase font-bold tracking-wider mb-2">
                                                    <div class="flex gap-4">
                                                        <span class="text-blue-600 bg-blue-50 px-2 py-0.5 rounded border border-blue-100">
                                                            {format!("Version: {}", version)}
                                                        </span>
                                                        // Integration status placeholder
                                                        <span class="text-gray-400">"AWS: Not Synced"</span>
                                                    </div>
                                                    <div class="flex items-center gap-2">
                                                        <span class="text-gray-500">"Expires: "</span>
                                                        <span class="text-gray-700 font-mono lowercase">
                                                            {move || expires_at.clone().unwrap_or_else(|| "Never".to_string())}
                                                        </span>
                                                        // NOTE: "Extend +30d" button removed until the
                                                        // `/lifecycle/extend/*` backend route is mounted and
                                                        // authenticated.  Re-add once the lifecycle handler
                                                        // module is wired into the API router and updates the
                                                        // storage-level `expires_at` (not just the in-memory
                                                        // lifecycle manager).
                                                        <span class="ml-2 text-gray-300 normal-case font-medium" title="Extend TTL is not yet available">
                                                            "Extend (coming soon)"
                                                        </span>
                                                    </div>
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
                                                                        on:click=move |_| { if let Some(w) = web_sys::window() { let _ = w.navigator().clipboard().write_text(&val_str); } }
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
                show=show_history_modal
                on_close=move || {
                    set_error_msg.set(None);
                    set_show_history_modal.set(false);
                }
                title="Secret History".to_string()
            >
                <Show when=move || error_msg.get().is_some()>
                    <div class="bg-red-50 text-red-700 p-3 rounded mb-4 text-sm">
                        {move || error_msg.get().unwrap_or_default()}
                    </div>
                </Show>
                <div class="max-h-[60vh] overflow-y-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Version"</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Created At"</th>
                                <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">"Action"</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {move || history_versions.get().into_iter().enumerate().map(|(idx, v)| {
                                let ver = v.version;
                                let is_latest = idx == 0;
                                view! {
                                    <tr>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{v.version}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{v.created_at}</td>
                                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-3">
                                            <button
                                                class="text-blue-600 hover:text-blue-900"
                                                on:click=move |_| load_specific_version(ver)
                                            >
                                                "View"
                                            </button>
                                            {if !is_latest {
                                                view! {
                                                    <button
                                                        class="text-orange-600 hover:text-orange-900"
                                                        on:click=move |_| rollback_to_version(ver)
                                                    >
                                                        "Rollback"
                                                    </button>
                                                }.into_any()
                                            } else {
                                                view! {}.into_any()
                                            }}
                                        </td>
                                    </tr>
                                }
                            }).collect_view()}
                        </tbody>
                    </table>
                </div>
            </Modal>

            <Modal
                show=show_modal
                on_close=move || {
                    set_error_msg.set(None);
                    set_show_modal.set(false);
                }
                title=if matches!(secret_resource.get(), Some(SecretViewMode::View { .. })) {
                    format!("Edit Secret: {}", path())
                } else {
                    "Create New Secret".to_string()
                }
            >
                {
                    let handle_save = handle_save.clone();
                    view! {
                        <div class="space-y-4 max-h-[70vh] flex flex-col">
                             <Show when=move || error_msg.get().is_some()>
                                 <div class="bg-red-50 text-red-700 p-3 rounded mb-4 text-sm">
                                     {move || error_msg.get().unwrap_or_default()}
                                 </div>
                             </Show>
                             <Show when=move || !matches!(secret_resource.get(), Some(SecretViewMode::View { .. }))>
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
