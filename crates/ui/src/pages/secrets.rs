use leptos::*;
use leptos_router::*;
use crate::api;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[component]
pub fn SecretsList() -> impl IntoView {
    let params = use_params_map();

    // Derived path from router
    let path = move || {
        params.with(|p| p.get("path").cloned().unwrap_or_default())
    };

    // Fetch secret data
    let secret_resource = create_resource(
        path,
        |current_path| async move {
            let url = if current_path.is_empty() {
                "/secrets/data".to_string() // Root list? Or just /secrets/data/
            } else {
                format!("/secrets/data/{}", current_path)
            };

            api::get::<serde_json::Value>(&url).await
        },
    );

    // Form state for creating/updating
    let (key_input, set_key_input) = create_signal("".to_string());
    let (val_input, set_val_input) = create_signal("".to_string());
    let (is_editing, set_is_editing) = create_signal(false);

    let handle_save = move |_| {
        let current_path = path();
        spawn_local(async move {
            let mut map = HashMap::new();
            map.insert(key_input.get(), val_input.get());

            let payload = serde_json::json!({
                "data": map
            });

            // If it's a new secret or update
            let url = format!("/secrets/data/{}", current_path);
            let _ = api::post::<serde_json::Value, _>(&url, payload).await;
            set_is_editing.set(false);
            secret_resource.refetch();
        });
    };

    let handle_delete = move |_| {
        let current_path = path();
        if !web_sys::window().unwrap().confirm_with_message(&format!("Delete secret at {}?", current_path)).unwrap_or(false) {
            return;
        }

        spawn_local(async move {
            let url = format!("/secrets/data/{}", current_path);
            let _ = api::delete::<serde_json::Value>(&url).await;
             // Navigate up?
             // For now just refetch (might return 404)
             secret_resource.refetch();
        });
    };

    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Secrets"</h1>
                    <div class="flex items-center gap-2 text-sm text-gray-600 mt-1">
                        <A href="/secrets" class="hover:text-blue-600">"root"</A>
                        {move || {
                            let p = path();
                            if p.is_empty() {
                                view! {}.into_view()
                            } else {
                                view! {
                                    <span>"/"</span>
                                    <span class="font-mono">{p}</span>
                                }.into_view()
                            }
                        }}
                    </div>
                </div>
                <div class="flex gap-2">
                    <button
                        class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50 transition"
                        on:click=move |_| set_is_editing.set(true)
                    >
                        "Add/Update Secret"
                    </button>
                    <button
                        class="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50 transition"
                        disabled=move || path().is_empty()
                        on:click=handle_delete
                    >
                        "Delete"
                    </button>
                </div>
            </header>

            <Show when=move || is_editing.get()>
                 <div class="p-6 bg-white rounded-lg border border-blue-200 shadow-sm mb-6 animate-fade-in">
                    <h3 class="font-bold text-lg mb-4 text-gray-800">"Edit Secret"</h3>
                    <div class="grid gap-4 mb-4 md:grid-cols-2">
                        <div>
                             <label class="block text-sm font-medium text-gray-700 mb-1">"Key"</label>
                             <input type="text" placeholder="e.g. password" class="w-full border p-2 rounded focus:ring-2 focus:ring-blue-500 outline-none"
                                prop:value=key_input
                                on:input=move |ev| set_key_input.set(event_target_value(&ev))
                            />
                        </div>
                        <div>
                             <label class="block text-sm font-medium text-gray-700 mb-1">"Value"</label>
                             <input type="text" placeholder="Secret value" class="w-full border p-2 rounded focus:ring-2 focus:ring-blue-500 outline-none"
                                prop:value=val_input
                                on:input=move |ev| set_val_input.set(event_target_value(&ev))
                            />
                        </div>
                    </div>
                    <div class="flex gap-3 justify-end">
                         <button class="px-4 py-2 bg-gray-100 text-gray-700 rounded hover:bg-gray-200 transition" on:click=move |_| set_is_editing.set(false)>"Cancel"</button>
                         <button class="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition" on:click=handle_save>"Save Changes"</button>
                    </div>
                 </div>
            </Show>

            <Suspense fallback=|| view! {
                <div class="flex justify-center p-8">
                    <div class="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </div>
            }>
                {move || {
                    secret_resource.get().map(|res| {
                        match res {
                            Ok(data) => {
                                match data {
                                    serde_json::Value::Object(map) => {
                                        if map.is_empty() {
                                            view! { <div class="p-8 text-center text-gray-500 italic">"No data at this path."</div> }.into_view()
                                        } else {
                                            view! {
                                                <div class="bg-white rounded-lg shadow overflow-hidden border border-gray-100">
                                                    <div class="p-4 border-b border-gray-100 bg-gray-50 flex justify-between items-center">
                                                        <h3 class="font-medium text-gray-700">"Data Content"</h3>
                                                        <span class="text-xs text-gray-400">"Key-Value View"</span>
                                                    </div>
                                                    <div class="divide-y divide-gray-100">
                                                        {map.iter().map(|(k, v)| {
                                                            let val_str = if v.is_object() { "[Object]".to_string() } else { v.as_str().unwrap_or("...").to_string() };
                                                            // Clone k and val_str to own them in the view
                                                            let k = k.clone();
                                                            let title_str = v.to_string();
                                                            view! {
                                                                <div class="flex items-center justify-between p-4 hover:bg-gray-50 transition-colors group">
                                                                    <span class="font-medium text-gray-700 font-mono text-sm">{k}</span>
                                                                    <div class="flex items-center gap-3">
                                                                        <span class="font-mono text-sm text-gray-600 truncate max-w-md bg-gray-100 px-2 py-1 rounded" title=title_str>
                                                                            {val_str}
                                                                        </span>
                                                                    </div>
                                                                </div>
                                                            }
                                                        }).collect_view()}
                                                    </div>
                                                </div>
                                            }.into_view()
                                        }
                                    },
                                    _ => {
                                        let s = data.to_string();
                                        view! { <div class="p-4 text-gray-600">{s}</div> }.into_view()
                                    }
                                }
                            },
                            Err(e) => {
                                view! {
                                    <div class="p-8 text-center text-gray-500 bg-white rounded-lg border-2 border-dashed border-gray-200">
                                        <div class="text-4xl mb-2">"🔒"</div>
                                        <p class="font-medium text-gray-900">"No secret found"</p>
                                        <p class="text-sm text-gray-500 mt-1">"Create a new secret here or check permissions."</p>
                                        <p class="text-xs text-red-400 mt-4 font-mono bg-red-50 p-2 rounded inline-block">{e.to_string()}</p>
                                    </div>
                                }.into_view()
                            }
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
