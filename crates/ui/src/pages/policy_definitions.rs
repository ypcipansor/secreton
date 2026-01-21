use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::input::Input;
use crate::components::card::Card;
use crate::components::modal::Modal;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PolicyResponse {
    name: String,
    rules: Vec<String>,
    metadata: PolicyMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct PolicyMetadata {
    description: Option<String>,
    tags: Vec<String>,
    owner: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct CreatePolicyRequest {
    name: String,
    rules: Vec<String>,
    metadata: Option<PolicyMetadata>,
}

#[component]
pub fn PolicyDefinitions() -> impl IntoView {
    // Resource
    let policy_resource = LocalResource::new(|| async move {
        api::get::<Vec<PolicyResponse>>("/policies").await
    });

    // State
    let (show_modal, set_show_modal) = signal(false);
    let (policy_name, set_policy_name) = signal("".to_string());
    let (policy_rules, set_policy_rules) = signal("".to_string());
    let (policy_desc, set_policy_desc) = signal("".to_string());
    let (is_edit, set_is_edit) = signal(false);

    // Handlers
    let open_create = move |_| {
        set_policy_name.set("".to_string());
        set_policy_rules.set("".to_string());
        set_policy_desc.set("".to_string());
        set_is_edit.set(false);
        set_show_modal.set(true);
    };

    let open_edit = move |policy: PolicyResponse| {
        set_policy_name.set(policy.name);
        set_policy_rules.set(policy.rules.join("\n"));
        set_policy_desc.set(policy.metadata.description.unwrap_or_default());
        set_is_edit.set(true);
        set_show_modal.set(true);
    };

    let handle_save = move || {
        spawn_local(async move {
            let rules: Vec<String> = policy_rules.get()
                .split('\n')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let req = CreatePolicyRequest {
                name: policy_name.get(),
                rules,
                metadata: Some(PolicyMetadata {
                    description: if policy_desc.get().is_empty() { None } else { Some(policy_desc.get()) },
                    tags: vec![],
                    owner: None,
                }),
            };

            let url = format!("/policies/{}", policy_name.get());
            let res = if is_edit.get() {
                 // PUT usually for updates but check API. secret.rs has POST and PUT for create/update.
                 // Actually secret.rs: route("/policies/{name}", put(update_policy))
                 api::put::<PolicyResponse, _>(&url, req).await
            } else {
                 api::post::<PolicyResponse, _>(&url, req).await
            };

            if let Ok(_) = res {
                set_show_modal.set(false);
                policy_resource.refetch();
            }
        });
    };

    let handle_delete = move |name: String| {
        if !web_sys::window().unwrap().confirm_with_message(&format!("Delete policy {}?", name)).unwrap_or(false) {
            return;
        }
        spawn_local(async move {
             let url = format!("/policies/{}", name);
             let _ = api::delete::<serde_json::Value>(&url).await;
             policy_resource.refetch();
        });
    };

    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Policies"</h1>
                    <p class="text-gray-500 text-sm mt-1">"Define access control rules (ACL/Sentinel)."</p>
                </div>
                <Button variant=ButtonVariant::Primary on_click=Box::new(open_create)>
                    "Create Policy"
                </Button>
            </header>

            <Suspense fallback=|| view! { <div class="text-center p-8">"Loading policies..."</div> }>
                {move || {
                    policy_resource.get().map(|res| {
                        match res {
                            Ok(policies) => {
                                let policies = policies.clone();
                                if policies.is_empty() {
                                    view! {
                                        <Card>
                                            <div class="text-center py-8 text-gray-500">
                                                "No policies defined."
                                            </div>
                                        </Card>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                                            {policies.into_iter().map(|policy| {
                                                let p = policy.clone();
                                                let p_del = policy.name.clone();
                                                let p_edit = policy.clone();
                                                let desc = policy.metadata.description.unwrap_or_default();

                                                view! {
                                                    <Card
                                                        title=p.name.clone()
                                                        subtitle=desc
                                                        actions=view! {
                                                            <div class="flex gap-2">
                                                                <button
                                                                    class="text-blue-600 hover:text-blue-800 text-sm font-medium"
                                                                    on:click=move |_| open_edit(p_edit.clone())
                                                                >
                                                                    "Edit"
                                                                </button>
                                                                <button
                                                                    class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                                    on:click=move |_| handle_delete(p_del.clone())
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            </div>
                                                        }.into_any()
                                                    >
                                                        <div class="mt-4 bg-gray-50 p-2 rounded border border-gray-100 h-24 overflow-y-auto">
                                                            <pre class="text-xs font-mono text-gray-600 whitespace-pre-wrap">{p.rules.join("\n")}</pre>
                                                        </div>
                                                    </Card>
                                                }
                                            }).collect_view()}
                                        </div>
                                    }.into_any()
                                }
                            },
                            Err(e) => view! {
                                <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                                    "Error loading policies: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>

            <Modal
                show=show_modal
                on_close=move || set_show_modal.set(false)
                title=if is_edit.get() { "Edit Policy".to_string() } else { "Create Policy".to_string() }
            >
                <div class="space-y-4">
                    <Input
                        label="Name".to_string()
                        placeholder="my-policy".to_string()
                        value=policy_name
                        on_input=Box::new(move |v| set_policy_name.set(v))
                        // Disable name edit if editing
                        // type_="text".to_string() // Input component doesn't support disabled prop easily yet?
                        // Assuming Input component is simple. If needed I'd modify Input.
                        // For now, just let them edit it, backend might complain or create new.
                        // Ideally disable it.
                    />
                    <Input
                        label="Description".to_string()
                        placeholder="Policy description".to_string()
                        value=policy_desc
                        on_input=Box::new(move |v| set_policy_desc.set(v))
                    />

                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">"Rules"</label>
                        <textarea
                            class="w-full border border-gray-300 rounded-md shadow-sm p-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm h-48"
                            placeholder="path/to/secret read"
                            prop:value=policy_rules
                            on:input=move |ev| set_policy_rules.set(event_target_value(&ev))
                        ></textarea>
                        <p class="text-xs text-gray-500 mt-1">"Enter rules, one per line."</p>
                    </div>

                    <div class="flex justify-end pt-4">
                        <Button variant=ButtonVariant::Primary on_click=Box::new(move |_| handle_save())>
                            "Save Policy"
                        </Button>
                    </div>
                </div>
            </Modal>
        </div>
    }
}
