use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use crate::components::button::{Button, ButtonVariant};
use crate::components::card::Card;
use crate::components::modal::Modal;
use crate::components::input::Input;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RoleResponse {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
    users: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CreateRoleRequest {
    name: String,
    description: Option<String>,
    permissions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PolicyResponse {
    name: String,
    rules: Vec<String>,
    metadata: PolicyMetadata,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct PolicyMetadata {
    description: Option<String>,
    tags: Vec<String>,
    owner: Option<String>,
}

#[component]
pub fn PoliciesList() -> impl IntoView {
    // Fetch roles and policies
    let roles_resource = LocalResource::new(
        move || async move {
            api::get::<Vec<RoleResponse>>("/admin/roles").await
        },
    );

    let policies_resource = LocalResource::new(
        move || async move {
            api::get::<Vec<PolicyResponse>>("/secret/policies").await
        },
    );

    // Modal state
    let (show_modal, set_show_modal) = signal(false);
    let (role_name, set_role_name) = signal("".to_string());
    let (role_desc, set_role_desc) = signal("".to_string());
    let (role_perms, set_role_perms) = signal("".to_string()); // Comma separated

    let handle_create = move || {
        spawn_local(async move {
            let perms: Vec<String> = role_perms.get()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            let req = CreateRoleRequest {
                name: role_name.get(),
                description: if role_desc.get().is_empty() { None } else { Some(role_desc.get()) },
                permissions: perms,
            };

            if let Ok(_) = api::post::<RoleResponse, _>("/admin/roles", req).await {
                set_show_modal.set(false);
                set_role_name.set("".to_string());
                set_role_desc.set("".to_string());
                set_role_perms.set("".to_string());
                roles_resource.refetch();
            }
        });
    };

    let handle_delete = move |name: String| {
         let Some(window) = web_sys::window() else { return };
         if !window.confirm_with_message(&format!("Delete role {}?", name)).unwrap_or(false) {
            return;
        }
        spawn_local(async move {
            let url = format!("/admin/roles/{}", name);
            let _ = api::delete::<serde_json::Value>(&url).await;
            roles_resource.refetch();
        });
    };

    let handle_delete_policy = move |name: String| {
        let Some(window) = web_sys::window() else { return };
        if !window.confirm_with_message(&format!("Delete policy {}?", name)).unwrap_or(false) {
           return;
       }
       spawn_local(async move {
           let url = format!("/secret/policies/{}", name);
           let _ = api::delete::<serde_json::Value>(&url).await;
           policies_resource.refetch();
       });
   };

    view! {
        <div class="space-y-12">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Policies & Roles"</h1>
                    <p class="text-gray-500 text-sm mt-1">"Manage access control (RBAC)"</p>
                </div>
                <Button
                    variant=ButtonVariant::Primary
                    on_click=Box::new(move |_| set_show_modal.set(true))
                >
                    "Create Role"
                </Button>
            </header>

            <section class="space-y-6">
                <header>
                    <h2 class="text-xl font-bold text-gray-800">"Roles"</h2>
                </header>

                <Suspense fallback=|| view! { <div class="text-center p-8">"Loading roles..."</div> }>
                    {move || {
                        roles_resource.get().map(|res| {
                        match res {
                            Ok(roles) => {
                                let roles = roles.clone();
                                if roles.is_empty() {
                                    view! {
                                        <Card>
                                            <div class="text-center py-8 text-gray-500">
                                                "No roles defined."
                                            </div>
                                        </Card>
                                    }.into_any()
                                } else {
                                    view! {
                                        <div class="grid gap-6 md:grid-cols-2 xl:grid-cols-3">
                                            {roles.into_iter().map(|role| {
                                                let r_name = role.name.clone();
                                                let r_del = role.name.clone();
                                                let r_desc = role.description.clone().unwrap_or_default();

                                                view! {
                                                    <Card
                                                        title=r_name.clone()
                                                        subtitle=r_desc
                                                        actions=view! {
                                                             <button
                                                                class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                                on:click=move |_| handle_delete(r_del.clone())
                                                            >
                                                                "Delete"
                                                            </button>
                                                        }.into_any()
                                                    >
                                                        <div class="mt-2">
                                                            <h4 class="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">"Permissions"</h4>
                                                            <div class="flex flex-wrap gap-2">
                                                                {role.permissions.iter().map(|p| view! {
                                                                    <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800">
                                                                        {p.clone()}
                                                                    </span>
                                                                }).collect_view()}
                                                            </div>
                                                        </div>
                                                        <div class="mt-4 pt-4 border-t border-gray-100">
                                                            <div class="flex justify-between text-xs text-gray-500">
                                                                <span>"Users: " {role.users.len()}</span>
                                                            </div>
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
                                    "Error loading roles: " {e.to_string()}
                                    <br/>
                                    <span class="text-xs text-gray-500">"Make sure you are an admin."</span>
                                </div>
                            }.into_any()
                            }
                        })
                    }}
                </Suspense>
            </section>

            <section class="space-y-6">
                <header class="flex justify-between items-center">
                    <h2 class="text-xl font-bold text-gray-800">"Security Policies"</h2>
                </header>

                <Suspense fallback=|| view! { <div class="text-center p-8">"Loading policies..."</div> }>
                    {move || {
                        policies_resource.get().map(|res| {
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
                                                    let p_name = policy.name.clone();
                                                    let p_del = policy.name.clone();
                                                    let p_desc = policy.metadata.description.clone().unwrap_or_default();

                                                    view! {
                                                        <Card
                                                            title=p_name.clone()
                                                            subtitle=p_desc
                                                            actions=view! {
                                                                 <button
                                                                    class="text-red-600 hover:text-red-800 text-sm font-medium"
                                                                    on:click=move |_| handle_delete_policy(p_del.clone())
                                                                >
                                                                    "Delete"
                                                                </button>
                                                            }.into_any()
                                                        >
                                                            <div class="mt-2">
                                                                <h4 class="text-xs font-semibold text-gray-500 uppercase tracking-wider mb-2">"Rules"</h4>
                                                                <div class="space-y-1">
                                                                    {policy.rules.iter().take(3).map(|rule| view! {
                                                                        <div class="text-xs font-mono bg-gray-50 p-1 rounded truncate">
                                                                            {rule.clone()}
                                                                        </div>
                                                                    }).collect_view()}
                                                                    {if policy.rules.len() > 3 {
                                                                        view! { <div class="text-[10px] text-gray-400">"plus " {policy.rules.len() - 3} " more..."</div> }.into_any()
                                                                    } else {
                                                                        view! {}.into_any()
                                                                    }}
                                                                </div>
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
            </section>

            <Modal
                show=show_modal
                on_close=move || set_show_modal.set(false)
                title="Create New Role".to_string()
            >
                {
                    let handle_create = handle_create.clone();
                    view! {
                        <div class="space-y-4">
                            <Input
                                label="Role Name".to_string()
                                placeholder="e.g. read-only".to_string()
                                value=role_name
                                on_input=Box::new(move |v| set_role_name.set(v))
                            />
                            <Input
                                label="Description".to_string()
                                placeholder="Optional description".to_string()
                                value=role_desc
                                on_input=Box::new(move |v| set_role_desc.set(v))
                            />
                            <div>
                                <label class="block text-sm font-medium text-gray-700 mb-1">"Permissions (comma separated)"</label>
                                 <textarea
                                    class="w-full border border-gray-300 rounded-md shadow-sm p-2 focus:ring-blue-500 focus:border-blue-500 sm:text-sm"
                                    rows="3"
                                    placeholder="secrets:read, secrets:list"
                                    prop:value=role_perms
                                    on:input=move |ev| set_role_perms.set(event_target_value(&ev))
                                ></textarea>
                                <p class="text-xs text-gray-500 mt-1">"Example: secrets:read, admin:*"</p>
                            </div>

                            <div class="flex justify-end pt-4">
                                <Button
                                    variant=ButtonVariant::Primary
                                    on_click=Box::new(move |_| handle_create())
                                >
                                    "Create Role"
                                </Button>
                            </div>
                        </div>
                    }
                }
            </Modal>
        </div>
    }
}
