use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};
use crate::components::{Button, Card, Input, ButtonVariant};
use crate::api::{get, post, delete};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigRequest {
    pub connection_url: String,
    pub plugin_name: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub allowed_roles: Option<Vec<String>>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CreateRoleRequest {
    pub sql: String,
    pub max_ttl: Option<u64>,
    pub default_ttl: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ConfigResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ListRolesResponse {
    pub roles: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CredsResponse {
    pub username: String,
    pub password: String,
    pub lease_id: String,
    pub lease_duration: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lease {
    pub lease_id: String,
    pub username: String,
    pub role: String,
    pub created_at: String,
    pub lease_duration: u64,
}

#[component]
pub fn DatabaseSecrets() -> impl IntoView {
    let (active_tab, set_active_tab) = signal("config".to_string());

    // Config State
    let (config_url, set_config_url) = signal("postgresql://postgres:postgres@localhost:5432/postgres".to_string());
    let (config_plugin, set_config_plugin) = signal("database".to_string());
    let (config_loading, set_config_loading) = signal(false);
    let (config_msg, set_config_msg) = signal(Option::<String>::None);

    // Role State
    let (role_name, set_role_name) = signal("readonly".to_string());
    let (role_sql, set_role_sql) = signal("CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";".to_string());
    let (role_loading, set_role_loading) = signal(false);
    let (role_msg, set_role_msg) = signal(Option::<String>::None);

    // Roles List Resource
    let roles_trigger = Trigger::new();
    let roles_resource = LocalResource::new(
        move || {
            roles_trigger.track();
            async move {
                get::<ListRolesResponse>("/database/roles").await
            }
        }
    );

    // Leases List Resource
    let leases_trigger = Trigger::new();
    let leases_resource = LocalResource::new(
        move || {
            leases_trigger.track();
            async move {
                get::<Vec<Lease>>("/database/leases").await
            }
        }
    );

    // Creds State
    let (selected_role, set_selected_role) = signal("".to_string());
    let (creds_result, set_creds_result) = signal(Option::<CredsResponse>::None);
    let (creds_loading, set_creds_loading) = signal(false);
    let (creds_error, set_creds_error) = signal(Option::<String>::None);

    // Actions
    let save_config = move |_| {
        set_config_loading.set(true);
        set_config_msg.set(None);

        spawn_local(async move {
            let req = ConfigRequest {
                connection_url: config_url.get(),
                plugin_name: Some(config_plugin.get()),
                username: None,
                password: None,
                allowed_roles: None,
            };

            match post::<ConfigResponse, _>("/database/config", req).await {
                Ok(res) => set_config_msg.set(Some(format!("Success: {}", res.message))),
                Err(e) => set_config_msg.set(Some(format!("Error: {}", e))),
            }
            set_config_loading.set(false);
        });
    };

    let save_role = move |_| {
        set_role_loading.set(true);
        set_role_msg.set(None);

        let name = role_name.get();
        let sql = role_sql.get();

        spawn_local(async move {
            let req = CreateRoleRequest {
                sql: sql,
                max_ttl: Some(3600),
                default_ttl: Some(600),
            };

            match post::<ConfigResponse, _>(&format!("/database/roles/{}", name), req).await {
                Ok(res) => {
                    set_role_msg.set(Some(format!("Success: {}", res.message)));
                    roles_trigger.notify();
                },
                Err(e) => set_role_msg.set(Some(format!("Error: {}", e))),
            }
            set_role_loading.set(false);
        });
    };

    let generate_creds = move |_| {
        let role = selected_role.get();
        if role.is_empty() { return; }

        set_creds_loading.set(true);
        set_creds_error.set(None);
        set_creds_result.set(None);

        spawn_local(async move {
            match get::<CredsResponse>(&format!("/database/creds/{}", role)).await {
                Ok(res) => {
                    set_creds_result.set(Some(res));
                    leases_trigger.notify(); // Refresh leases list
                },
                Err(e) => set_creds_error.set(Some(format!("Error: {}", e))),
            }
            set_creds_loading.set(false);
        });
    };

    let revoke_lease = move |lease_id: String| {
        spawn_local(async move {
            // We use ConfigResponse as generic success response wrapper, ignoring message for now or logging it
            match delete::<ConfigResponse>(&format!("/database/leases/{}", lease_id)).await {
                Ok(_) => leases_trigger.notify(),
                Err(e) => {
                    log::error!("Failed to revoke lease: {}", e);
                    // In a real app we'd set an error signal
                }
            }
        });
    };

    // Tab Class Helper
    let tab_class = move |tab_name: &'static str| {
        let base = "px-4 py-2 font-medium text-sm rounded-t-lg focus:outline-none";
        move || {
            if active_tab.get() == tab_name {
                format!("{} bg-white text-blue-600 border-t border-l border-r border-gray-200", base)
            } else {
                format!("{} text-gray-500 hover:text-gray-700 bg-gray-50", base)
            }
        }
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold text-gray-900">"Database Secrets"</h1>
                <div class="flex space-x-2">
                    <span class="px-2 py-1 text-xs font-semibold bg-blue-100 text-blue-800 rounded-full">"BETA"</span>
                </div>
            </div>

            <Card>
                <div class="border-b border-gray-200">
                    <nav class="-mb-px flex space-x-1" aria-label="Tabs">
                        <button class=tab_class("config") on:click=move |_| set_active_tab.set("config".to_string())>
                            "Configuration"
                        </button>
                        <button class=tab_class("roles") on:click=move |_| set_active_tab.set("roles".to_string())>
                            "Roles"
                        </button>
                        <button class=tab_class("creds") on:click=move |_| set_active_tab.set("creds".to_string())>
                            "Credentials"
                        </button>
                        <button class=tab_class("leases") on:click=move |_| set_active_tab.set("leases".to_string())>
                            "Leases"
                        </button>
                    </nav>
                </div>

                <div class="p-6">
                    <Show when=move || active_tab.get() == "config">
                        <div class="space-y-4 max-w-2xl">
                            <h3 class="text-lg font-medium text-gray-900">"Connection Configuration"</h3>
                            <Input
                                label="Connection URL"
                                placeholder="postgresql://user:pass@host:5432/db"
                                value=config_url
                                on_input=Box::new(move |v| set_config_url.set(v))
                            />
                            <Input
                                label="Plugin Name"
                                value=config_plugin
                                on_input=Box::new(move |v| set_config_plugin.set(v))
                            />

                            <div class="pt-2">
                                <Button
                                    loading=config_loading
                                    on_click=Box::new(save_config)
                                >
                                    "Save Configuration"
                                </Button>
                            </div>

                            <Show when=move || config_msg.get().is_some()>
                                <div class="p-4 rounded-md bg-gray-50 text-sm">
                                    {move || config_msg.get()}
                                </div>
                            </Show>
                        </div>
                    </Show>

                    <Show when=move || active_tab.get() == "roles">
                        <div class="space-y-6">
                            <div class="space-y-4 max-w-2xl">
                                <h3 class="text-lg font-medium text-gray-900">"Create/Update Role"</h3>
                                <Input
                                    label="Role Name"
                                    value=role_name
                                    on_input=Box::new(move |v| set_role_name.set(v))
                                />
                                <div class="space-y-1">
                                    <label class="block text-sm font-medium text-gray-700">"SQL Statements"</label>
                                    <textarea
                                        class="block w-full px-3 py-2 sm:text-sm rounded-md shadow-sm border border-gray-300 focus:ring-blue-500 focus:border-blue-500 h-32 font-mono"
                                        on:input=move |ev| set_role_sql.set(event_target_value(&ev))
                                        prop:value=role_sql
                                    ></textarea>
                                    <p class="text-xs text-gray-500">"Use {{name}}, {{password}}, {{expiration}} as placeholders."</p>
                                </div>

                                <div class="pt-2">
                                    <Button
                                        loading=role_loading
                                        on_click=Box::new(save_role)
                                    >
                                        "Save Role"
                                    </Button>
                                </div>

                                <Show when=move || role_msg.get().is_some()>
                                    <div class="p-4 rounded-md bg-gray-50 text-sm">
                                        {move || role_msg.get()}
                                    </div>
                                </Show>
                            </div>

                            <div class="border-t border-gray-200 pt-6">
                                <h3 class="text-lg font-medium text-gray-900 mb-4">"Existing Roles"</h3>
                                <Suspense fallback=|| view! { <div>"Loading roles..."</div> }>
                                    {move || {
                                        roles_resource.get().map(|res| match res {
                                            Ok(data) => view! {
                                                <ul class="divide-y divide-gray-200">
                                                    <For
                                                        each=move || data.roles.clone()
                                                        key=|role| role.clone()
                                                        children=move |role| {
                                                            view! {
                                                                <li class="py-3 flex justify-between items-center">
                                                                    <span class="text-sm font-medium text-gray-900">{role.clone()}</span>
                                                                    <Button
                                                                        variant=ButtonVariant::Outline
                                                                        class="text-xs px-2 py-1"
                                                                        on_click=Box::new(move |_| {
                                                                            set_selected_role.set(role.clone());
                                                                            set_active_tab.set("creds".to_string());
                                                                        })
                                                                    >
                                                                        "Get Creds"
                                                                    </Button>
                                                                </li>
                                                            }
                                                        }
                                                    />
                                                </ul>
                                            }.into_any(),
                                            Err(e) => view! { <div class="text-red-500">{format!("Error loading roles: {}", e)}</div> }.into_any()
                                        })
                                    }}
                                </Suspense>
                            </div>
                        </div>
                    </Show>

                    <Show when=move || active_tab.get() == "creds">
                        <div class="space-y-4 max-w-2xl">
                            <h3 class="text-lg font-medium text-gray-900">"Generate Credentials"</h3>

                            <div class="flex items-end gap-4">
                                <div class="flex-grow">
                                    <Input
                                        label="Role Name"
                                        value=selected_role
                                        on_input=Box::new(move |v| set_selected_role.set(v))
                                    />
                                </div>
                                <div class="pb-0.5">
                                    <Button
                                        loading=creds_loading
                                        on_click=Box::new(generate_creds)
                                    >
                                        "Generate"
                                    </Button>
                                </div>
                            </div>

                            <Show when=move || creds_error.get().is_some()>
                                <div class="p-4 rounded-md bg-red-50 text-red-700 text-sm">
                                    {move || creds_error.get()}
                                </div>
                            </Show>

                            <Show when=move || creds_result.get().is_some()>
                                {move || {
                                    let res = creds_result.get().unwrap();
                                    view! {
                                        <div class="mt-4 p-4 rounded-md bg-green-50 border border-green-200">
                                            <h4 class="text-sm font-medium text-green-800 mb-2">"Credentials Generated"</h4>
                                            <dl class="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                                                <div class="sm:col-span-1">
                                                    <dt class="text-xs font-medium text-green-600 uppercase tracking-wider">"Username"</dt>
                                                    <dd class="mt-1 text-sm text-gray-900 font-mono bg-white p-2 rounded border border-green-100 select-all">{res.username}</dd>
                                                </div>
                                                <div class="sm:col-span-1">
                                                    <dt class="text-xs font-medium text-green-600 uppercase tracking-wider">"Password"</dt>
                                                    <dd class="mt-1 text-sm text-gray-900 font-mono bg-white p-2 rounded border border-green-100 select-all">{res.password}</dd>
                                                </div>
                                                <div class="sm:col-span-2">
                                                    <dt class="text-xs font-medium text-green-600 uppercase tracking-wider">"Lease ID"</dt>
                                                    <dd class="mt-1 text-xs text-gray-500 font-mono">{res.lease_id}</dd>
                                                </div>
                                            </dl>
                                        </div>
                                    }
                                }}
                            </Show>
                        </div>
                    </Show>

                    <Show when=move || active_tab.get() == "leases">
                        <div class="space-y-4">
                            <div class="flex justify-between items-center">
                                <h3 class="text-lg font-medium text-gray-900">"Active Leases"</h3>
                                <Button
                                    variant=ButtonVariant::Outline
                                    class="text-xs"
                                    on_click=Box::new(move |_| leases_trigger.notify())
                                >
                                    "Refresh"
                                </Button>
                            </div>

                            <Suspense fallback=|| view! { <div>"Loading leases..."</div> }>
                                {move || {
                                    leases_resource.get().map(|res| match res {
                                        Ok(leases) => {
                                            if leases.is_empty() {
                                                view! { <div class="text-sm text-gray-500 italic">"No active leases found."</div> }.into_any()
                                            } else {
                                                view! {
                                                    <div class="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
                                                        <table class="min-w-full divide-y divide-gray-300">
                                                            <thead class="bg-gray-50">
                                                                <tr>
                                                                    <th scope="col" class="py-3.5 pl-4 pr-3 text-left text-sm font-semibold text-gray-900 sm:pl-6">"Lease ID"</th>
                                                                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">"Username"</th>
                                                                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">"Role"</th>
                                                                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">"Duration"</th>
                                                                    <th scope="col" class="px-3 py-3.5 text-left text-sm font-semibold text-gray-900">"Created At"</th>
                                                                    <th scope="col" class="relative py-3.5 pl-3 pr-4 sm:pr-6">
                                                                        <span class="sr-only">"Actions"</span>
                                                                    </th>
                                                                </tr>
                                                            </thead>
                                                            <tbody class="divide-y divide-gray-200 bg-white">
                                                                <For
                                                                    each=move || leases.clone()
                                                                    key=|lease| lease.lease_id.clone()
                                                                    children=move |lease| {
                                                                        let id = lease.lease_id.clone();
                                                                        view! {
                                                                            <tr>
                                                                                <td class="whitespace-nowrap py-4 pl-4 pr-3 text-sm font-medium text-gray-900 sm:pl-6">{lease.lease_id}</td>
                                                                                <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500 font-mono">{lease.username}</td>
                                                                                <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{lease.role}</td>
                                                                                <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{format!("{}s", lease.lease_duration)}</td>
                                                                                <td class="whitespace-nowrap px-3 py-4 text-sm text-gray-500">{lease.created_at}</td>
                                                                                <td class="relative whitespace-nowrap py-4 pl-3 pr-4 text-right text-sm font-medium sm:pr-6">
                                                                                    <Button
                                                                                        variant=ButtonVariant::Danger
                                                                                        class="text-xs px-2 py-1"
                                                                                        on_click=Box::new(move |_| revoke_lease(id.clone()))
                                                                                    >
                                                                                        "Revoke"
                                                                                    </Button>
                                                                                </td>
                                                                            </tr>
                                                                        }
                                                                    }
                                                                />
                                                            </tbody>
                                                        </table>
                                                    </div>
                                                }.into_any()
                                            }
                                        },
                                        Err(e) => view! { <div class="text-red-500">{format!("Error loading leases: {}", e)}</div> }.into_any()
                                    })
                                }}
                            </Suspense>
                        </div>
                    </Show>
                </div>
            </Card>
        </div>
    }
}
