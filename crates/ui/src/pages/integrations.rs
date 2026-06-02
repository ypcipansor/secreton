use leptos::prelude::*;
use leptos::task::spawn_local;
use crate::api;
use secreton_common::dto::lifecycle::LifecycleStatistics;
use secreton_common::dto::integrations::{
    IntegrationConfig, IntegrationType, LifecycleHook, HookType, K8sSecret, PodInjection, InjectionStatus
};

#[component]
pub fn IntegrationsPage() -> impl IntoView {
    let (stats, set_stats) = signal::<Option<LifecycleStatistics>>(None);
    let (hooks, set_hooks) = signal::<Vec<LifecycleHook>>(vec![]);
    let (integrations, set_integrations) = signal::<Vec<IntegrationConfig>>(vec![]);
    let (k8s_secrets, set_k8s_secrets) = signal::<Vec<K8sSecret>>(vec![]);
    let (k8s_injections, set_k8s_injections) = signal::<Vec<PodInjection>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);

    // Form states
    let (show_add_integration, set_show_add_integration) = signal(false);
    let (new_integration_name, set_new_integration_name) = signal(String::new());
    let (new_integration_type, set_new_integration_type) = signal(IntegrationType::AwsSecretsManager);

    let load_data = move || {
        set_loading.set(true);
        set_error.set(None);

        spawn_local(async move {
            // Load stats
            match api::get::<LifecycleStatistics>("/lifecycle/stats").await {
                Ok(res) => set_stats.set(Some(res)),
                Err(e) => set_error.set(Some(format!("Failed to load stats: {}", e))),
            }

            // Load hooks
            match api::get::<Vec<LifecycleHook>>("/lifecycle/hooks").await {
                Ok(res) => set_hooks.set(res),
                Err(e) => web_sys::console::error_1(&format!("Failed to load hooks: {}", e).into()),
            }

            // Load integrations
            match api::get::<Vec<IntegrationConfig>>("/integrations").await {
                Ok(res) => set_integrations.set(res),
                Err(e) => web_sys::console::error_1(&format!("Failed to load integrations: {}", e).into()),
            }
            set_k8s_secrets.set(vec![]);
            set_k8s_injections.set(vec![]);

            set_loading.set(false);
        });
    };

    let handle_add_integration = move |_| {
        let name = new_integration_name.get();
        let i_type = new_integration_type.get();

        if name.is_empty() { return; }

        spawn_local(async move {
            let config = IntegrationConfig {
                id: uuid::Uuid::new_v4().to_string(),
                name,
                integration_type: i_type,
                config: serde_json::json!({}),
                enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
            };

            match api::post::<(), _>("/integrations", config).await {
                Ok(_) => {
                    set_show_add_integration.set(false);
                    load_data();
                },
                Err(e) => web_sys::console::error_1(&format!("Failed to create integration: {}", e).into()),
            }
        });
    };

    Effect::new(move |_| {
        load_data();
    });

    view! {
        <div class="container mx-auto px-4 py-8">
            <div class="flex justify-between items-center mb-8">
                <h1 class="text-3xl font-bold text-gray-900">"Integrations & Lifecycle"</h1>
                <button
                    on:click=move |_| load_data()
                    class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md transition-colors"
                >
                    "Refresh"
                </button>
            </div>

            {move || if loading.get() {
                view! { <div class="flex justify-center items-center py-12"><div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div></div> }.into_any()
            } else if let Some(err) = error.get() {
                view! { <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">{err}</div> }.into_any()
            } else {
                view! {
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
                        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                            <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider">"Active Secrets"</h3>
                            <p class="mt-2 text-3xl font-semibold text-gray-900">
                                {move || stats.get().map(|s| s.active_secrets).unwrap_or(0)}
                            </p>
                        </div>
                        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                            <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider">"Expiring Soon"</h3>
                            <p class="mt-2 text-3xl font-semibold text-yellow-600">
                                {move || stats.get().map(|s| s.expiring_secrets).unwrap_or(0)}
                            </p>
                        </div>
                        <div class="bg-white p-6 rounded-lg shadow-sm border border-gray-200">
                            <h3 class="text-sm font-medium text-gray-500 uppercase tracking-wider">"Expired"</h3>
                            <p class="mt-2 text-3xl font-semibold text-red-600">
                                {move || stats.get().map(|s| s.expired_secrets).unwrap_or(0)}
                            </p>
                        </div>
                    </div>

                    // Add Integration Form
                    {move || if show_add_integration.get() {
                        view! {
                            <div class="bg-blue-50 p-6 rounded-lg border border-blue-100 mb-8">
                                <h3 class="text-lg font-semibold text-blue-900 mb-4">"Add New Integration"</h3>
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Name"</label>
                                        <input
                                            type="text"
                                            on:input=move |e| set_new_integration_name.set(event_target_value(&e))
                                            prop:value=new_integration_name
                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        />
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Type"</label>
                                        <select
                                            on:change=move |e| {
                                                let val = event_target_value(&e);
                                                set_new_integration_type.set(match val.as_str() {
                                                    "aws" => IntegrationType::AwsSecretsManager,
                                                    "azure" => IntegrationType::AzureKeyVault,
                                                    _ => IntegrationType::AwsSecretsManager,
                                                });
                                            }
                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                        >
                                            <option value="aws">"AWS Secrets Manager"</option>
                                            <option value="azure">"Azure Key Vault"</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="mt-6 flex justify-end space-x-3">
                                    <button
                                        on:click=move |_| set_show_add_integration.set(false)
                                        class="px-4 py-2 text-gray-600 hover:text-gray-800"
                                    >
                                        "Cancel"
                                    </button>
                                    <button
                                        on:click=handle_add_integration
                                        class="bg-blue-600 text-white px-4 py-2 rounded-md hover:bg-blue-700 transition-colors"
                                    >
                                        "Save Integration"
                                    </button>
                                </div>
                            </div>
                        }.into_any()
                    } else {
                        view! {}.into_any()
                    }}

                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-8">
                        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                            <h2 class="text-xl font-semibold text-gray-800">"Cloud Provider Integrations"</h2>
                            <button
                                on:click=move |_| set_show_add_integration.set(true)
                                class="text-sm bg-blue-50 text-blue-600 hover:bg-blue-100 px-3 py-1 rounded transition-colors"
                            >
                                "+ Add Integration"
                            </button>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Name"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Type"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Status"</th>
                                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    {move || {
                                        let items = integrations.get();
                                        if items.is_empty() {
                                            view! { <tr><td colspan="4" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No integrations configured"</td></tr> }.into_any()
                                        } else {
                                            items.into_iter().map(|integration| {
                                                let id = integration.id.clone();
                                                let type_str = match integration.integration_type {
                                                    IntegrationType::AwsSecretsManager => "AWS Secrets Manager",
                                                    IntegrationType::AzureKeyVault => "Azure Key Vault",
                                                    IntegrationType::Kubernetes => "Kubernetes Operator",
                                                };
                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{integration.name}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{type_str}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap">
                                                            <span class=format!("px-2 inline-flex text-xs leading-5 font-semibold rounded-full {}", if integration.enabled { "bg-green-100 text-green-800" } else { "bg-gray-100 text-gray-800" })>
                                                                {if integration.enabled { "Enabled" } else { "Disabled" }}
                                                            </span>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                            <button
                                                                on:click=move |_| {
                                                                    let id = id.clone();
                                                                    spawn_local(async move {
                                                                        match api::delete::<()>(&format!("/integrations/{}", id)).await {
                                                                            Ok(_) => load_data(),
                                                                            Err(e) => set_error.set(Some(format!("Failed to delete integration: {}", e))),
                                                                        }
                                                                    });
                                                                }
                                                                class="text-red-600 hover:text-red-900"
                                                            >
                                                                "Delete"
                                                            </button>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view().into_any()
                                        }
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-8">
                        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                            <h2 class="text-xl font-semibold text-gray-800">"Kubernetes Managed Secrets"</h2>
                            <div class="space-x-2">
                                <button
                                    disabled=true
                                    class="text-sm bg-gray-100 text-gray-400 px-3 py-1 rounded cursor-not-allowed"
                                >
                                    "Rotate All"
                                </button>
                                <button disabled=true class="text-sm bg-gray-100 text-gray-400 px-3 py-1 rounded cursor-not-allowed">
                                    "+ New K8s Secret"
                                </button>
                            </div>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Name"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Namespace"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Secreton Path"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Version"</th>
                                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    {move || {
                                        let items = k8s_secrets.get();
                                        if items.is_empty() {
                                            view! { <tr><td colspan="5" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No Kubernetes secrets managed"</td></tr> }.into_any()
                                        } else {
                                            items.into_iter().map(|s| {
                                                let name = s.name.clone();
                                                let ns = s.namespace.clone();
                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{name.clone()}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{ns.clone()}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{s.secreton_path}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{s.version}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                            <button
                                                                on:click=move |_| {
                                                                    let name = name.clone();
                                                                    let ns = ns.clone();
                                                                    spawn_local(async move {
                                                                        web_sys::console::log_1(&format!("Syncing {} in {}", name, ns).into());
                                                                        load_data();
                                                                    });
                                                                }
                                                                class="text-blue-600 hover:text-blue-900 mr-4"
                                                            >
                                                                "Sync"
                                                            </button>
                                                            <button class="text-red-600 hover:text-red-900">"Remove"</button>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view().into_any()
                                        }
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-8">
                        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                            <h2 class="text-xl font-semibold text-gray-800">"Pod Injections"</h2>
                            <button class="text-sm bg-blue-50 text-blue-600 hover:bg-blue-100 px-3 py-1 rounded transition-colors">
                                "+ New Injection"
                            </button>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Pod Name"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Namespace"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Mount Path"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Status"</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    {move || {
                                        let items = k8s_injections.get();
                                        if items.is_empty() {
                                            view! { <tr><td colspan="4" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No active pod injections"</td></tr> }.into_any()
                                        } else {
                                            items.into_iter().map(|i| {
                                                let status_cls = match i.status {
                                                    InjectionStatus::Injected => "bg-green-100 text-green-800",
                                                    InjectionStatus::Pending => "bg-yellow-100 text-yellow-800",
                                                    InjectionStatus::Failed => "bg-red-100 text-red-800",
                                                    InjectionStatus::Updating => "bg-blue-100 text-blue-800",
                                                };
                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{i.pod_name}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{i.namespace}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{i.mount_path}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap">
                                                            <span class=format!("px-2 inline-flex text-xs leading-5 font-semibold rounded-full {}", status_cls)>
                                                                {format!("{:?}", i.status)}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view().into_any()
                                        }
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <div class="bg-white rounded-lg shadow-sm border border-gray-200">
                        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                            <h2 class="text-xl font-semibold text-gray-800">"Lifecycle Webhooks"</h2>
                            <button class="text-sm bg-blue-50 text-blue-600 hover:bg-blue-100 px-3 py-1 rounded transition-colors">
                                "+ Add Hook"
                            </button>
                        </div>
                        <div class="overflow-x-auto">
                            <table class="min-w-full divide-y divide-gray-200">
                                <thead class="bg-gray-50">
                                    <tr>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Type"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"URL"</th>
                                        <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Status"</th>
                                        <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">"Actions"</th>
                                    </tr>
                                </thead>
                                <tbody class="bg-white divide-y divide-gray-200">
                                    {move || {
                                        let items = hooks.get();
                                        if items.is_empty() {
                                            view! { <tr><td colspan="4" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No webhooks configured"</td></tr> }.into_any()
                                        } else {
                                            items.into_iter().map(|hook| {
                                                let type_str = match hook.hook_type {
                                                    HookType::PreExpire => "Pre-Expire",
                                                    HookType::PostExpire => "Post-Expire",
                                                    HookType::PreArchive => "Pre-Archive",
                                                    HookType::PostArchive => "Post-Archive",
                                                };
                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{type_str}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{hook.action_url}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap">
                                                            <span class=format!("px-2 inline-flex text-xs leading-5 font-semibold rounded-full {}", if hook.enabled { "bg-green-100 text-green-800" } else { "bg-gray-100 text-gray-800" })>
                                                                {if hook.enabled { "Active" } else { "Inactive" }}
                                                            </span>
                                                        </td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                                            <button class="text-blue-600 hover:text-blue-900 mr-4">"Edit"</button>
                                                            <button class="text-red-600 hover:text-red-900">"Delete"</button>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view().into_any()
                                        }
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>
                }.into_any()
            }}
        </div>
    }
}
