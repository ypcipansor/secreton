use crate::api::fetch_api;
use leptos::prelude::*;
use secreton_common::dto::lifecycle::LifecycleStatistics;
use secreton_integrations::integrations::secret_lifecycle_management::{HookType, LifecycleHook};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum IntegrationType {
    AwsSecretsManager,
    AzureKeyVault,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    pub id: String,
    pub name: String,
    pub integration_type: IntegrationType,
    pub config: serde_json::Value,
    pub enabled: bool,
    pub created_at: String,
}

#[component]
pub fn IntegrationsPage() -> impl IntoView {
    let (stats, set_stats) = signal::<Option<LifecycleStatistics>>(None);
    let (hooks, set_hooks) = signal::<Vec<LifecycleHook>>(vec![]);
    let (integrations, set_integrations) = signal::<Vec<IntegrationConfig>>(vec![]);
    let (loading, set_loading) = signal(true);
    let (error, set_error) = signal::<Option<String>>(None);

    let load_data = move || {
        set_loading.set(true);
        set_error.set(None);

        spawn_local(async move {
            // Load stats
            match fetch_api::<LifecycleStatistics>("/lifecycle/stats", "GET", None::<()>).await {
                Ok(res) => set_stats.set(Some(res)),
                Err(e) => set_error.set(Some(format!("Failed to load stats: {}", e))),
            }

            // Load hooks
            match fetch_api::<Vec<LifecycleHook>>("/lifecycle/hooks", "GET", None::<()>).await {
                Ok(res) => set_hooks.set(res),
                Err(e) => tracing::error!("Failed to load hooks: {}", e),
            }

            // Load integrations
            match fetch_api::<Vec<IntegrationConfig>>("/integrations", "GET", None::<()>).await {
                Ok(res) => set_integrations.set(res),
                Err(e) => tracing::error!("Failed to load integrations: {}", e),
            }

            set_loading.set(false);
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
                view! { <div class="flex justify-center items-center py-12"><div class="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div></div> }.into_view()
            } else if let Some(err) = error.get() {
                view! { <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-6">{err}</div> }.into_view()
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

                    <div class="bg-white rounded-lg shadow-sm border border-gray-200 mb-8">
                        <div class="px-6 py-4 border-b border-gray-200 flex justify-between items-center">
                            <h2 class="text-xl font-semibold text-gray-800">"Cloud Provider Integrations"</h2>
                            <button class="text-sm bg-blue-50 text-blue-600 hover:bg-blue-100 px-3 py-1 rounded transition-colors">
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
                                    {move || integrations.get().into_iter().map(|integration| {
                                        let type_str = match integration.integration_type {
                                            IntegrationType::AwsSecretsManager => "AWS Secrets Manager",
                                            IntegrationType::AzureKeyVault => "Azure Key Vault",
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
                                                    <button class="text-blue-600 hover:text-blue-900 mr-4">"Edit"</button>
                                                    <button class="text-red-600 hover:text-red-900">"Delete"</button>
                                                </td>
                                            </tr>
                                        }
                                    }).collect_view()}
                                    {move || if integrations.get().is_empty() {
                                        view! { <tr><td colspan="4" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No integrations configured"</td></tr> }.into_view()
                                    } else {
                                        view! {}.into_view()
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
                                    {move || hooks.get().into_iter().map(|hook| {
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
                                    }).collect_view()}
                                    {move || if hooks.get().is_empty() {
                                        view! { <tr><td colspan="4" class="px-6 py-10 text-center text-sm text-gray-500 italic">"No webhooks configured"</td></tr> }.into_view()
                                    } else {
                                        view! {}.into_view()
                                    }}
                                </tbody>
                            </table>
                        </div>
                    </div>
                }.into_view()
            }}
        </div>
    }
}
