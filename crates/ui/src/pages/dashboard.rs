use leptos::prelude::*;
use crate::api;
use crate::components::card::Card;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct HealthResponse {
    status: String,
    version: String,
    #[serde(default)]
    sealed: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SealStatusResponse {
    sealed: bool,
    t: u8,
    n: u8,
    progress: u8,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SystemMetrics {
    uptime: u64,
    secreton: Option<SecretMetrics>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct SecretMetrics {
    total_secrets: u64,
    active_sessions: u64,
}

#[component]
pub fn Dashboard() -> impl IntoView {
    // Parallel fetching of resources
    let health_resource = LocalResource::new(
        move || async move {
            api::get::<HealthResponse>("/sys/health").await
        },
    );

    let seal_resource = LocalResource::new(
        move || async move {
            api::get::<SealStatusResponse>("/sys/seal-status").await
        },
    );

    let metrics_resource = LocalResource::new(
        move || async move {
            api::get::<SystemMetrics>("/admin/metrics").await
        },
    );

    view! {
        <div class="space-y-6 animate-fade-in">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"Dashboard"</h1>
                <p class="text-gray-600">"System Overview & Health"</p>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                // System Status
                <Card title="System Health".to_string()>
                    <Suspense fallback=|| view! { <div class="animate-pulse h-8 bg-gray-200 rounded"></div> }>
                        {move || {
                            health_resource.get().map(|res| {
                                match &*res {
                                    Ok(health) => view! {
                                        <div class="flex flex-col gap-2">
                                            <div class="flex items-center gap-2">
                                                <span class={if health.status == "active" || health.status == "healthy" { "w-3 h-3 rounded-full bg-green-500" } else { "w-3 h-3 rounded-full bg-red-500" }}></span>
                                                <span class="text-2xl font-bold text-gray-900 capitalize">{health.status.clone()}</span>
                                            </div>
                                            <p class="text-xs text-gray-500">"Version: " {health.version.clone()}</p>
                                        </div>
                                    }.into_any(),
                                    Err(_) => view! { <span class="text-red-500">"Unavailable"</span> }.into_any()
                                }
                            })
                        }}
                    </Suspense>
                </Card>

                // Seal Status
                <Card title="Vault Status".to_string()>
                     <Suspense fallback=|| view! { <div class="animate-pulse h-8 bg-gray-200 rounded"></div> }>
                        {move || {
                            seal_resource.get().map(|res| {
                                match &*res {
                                    Ok(status) => view! {
                                        <div class="flex flex-col gap-2">
                                            <div class="flex items-center gap-2">
                                                <span class="text-2xl font-bold text-gray-900">
                                                    {if status.sealed { "Sealed" } else { "Unsealed" }}
                                                </span>
                                                <span class="text-lg">
                                                    {if status.sealed { "🔒" } else { "🔓" }}
                                                </span>
                                            </div>
                                            <p class="text-xs text-gray-500">
                                                "Shares: " {status.progress} "/" {status.t} " (Threshold)"
                                            </p>
                                        </div>
                                    }.into_any(),
                                    Err(_) => view! { <span class="text-gray-400">"Status Unknown"</span> }.into_any()
                                }
                            })
                        }}
                    </Suspense>
                </Card>

                 // Active Sessions
                <Card title="Active Sessions".to_string()>
                    <Suspense fallback=|| view! { <div class="animate-pulse h-8 bg-gray-200 rounded"></div> }>
                        {move || {
                            metrics_resource.get().map(|res| {
                                match &*res {
                                    Ok(m) => {
                                        let count = m.secreton.clone().map(|s| s.active_sessions).unwrap_or(0);
                                        view! {
                                            <div class="flex items-center gap-2">
                                                <span class="text-3xl font-bold text-blue-600">{count}</span>
                                            </div>
                                        }.into_any()
                                    },
                                    Err(_) => view! { <span class="text-gray-400">"-"</span> }.into_any()
                                }
                            })
                        }}
                    </Suspense>
                </Card>

                // Secrets Count
                <Card title="Total Secrets".to_string()>
                    <Suspense fallback=|| view! { <div class="animate-pulse h-8 bg-gray-200 rounded"></div> }>
                        {move || {
                            metrics_resource.get().map(|res| {
                                match &*res {
                                    Ok(m) => {
                                        let count = m.secreton.clone().map(|s| s.total_secrets).unwrap_or(0);
                                        view! {
                                            <div class="flex items-center gap-2">
                                                <span class="text-3xl font-bold text-purple-600">{count}</span>
                                            </div>
                                        }.into_any()
                                    },
                                    Err(_) => view! { <span class="text-gray-400">"-"</span> }.into_any()
                                }
                            })
                        }}
                    </Suspense>
                </Card>
            </div>

            // Recent Activity / Audit Log Preview could go here
             <div class="mt-8">
                <h3 class="text-lg font-medium text-gray-900 mb-4">"Quick Actions"</h3>
                <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
                     <a href="/secrets" class="block p-4 bg-white border border-gray-200 rounded-lg hover:border-blue-500 hover:shadow-md transition-all group">
                        <span class="block text-2xl mb-2">"🔑"</span>
                        <span class="font-medium text-gray-900 group-hover:text-blue-600">"Manage Secrets"</span>
                     </a>
                     <a href="/policies" class="block p-4 bg-white border border-gray-200 rounded-lg hover:border-blue-500 hover:shadow-md transition-all group">
                        <span class="block text-2xl mb-2">"📝"</span>
                        <span class="font-medium text-gray-900 group-hover:text-blue-600">"Update Policies"</span>
                     </a>
                     <a href="/audit" class="block p-4 bg-white border border-gray-200 rounded-lg hover:border-blue-500 hover:shadow-md transition-all group">
                        <span class="block text-2xl mb-2">"👁️"</span>
                        <span class="font-medium text-gray-900 group-hover:text-blue-600">"View Audit Logs"</span>
                     </a>
                </div>
            </div>
        </div>
    }
}
