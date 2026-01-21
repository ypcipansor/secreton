use leptos::*;
use crate::api;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct HealthResponse {
    status: String,
    version: String,
    // Add other fields as needed
}

#[component]
pub fn Dashboard() -> impl IntoView {
    let health_resource = create_resource(
        || (),
        |_| async move {
            // Note: Current trunk proxy maps /health -> http://backend/health
            // So we can just fetch /health or /api/v1/sys/health if mapped.
            // Let's try /health first based on Trunk.toml
            api::get::<HealthResponse>("/sys/health").await
        },
    );

    view! {
        <div class="space-y-6">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"Dashboard"</h1>
                <p class="text-gray-600">"System Overview"</p>
            </header>

            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                // System Status Card
                <div class="p-6 bg-white rounded-lg shadow">
                    <div class="flex items-center justify-between">
                        <h3 class="text-sm font-medium text-gray-500">"System Status"</h3>
                        // Icon
                    </div>
                    <div class="mt-4">
                        <Suspense fallback=|| view! { <span class="text-gray-400">"Loading..."</span> }>
                            {move || {
                                health_resource.get().map(|res| {
                                    match res {
                                        Ok(health) => view! {
                                            <div class="flex items-center gap-2">
                                                <span class={if health.status == "healthy" { "w-3 h-3 rounded-full bg-green-500" } else { "w-3 h-3 rounded-full bg-red-500" }}></span>
                                                <span class="text-2xl font-bold text-gray-900 capitalize">{health.status}</span>
                                            </div>
                                            <p class="text-xs text-gray-500 mt-1">"Version: " {health.version}</p>
                                        }.into_view(),
                                        Err(e) => view! {
                                            <span class="text-red-500">"Error: " {e.to_string()}</span>
                                        }.into_view()
                                    }
                                })
                            }}
                        </Suspense>
                    </div>
                </div>

                // Other stats can go here (Users, Secrets Count, etc.)
                <div class="p-6 bg-white rounded-lg shadow">
                    <h3 class="text-sm font-medium text-gray-500">"Active Sessions"</h3>
                     <p class="mt-2 text-2xl font-bold text-gray-900">"-"</p>
                </div>
            </div>
        </div>
    }
}
