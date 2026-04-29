use leptos::prelude::*;
use crate::api;
use crate::components::Card;
pub use secreton_common::dto::lifecycle::LifecycleStatistics;

#[component]
pub fn LifecycleDashboard() -> impl IntoView {
    let stats_resource = LocalResource::new(|| async move {
        api::get::<LifecycleStatistics>("/lifecycle/stats").await
    });

    view! {
        <div class="space-y-6">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"Secret Lifecycle Dashboard"</h1>
                <p class="text-gray-500 mt-1">"Overview of secret expiration and archival status."</p>
            </header>

            <Suspense fallback=|| view! { <div class="animate-pulse flex space-x-4"><div class="flex-1 space-y-4 py-1"><div class="h-4 bg-gray-200 rounded w-3/4"></div><div class="space-y-2"><div class="h-4 bg-gray-200 rounded"></div><div class="h-4 bg-gray-200 rounded w-5/6"></div></div></div></div> }>
                {move || {
                    stats_resource.get().map(|res: Result<LifecycleStatistics, api::ApiError>| {
                        match res {
                            Ok(stats) => view! {
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
                                    <StatCard title="Active Secrets" value=stats.active_secrets.to_string() color="text-green-600" />
                                    <StatCard title="Expiring Soon" value=stats.expiring_secrets.to_string() color="text-yellow-600" />
                                    <StatCard title="Expired" value=stats.expired_secrets.to_string() color="text-red-600" />
                                    <StatCard title="Archived" value=stats.archived_secrets.to_string() color="text-blue-600" />
                                </div>
                            }.into_any(),
                            Err(e) => view! {
                                <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                                    "Error loading lifecycle statistics: " {e.to_string()}
                                </div>
                            }.into_any(),
                        }
                    })
                }}
            </Suspense>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card title="Upcoming Expirations".to_string()>
                    <div class="text-gray-500 italic">"No secrets expiring in the next 30 days."</div>
                </Card>
                <Card title="Recent Lifecycle Events".to_string()>
                    <div class="text-gray-500 italic">"No recent events."</div>
                </Card>
            </div>
        </div>
    }
}

#[component]
fn StatCard(title: &'static str, value: String, color: &'static str) -> impl IntoView {
    view! {
        <Card>
            <div class="flex flex-col items-center justify-center py-4">
                <span class="text-sm font-medium text-gray-500 uppercase tracking-wider">{title}</span>
                <span class=format!("text-4xl font-bold mt-2 {}", color)>{value}</span>
            </div>
        </Card>
    }
}
