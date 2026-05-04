use crate::api;
use leptos::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct AuditEvent {
    pub id: String,
    pub timestamp: String,
    pub user_id: String,
    pub action: String,
    pub resource: String,
    pub ip_address: String,
    pub success: bool,
    pub details: Option<serde_json::Value>,
}

#[component]
pub fn AuditLog() -> impl IntoView {
    // Fetch audit events using LocalResource since reqwest is !Send in WASM
    let audit_resource =
        LocalResource::new(
            move || async move { api::get::<Vec<AuditEvent>>("/admin/audit").await },
        );

    view! {
        <div class="space-y-6">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"Audit Log"</h1>
                <p class="text-gray-600">"Security Events and Access Logs"</p>
            </header>

            <Suspense fallback=|| view! { <div>"Loading audit logs..."</div> }>
                {move || {
                    audit_resource.get().map(|res| {
                        match res {
                            Ok(data) => view! {
                                <div class="bg-white rounded-lg shadow overflow-hidden">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50">
                                            <tr>
                                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Timestamp"</th>
                                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Type"</th>
                                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"User"</th>
                                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Status"</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            {data.iter().map(|event| {
                                                let timestamp = event.timestamp.clone();
                                                let action = event.action.clone();
                                                let user = event.user_id.clone();
                                                let success = event.success;

                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{timestamp.split('T').next().unwrap_or_default().to_string()}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{action}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap">
                                                            <span class={
                                                                let base = "px-2 inline-flex text-xs leading-5 font-semibold rounded-full ";
                                                                if success {
                                                                    format!("{} bg-green-100 text-green-800", base)
                                                                } else {
                                                                    format!("{} bg-red-100 text-red-800", base)
                                                                }
                                                            }>
                                                                {if success { "success" } else { "failure" }}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()}
                                        </tbody>
                                    </table>
                                    <div class="p-4 border-t border-gray-200 text-sm text-gray-500">
                                        "Total events: " {data.len()}
                                    </div>
                                </div>
                            }.into_any(),
                            Err(e) => view! {
                                <div class="p-4 text-red-500 bg-white rounded shadow">
                                    "Error loading audit logs: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
