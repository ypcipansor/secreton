use leptos::prelude::*;
use crate::api;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct AuditEvent {
    id: String,
    #[serde(rename = "type")]
    event_type: String,
    user: String,
    status: String,
    timestamp: String,
    #[serde(flatten)]
    details: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
struct AuditResponse {
    events: Vec<AuditEvent>,
    total: u64,
}

#[component]
pub fn AuditLog() -> impl IntoView {
    // Fetch audit events using LocalResource since reqwest is !Send in WASM
    let audit_resource = LocalResource::new(
        move || async move {
            api::get::<AuditResponse>("/audit/events").await
        },
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
                        match &*res {
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
                                            {data.events.iter().map(|event| {
                                                let timestamp = event.timestamp.clone();
                                                let event_type = event.event_type.clone();
                                                let user = event.user.clone();
                                                let status = event.status.clone();
                                                let status_text = status.clone();

                                                view! {
                                                    <tr>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{timestamp}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{event_type}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{user}</td>
                                                        <td class="px-6 py-4 whitespace-nowrap">
                                                            <span class={
                                                                let base = "px-2 inline-flex text-xs leading-5 font-semibold rounded-full ";
                                                                if status == "success" {
                                                                    format!("{} bg-green-100 text-green-800", base)
                                                                } else {
                                                                    format!("{} bg-red-100 text-red-800", base)
                                                                }
                                                            }>
                                                                {status_text}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                }
                                            }).collect_view()}
                                        </tbody>
                                    </table>
                                    <div class="p-4 border-t border-gray-200 text-sm text-gray-500">
                                        "Total events: " {data.total}
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
