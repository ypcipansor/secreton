use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use crate::api;
use crate::components::{Button, Card};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct BackupInfo {
    pub id: String,
    pub created_at: String,
    pub size_bytes: u64,
    pub compressed: bool,
    pub encrypted: bool,
    pub checksum: String,
    pub metadata: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MaintenanceResult {
    pub operation: String,
    pub success: bool,
    pub duration_ms: u64,
    pub details: HashMap<String, serde_json::Value>,
}

#[component]
pub fn BackupsPage() -> impl IntoView {
    let (backups, set_backups) = signal(Vec::<BackupInfo>::new());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (success_msg, set_success_msg) = signal(Option::<String>::None);

    let fetch_backups = Action::new_local(move |_: &()| {
        async move {
            set_loading.set(true);
            match api::get::<Vec<BackupInfo>>("/admin/backups").await {
                Ok(res) => {
                    set_backups.set(res);
                    set_error_msg.set(None);
                },
                Err(e) => set_error_msg.set(Some(format!("Failed to fetch backups: {:?}", e))),
            }
            set_loading.set(false);
        }
    });

    Effect::new(move |_| {
        fetch_backups.dispatch(());
    });

    let create_backup = Action::new_local(move |_: &()| {
        async move {
            set_loading.set(true);
            match api::post::<BackupInfo, _>("/admin/backups", serde_json::json!({})).await {
                Ok(_) => {
                    set_success_msg.set(Some("Backup created successfully".to_string()));
                    fetch_backups.dispatch(());
                },
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to create backup: {:?}", e)));
                    set_loading.set(false);
                },
            }
        }
    });

    let restore_backup = Action::new_local(move |id: &String| {
        let id = id.clone();
        async move {
            let confirm = web_sys::window().and_then(|w| w.confirm_with_message(&format!("Restore system from backup {}? This will overwrite current data.", id)).ok()).unwrap_or(false);
            if !confirm { return; }

            set_loading.set(true);
            let url = format!("/admin/backups/{}/restore", id);
            match api::post::<MaintenanceResult, _>(&url, serde_json::json!({})).await {
                Ok(res) => {
                    if res.success {
                        set_error_msg.set(None);
                        set_success_msg.set(Some("System restored successfully".to_string()));
                    } else {
                        set_error_msg.set(Some("Restore failed".to_string()));
                    }
                },
                Err(e) => set_error_msg.set(Some(format!("Restore failed: {:?}", e))),
            }
            set_loading.set(false);
        }
    });

    let delete_backup = Action::new_local(move |id: &String| {
        let id = id.clone();
        async move {
            let confirm = web_sys::window().and_then(|w| w.confirm_with_message(&format!("Delete backup {}?", id)).ok()).unwrap_or(false);
            if !confirm { return; }

            set_loading.set(true);
            let url = format!("/admin/backups/{}", id);
            match api::delete::<serde_json::Value>(&url).await {
                Ok(_) => {
                    set_success_msg.set(Some("Backup deleted successfully".to_string()));
                    fetch_backups.dispatch(());
                },
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to delete backup: {:?}", e)));
                    set_loading.set(false);
                },
            }
        }
    });

    view! {
        <div class="space-y-6 animate-fade-in">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Backups"</h1>
                    <p class="text-gray-600">"System-wide backups and disaster recovery"</p>
                </div>
                <Button on_click=Box::new(move |_| { create_backup.dispatch(()); }) loading=loading>
                    "Create New Backup"
                </Button>
            </header>

            {move || error_msg.get().map(|msg| view! {
                <div class="bg-red-50 border-l-4 border-red-400 p-4 mb-4">
                    <p class="text-sm text-red-700">{msg}</p>
                </div>
            })}

            {move || success_msg.get().map(|msg| view! {
                <div class="bg-green-50 border-l-4 border-green-400 p-4 mb-4 flex justify-between items-center">
                    <p class="text-sm text-green-700">{msg}</p>
                    <button on:click=move |_| set_success_msg.set(None) class="text-green-700 font-bold">"✕"</button>
                </div>
            })}

            <Card>
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Backup ID"</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Created At"</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Size"</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">"Status"</th>
                                <th class="px-6 py-3 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">"Actions"</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {move || {
                                let b_list = backups.get();
                                if b_list.is_empty() && !loading.get() {
                                    view! {
                                        <tr>
                                            <td colspan="5" class="px-6 py-10 text-center text-gray-500 italic">
                                                "No backups found"
                                            </td>
                                        </tr>
                                    }.into_any()
                                } else {
                                    b_list.into_iter().map(|b| {
                                        let id = b.id.clone();
                                        let id_for_delete = b.id.clone();
                                        view! {
                                            <tr>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm font-mono text-blue-600">{b.id.clone()}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">{b.created_at.clone()}</td>
                                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                                    {(b.size_bytes as f64 / 1024.0 / 1024.0).round()} " MB"
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap">
                                                    <div class="flex gap-2">
                                                        {if b.encrypted {
                                                            view! { <span class="px-2 py-0.5 text-[10px] bg-purple-100 text-purple-800 rounded font-bold">"ENCRYPTED"</span> }
                                                        } else {
                                                            view! { <span class="px-2 py-0.5 text-[10px] bg-gray-100 text-gray-800 rounded font-bold">"PLAINTEXT"</span> }
                                                        }}
                                                    </div>
                                                </td>
                                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium space-x-3">
                                                    <button
                                                        class="text-blue-600 hover:text-blue-900"
                                                        on:click=move |_| { restore_backup.dispatch(id.clone()); }
                                                    >
                                                        "Restore"
                                                    </button>
                                                    <button
                                                        class="text-red-600 hover:text-red-900"
                                                        on:click=move |_| { delete_backup.dispatch(id_for_delete.clone()); }
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
            </Card>

            <div class="mt-8 bg-blue-50 p-6 rounded-lg border border-blue-100">
                <h3 class="text-lg font-semibold text-blue-900 mb-2">"Disaster Recovery"</h3>
                <p class="text-sm text-blue-800 mb-4">
                    "Backups contain all encrypted secrets, keys, and system configuration. Restoration will revert the system state to the exact point the backup was taken."
                </p>
                <div class="text-xs text-blue-700 font-mono">
                    "Note: Restoration requires the system to be initialized. For encrypted backups, the original root key is required for decryption if it has been changed since the backup."
                </div>
            </div>
        </div>
    }
}
