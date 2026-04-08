use leptos::prelude::*;
use crate::api;
use crate::components::Card;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SystemConfig {
    pub api: ApiConfigInfo,
    pub security: SecurityConfigInfo,
    pub storage: StorageConfigInfo,
    pub monitoring: MonitoringConfigInfo,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ApiConfigInfo {
    pub version: String,
    pub bind_address: String,
    pub max_connections: u32,
    pub timeout: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SecurityConfigInfo {
    pub mfa_enabled: bool,
    pub password_policy: PasswordPolicyInfo,
    pub session_timeout: u64,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct PasswordPolicyInfo {
    pub min_length: u8,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_numbers: bool,
    pub require_special: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct StorageConfigInfo {
    pub backend: String,
    pub encryption_enabled: bool,
    pub backup_enabled: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct MonitoringConfigInfo {
    pub metrics_enabled: bool,
    pub tracing_enabled: bool,
    pub log_level: String,
}

#[component]
pub fn SettingsPage() -> impl IntoView {
    let (success_msg, set_success_msg) = signal(Option::<String>::None);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    let config_resource = LocalResource::new(
        move || async move {
            api::get::<SystemConfig>("/admin/config").await
        },
    );

    // Form signals
    let (mfa_enabled, set_mfa_enabled) = signal(false);
    let (min_length, set_min_length) = signal(8u8);
    let (req_upper, set_req_upper) = signal(true);
    let (req_lower, set_req_lower) = signal(true);
    let (req_numbers, set_req_numbers) = signal(true);
    let (req_special, set_req_special) = signal(false);
    let (session_timeout, set_session_timeout) = signal(3600u64);
    let (config_loaded, set_config_loaded) = signal(false);

    Effect::new(move |_| {
        if let Some(Ok(config)) = config_resource.get() {
            set_mfa_enabled.set(config.security.mfa_enabled);
            set_min_length.set(config.security.password_policy.min_length);
            set_req_upper.set(config.security.password_policy.require_uppercase);
            set_req_lower.set(config.security.password_policy.require_lowercase);
            set_req_numbers.set(config.security.password_policy.require_numbers);
            set_req_special.set(config.security.password_policy.require_special);
            set_session_timeout.set(config.security.session_timeout);
            set_config_loaded.set(true);
        }
    });

    let save_config = Action::new_local(move |_: &()| {
        async move {
            let updates = serde_json::json!({
                "enable_mfa": mfa_enabled.get(),
                "password_policy_min_length": min_length.get(),
                "password_policy_require_uppercase": req_upper.get(),
                "password_policy_require_lowercase": req_lower.get(),
                "password_policy_require_numbers": req_numbers.get(),
                "password_policy_require_special": req_special.get(),
                "session_timeout": session_timeout.get(),
            });

            match api::put::<serde_json::Value, _>("/admin/config", updates).await {
                Ok(_) => {
                    set_success_msg.set(Some("Configuration updated successfully".to_string()));
                    set_error_msg.set(None);
                },
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to update configuration: {:?}", e)));
                    set_success_msg.set(None);
                }
            }
        }
    });

    let clear_cache = Action::new_local(move |_: &()| {
        async move {
            match api::post::<serde_json::Value, _>("/admin/maintenance/cache/clear", serde_json::json!({})).await {
                Ok(_) => {
                    set_success_msg.set(Some("Performance cache cleared".to_string()));
                    set_error_msg.set(None);
                },
                Err(e) => {
                    set_error_msg.set(Some(format!("Failed to clear cache: {:?}", e)));
                    set_success_msg.set(None);
                }
            }
        }
    });

    view! {
        <div class="space-y-6">
            <header class="flex justify-between items-center">
                <div>
                    <h1 class="text-3xl font-bold text-gray-900">"Settings"</h1>
                    <p class="text-gray-600">"System-wide configuration and security policies"</p>
                </div>
                <button
                    on:click=move |_| save_config.dispatch(())
                    disabled=move || !config_loaded.get()
                    class=move || if config_loaded.get() {
                        "px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 transition"
                    } else {
                        "px-4 py-2 bg-gray-400 text-white rounded cursor-not-allowed"
                    }
                >
                    "Save Changes"
                </button>
            </header>

            {move || success_msg.get().map(|msg| view! {
                <div class="bg-green-50 border-l-4 border-green-400 p-4">
                    <p class="text-sm text-green-700">{msg}</p>
                </div>
            })}

            {move || error_msg.get().map(|msg| view! {
                <div class="bg-red-50 border-l-4 border-red-400 p-4">
                    <p class="text-sm text-red-700">{msg}</p>
                </div>
            })}

            <Suspense fallback=|| view! { <div class="animate-pulse h-12 bg-gray-200 rounded"></div> }>
                {move || {
                    config_resource.get().map(|res| {
                        match res {
                            Ok(config) => view! {
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <Card title="Security Policy".to_string()>
                                        <div class="space-y-4">
                                            <div class="flex justify-between items-center pb-2 border-b">
                                                <span class="text-sm text-gray-500">"MFA Required"</span>
                                                <input
                                                    type="checkbox"
                                                    checked=move || mfa_enabled.get()
                                                    on:change=move |ev| set_mfa_enabled.set(event_target_checked(&ev))
                                                    class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
                                                />
                                            </div>
                                            <div class="space-y-2">
                                                <p class="text-xs font-bold text-gray-400 uppercase">"Password Requirements"</p>
                                                <div class="space-y-3">
                                                    <div class="flex justify-between items-center">
                                                        <span class="text-sm">"Minimum Length"</span>
                                                        <input
                                                            type="number"
                                                            min="1"
                                                            max="255"
                                                            value=move || min_length.get().to_string()
                                                            on:input=move |ev| {
                                                                let v = event_target_value(&ev).parse::<u8>().unwrap_or(8).max(1);
                                                                set_min_length.set(v)
                                                            }
                                                            class="w-16 px-2 py-1 text-sm border rounded focus:ring-blue-500 focus:border-blue-500"
                                                        />
                                                    </div>
                                                    <div class="flex justify-between items-center">
                                                        <span class="text-sm">"Require Uppercase"</span>
                                                        <input type="checkbox" checked=move || req_upper.get() on:change=move |ev| set_req_upper.set(event_target_checked(&ev)) />
                                                    </div>
                                                    <div class="flex justify-between items-center">
                                                        <span class="text-sm">"Require Lowercase"</span>
                                                        <input type="checkbox" checked=move || req_lower.get() on:change=move |ev| set_req_lower.set(event_target_checked(&ev)) />
                                                    </div>
                                                    <div class="flex justify-between items-center">
                                                        <span class="text-sm">"Require Numbers"</span>
                                                        <input type="checkbox" checked=move || req_numbers.get() on:change=move |ev| set_req_numbers.set(event_target_checked(&ev)) />
                                                    </div>
                                                    <div class="flex justify-between items-center">
                                                        <span class="text-sm">"Require Special Chars"</span>
                                                        <input type="checkbox" checked=move || req_special.get() on:change=move |ev| set_req_special.set(event_target_checked(&ev)) />
                                                    </div>
                                                </div>
                                            </div>
                                            <div class="flex justify-between items-center pt-2 border-t">
                                                <span class="text-sm text-gray-500">"Session Timeout (minutes)"</span>
                                                <input
                                                    type="number"
                                                    min="1"
                                                    max="1440"
                                                    value=move || (session_timeout.get() / 60).to_string()
                                                    on:input=move |ev| {
                                                        let mins = event_target_value(&ev).parse::<u64>().unwrap_or(60).max(1).min(1440);
                                                        set_session_timeout.set(mins * 60)
                                                    }
                                                    class="w-20 px-2 py-1 text-sm border rounded focus:ring-blue-500 focus:border-blue-500"
                                                />
                                            </div>
                                        </div>
                                    </Card>

                                    <Card title="Infrastructure".to_string()>
                                        <div class="space-y-4">
                                             <div class="flex justify-between items-center pb-2 border-b">
                                                <span class="text-sm text-gray-500">"Storage Backend"</span>
                                                <span class="font-mono text-sm uppercase">{config.storage.backend.clone()}</span>
                                            </div>
                                            <div class="flex justify-between items-center pb-2 border-b">
                                                <span class="text-sm text-gray-500">"Encryption"</span>
                                                <span class={format!("text-sm font-bold {}", if config.storage.encryption_enabled { "text-green-600" } else { "text-red-600" })}>{if config.storage.encryption_enabled { "ACTIVE" } else { "DISABLED" }}</span>
                                            </div>
                                            <div class="flex justify-between items-center pb-2 border-b">
                                                <span class="text-sm text-gray-500">"Automatic Backups"</span>
                                                <span class="text-sm">{if config.storage.backup_enabled { "✅" } else { "❌" }}</span>
                                            </div>
                                            <div class="flex justify-between items-center">
                                                <span class="text-sm text-gray-500">"Log Level"</span>
                                                <span class="px-2 py-1 bg-blue-100 text-blue-700 text-xs font-bold rounded uppercase">
                                                    {config.monitoring.log_level.clone()}
                                                </span>
                                            </div>
                                        </div>
                                    </Card>

                                    <Card title="API Metadata".to_string()>
                                         <div class="space-y-4">
                                             <div class="flex justify-between items-center">
                                                <span class="text-sm text-gray-500">"API Version"</span>
                                                <span class="font-mono text-sm">{config.api.version.clone()}</span>
                                            </div>
                                            <div class="flex justify-between items-center">
                                                <span class="text-sm text-gray-500">"Bind Address"</span>
                                                <span class="font-mono text-sm">{config.api.bind_address.clone()}</span>
                                            </div>
                                            <div class="flex justify-between items-center">
                                                <span class="text-sm text-gray-500">"Max Connections"</span>
                                                <span class="font-mono text-sm">{config.api.max_connections}</span>
                                            </div>
                                        </div>
                                    </Card>

                                     <Card title="Maintenance".to_string()>
                                         <div class="space-y-4">
                                              <p class="text-sm text-gray-600">
                                                "Manage system-wide maintenance tasks and data lifecycle policies."
                                              </p>
                                              <div class="flex flex-col gap-2">
                                                  <a href="/backups" class="block w-full text-center px-4 py-2 border border-gray-300 rounded shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition">
                                                      "System Backups"
                                                  </a>
                                                  <button
                                                      class="w-full text-center px-4 py-2 border border-gray-300 rounded shadow-sm text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 transition"
                                                      on:click=move |_| clear_cache.dispatch(())
                                                  >
                                                      "Clear Performance Cache"
                                                  </button>
                                              </div>
                                         </div>
                                    </Card>
                                </div>
                            }.into_any(),
                            Err(e) => view! {
                                <div class="p-4 bg-red-50 text-red-700 rounded border border-red-200">
                                    "Failed to load system configuration: " {e.to_string()}
                                </div>
                            }.into_any()
                        }
                    })
                }}
            </Suspense>
        </div>
    }
}
