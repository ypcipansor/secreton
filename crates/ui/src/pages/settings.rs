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
    let config_resource = LocalResource::new(
        move || async move {
            api::get::<SystemConfig>("/admin/config").await
        },
    );

    view! {
        <div class="space-y-6">
            <header>
                <h1 class="text-3xl font-bold text-gray-900">"Settings"</h1>
                <p class="text-gray-600">"System-wide configuration and security policies"</p>
            </header>

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
                                                <span class={format!("px-2 py-1 text-xs font-bold rounded {}", if config.security.mfa_enabled { "bg-green-100 text-green-700" } else { "bg-red-100 text-red-700" })}>
                                                    {if config.security.mfa_enabled { "ENABLED" } else { "DISABLED" }}
                                                </span>
                                            </div>
                                            <div class="space-y-2">
                                                <p class="text-xs font-bold text-gray-400 uppercase">"Password Requirements"</p>
                                                <ul class="text-sm text-gray-700 space-y-1">
                                                    <li class="flex justify-between">
                                                        <span>"Minimum Length"</span>
                                                        <span class="font-mono">{config.security.password_policy.min_length}</span>
                                                    </li>
                                                    <li class="flex justify-between">
                                                        <span>"Uppercase Required"</span>
                                                        <span>{if config.security.password_policy.require_uppercase { "✅" } else { "❌" }}</span>
                                                    </li>
                                                    <li class="flex justify-between">
                                                        <span>"Numbers Required"</span>
                                                        <span>{if config.security.password_policy.require_numbers { "✅" } else { "❌" }}</span>
                                                    </li>
                                                    <li class="flex justify-between">
                                                        <span>"Special Chars Required"</span>
                                                        <span>{if config.security.password_policy.require_special { "✅" } else { "❌" }}</span>
                                                    </li>
                                                </ul>
                                            </div>
                                            <div class="flex justify-between items-center pt-2 border-t">
                                                <span class="text-sm text-gray-500">"Session Timeout"</span>
                                                <span class="text-sm font-mono">{config.security.session_timeout / 60} " min"</span>
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
                                                  <button class="w-full text-center px-4 py-2 border border-gray-300 rounded shadow-sm text-sm font-medium text-gray-400 bg-gray-50 cursor-not-allowed" disabled=true title="Coming soon">
                                                      "Clear Performance Cache (Coming Soon)"
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
