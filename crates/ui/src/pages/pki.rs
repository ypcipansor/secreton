use crate::api::post;
use crate::components::{Button, Card, Input};
use leptos::prelude::*;
use leptos::task::spawn_local;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct GenerateCertRequest {
    pub common_name: String,
    pub ttl: Option<u64>,
    pub key_type: Option<String>,
    pub key_bits: Option<u64>,
    pub organization: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CertResponse {
    pub certificate: String,
    pub private_key: String,
    pub serial_number: String,
    pub expiration: i64,
}

#[component]
pub fn PkiPage() -> impl IntoView {
    // Form State
    let (common_name, set_common_name) = signal("example.com".to_string());
    let (organization, set_organization) = signal("Example Org".to_string());
    let (ttl, set_ttl) = signal("3600".to_string());
    let (loading, set_loading) = signal(false);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    // Result State
    let (result, set_result) = signal(Option::<CertResponse>::None);

    let generate_cert = move |_| {
        set_loading.set(true);
        set_error_msg.set(None);
        set_result.set(None);

        let cn = common_name.get();
        let org = organization.get();
        let ttl_val = ttl.get().parse::<u64>().unwrap_or(3600);

        spawn_local(async move {
            let req = GenerateCertRequest {
                common_name: cn,
                organization: Some(org),
                ttl: Some(ttl_val),
                key_type: Some("rsa".to_string()),
                key_bits: Some(2048),
            };

            match post::<CertResponse, _>("/pki/issue", req).await {
                Ok(res) => set_result.set(Some(res)),
                Err(e) => set_error_msg.set(Some(format!("Error: {}", e))),
            }
            set_loading.set(false);
        });
    };

    view! {
        <div class="space-y-6">
            <div class="flex items-center justify-between">
                <h1 class="text-2xl font-bold text-gray-900">"PKI Engine"</h1>
                <div class="flex space-x-2">
                    <span class="px-2 py-1 text-xs font-semibold bg-purple-100 text-purple-800 rounded-full">"BETA"</span>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <Card>
                    <div class="p-6 space-y-4">
                        <h3 class="text-lg font-medium text-gray-900">"Generate Certificate"</h3>

                        <Input
                            label="Common Name"
                            placeholder="e.g. www.example.com"
                            value=common_name
                            on_input=Box::new(move |v| set_common_name.set(v))
                        />
                        <Input
                            label="Organization"
                            value=organization
                            on_input=Box::new(move |v| set_organization.set(v))
                        />
                        <Input
                            label="TTL (seconds)"
                            value=ttl
                            type_="number"
                            on_input=Box::new(move |v| set_ttl.set(v))
                        />

                        <div class="pt-2">
                            <Button
                                loading=loading
                                on_click=Box::new(generate_cert)
                            >
                                "Generate Certificate"
                            </Button>
                        </div>

                        <Show when=move || error_msg.get().is_some()>
                            <div class="p-4 rounded-md bg-red-50 text-red-700 text-sm border border-red-200">
                                {move || error_msg.get()}
                            </div>
                        </Show>
                    </div>
                </Card>

                <Show when=move || result.get().is_some()>
                    {move || {
                        let res = result.get().unwrap();
                        view! {
                            <Card>
                                <div class="p-6 space-y-4">
                                    <h3 class="text-lg font-medium text-green-700 flex items-center gap-2">
                                        <span>"✅ Certificate Issued"</span>
                                    </h3>

                                    <div class="space-y-1">
                                        <label class="block text-xs font-medium text-gray-500 uppercase">"Serial Number"</label>
                                        <div class="text-sm font-mono bg-gray-50 p-2 rounded border border-gray-200 break-all">
                                            {res.serial_number}
                                        </div>
                                    </div>

                                    <div class="space-y-1">
                                        <label class="block text-xs font-medium text-gray-500 uppercase">"Certificate (PEM)"</label>
                                        <div class="relative group">
                                            <textarea
                                                readonly
                                                class="block w-full px-3 py-2 text-xs font-mono bg-gray-50 border border-gray-200 rounded-md h-32 focus:ring-0 focus:border-gray-200 resize-none"
                                            >
                                                {res.certificate.clone()}
                                            </textarea>
                                            <button
                                                class="absolute top-2 right-2 p-1 bg-white border border-gray-300 rounded hover:bg-gray-50 opacity-0 group-hover:opacity-100 transition shadow-sm"
                                                title="Copy"
                                                on:click=move |_| { let _ = web_sys::window().unwrap().navigator().clipboard().write_text(&res.certificate); }
                                            >
                                                "📋"
                                            </button>
                                        </div>
                                    </div>

                                    <div class="space-y-1">
                                        <label class="block text-xs font-medium text-gray-500 uppercase">"Private Key (PEM)"</label>
                                        <div class="relative group">
                                            <textarea
                                                readonly
                                                class="block w-full px-3 py-2 text-xs font-mono bg-gray-50 border border-gray-200 rounded-md h-32 focus:ring-0 focus:border-gray-200 resize-none"
                                            >
                                                {res.private_key.clone()}
                                            </textarea>
                                            <button
                                                class="absolute top-2 right-2 p-1 bg-white border border-gray-300 rounded hover:bg-gray-50 opacity-0 group-hover:opacity-100 transition shadow-sm"
                                                title="Copy"
                                                on:click=move |_| { let _ = web_sys::window().unwrap().navigator().clipboard().write_text(&res.private_key); }
                                            >
                                                "📋"
                                            </button>
                                        </div>
                                    </div>
                                </div>
                            </Card>
                        }
                    }}
                </Show>
            </div>
        </div>
    }
}
