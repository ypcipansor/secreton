use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use crate::api;
use crate::components::{Button, Input, Card};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};

// API Structures
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ListKeysResponse {
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateKeyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,       // base64 encoded
    pub context: Option<String>, // base64 encoded
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptResponse {
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub ciphertext: String,
    pub context: Option<String>, // base64 encoded
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DecryptResponse {
    pub plaintext: String, // base64 encoded
}

#[component]
pub fn TransitPage() -> impl IntoView {
    // State
    let (keys, set_keys) = signal(Vec::<String>::new());
    let (selected_key, set_selected_key) = signal(Option::<String>::None);
    let (active_tab, set_active_tab) = signal("encrypt".to_string());

    // Create Key Form
    let (new_key_name, set_new_key_name) = signal(String::new());
    let (new_key_type, set_new_key_type) = signal("aes256-gcm".to_string());
    let (create_status, set_create_status) = signal(Option::<String>::None);

    // Encrypt/Decrypt Form
    let (input_text, set_input_text) = signal(String::new());
    let (output_result, set_output_result) = signal(String::new());
    let (error_msg, set_error_msg) = signal(Option::<String>::None);

    // Fetch Keys
    let fetch_keys = Action::new_local(move |_: &()| {
        async move {
            match api::get::<ListKeysResponse>("/transit/keys").await {
                Ok(res) => set_keys.set(res.keys),
                Err(e) => set_error_msg.set(Some(format!("Failed to fetch keys: {:?}", e))),
            }
        }
    });

    // Initial fetch
    Effect::new(move |_| {
        fetch_keys.dispatch(());
    });

    // Create Key Action
    let create_key_action = Action::new_local(move |_: &()| {
        let name = new_key_name.get();
        let k_type = new_key_type.get();
        async move {
            if name.is_empty() {
                set_create_status.set(Some("Key name required".to_string()));
                return;
            }
            let req = CreateKeyRequest { key_type: Some(k_type) };
            let path = format!("/transit/keys/{}", name);
            match api::post::<CreateKeyResponse, _>(&path, req).await {
                Ok(res) => {
                    set_create_status.set(Some(res.message));
                    set_new_key_name.set(String::new());
                    fetch_keys.dispatch(()); // Refresh list
                },
                Err(e) => set_create_status.set(Some(format!("Error: {:?}", e))),
            }
        }
    });

    // Encrypt Action
    let encrypt_action = Action::new_local(move |_: &()| {
        let key = selected_key.get();
        let text = input_text.get();
        async move {
            if let Some(k) = key {
                let b64_text = BASE64.encode(text.as_bytes());
                let req = EncryptRequest { plaintext: b64_text, context: None };
                let path = format!("/transit/encrypt/{}", k);
                match api::post::<EncryptResponse, _>(&path, req).await {
                    Ok(res) => {
                        set_output_result.set(res.ciphertext);
                        set_error_msg.set(None);
                    },
                    Err(e) => {
                        set_output_result.set(String::new());
                        set_error_msg.set(Some(format!("Encryption failed: {:?}", e)));
                    },
                }
            }
        }
    });

    // Decrypt Action
    let decrypt_action = Action::new_local(move |_: &()| {
        let key = selected_key.get();
        let ciphertext = input_text.get();
        async move {
            if let Some(k) = key {
                let req = DecryptRequest { ciphertext, context: None };
                let path = format!("/transit/decrypt/{}", k);
                match api::post::<DecryptResponse, _>(&path, req).await {
                    Ok(res) => {
                        match BASE64.decode(&res.plaintext) {
                            Ok(bytes) => {
                                let s = String::from_utf8_lossy(&bytes).to_string();
                                set_output_result.set(s);
                                set_error_msg.set(None);
                            },
                            Err(_) => {
                                set_output_result.set(String::new());
                                set_error_msg.set(Some("Failed to decode plaintext result".to_string()));
                            },
                        }
                    },
                    Err(e) => {
                        set_output_result.set(String::new());
                        set_error_msg.set(Some(format!("Decryption failed: {:?}", e)));
                    },
                }
            }
        }
    });

    view! {
        <div class="space-y-6">
            <div class="flex justify-between items-center">
                <h1 class="text-2xl font-bold text-gray-800">"Transit Engine"</h1>
                <span class="text-sm text-gray-500">"Encryption as a Service"</span>
            </div>

            // Section: Create Key
            <Card>
                <div class="space-y-4">
                    <h2 class="text-lg font-semibold">"Create New Key"</h2>
                    <div class="flex gap-4 items-end">
                        <div class="flex-1">
                            <label class="block text-sm font-medium text-gray-700 mb-1">"Key Name"</label>
                            <Input
                                value=new_key_name
                                on_input=Box::new(move |v| set_new_key_name.set(v))
                                placeholder="my-app-key"
                            />
                        </div>
                        <div class="w-48">
                            <label class="block text-sm font-medium text-gray-700 mb-1">"Type"</label>
                            <select
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                on:change=move |ev| set_new_key_type.set(event_target_value(&ev))
                                prop:value=new_key_type
                            >
                                <option value="aes256-gcm">"AES-256-GCM"</option>
                                <option value="chacha20-poly1305">"ChaCha20-Poly1305"</option>
                                <option value="ed25519">"Ed25519 (Sign)"</option>
                            </select>
                        </div>
                        <Button on_click=Box::new(move |_| { create_key_action.dispatch(()); })>"Create"</Button>
                    </div>
                    {move || create_status.get().map(|s| view! { <p class="text-sm text-gray-600">{s}</p> })}
                </div>
            </Card>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                // Section: Key List
                <div class="lg:col-span-1">
                    <Card>
                        <h2 class="text-lg font-semibold mb-4">"Keys"</h2>
                        <div class="space-y-2">
                            {move || {
                                let k_list = keys.get();
                                if k_list.is_empty() {
                                    view! { <p class="text-gray-500 italic">"No keys found"</p> }.into_any()
                                } else {
                                    view! {
                                        <ul class="space-y-2">
                                            {k_list.into_iter().map(|k| {
                                                let k_clone = k.clone();
                                                let is_sel = selected_key.get() == Some(k.clone());
                                                view! {
                                                    <li
                                                        class=format!(
                                                            "p-3 rounded cursor-pointer transition-colors border {}",
                                                            if is_sel { "bg-blue-50 border-blue-500 text-blue-700" } else { "hover:bg-gray-50 border-gray-200" }
                                                        )
                                                        on:click=move |_| {
                                                            set_selected_key.set(Some(k_clone.clone()));
                                                            set_output_result.set(String::new());
                                                            set_input_text.set(String::new());
                                                            set_error_msg.set(None);
                                                        }
                                                    >
                                                        {k}
                                                    </li>
                                                }
                                            }).collect::<Vec<_>>()}
                                        </ul>
                                    }.into_any()
                                }
                            }}
                        </div>
                    </Card>
                </div>

                // Section: Operations
                <div class="lg:col-span-2">
                    {move || {
                        match selected_key.get() {
                            None => view! {
                                <div class="h-full flex items-center justify-center p-8 border-2 border-dashed border-gray-200 rounded-lg text-gray-400">
                                    "Select a key to perform operations"
                                </div>
                            }.into_any(),
                            Some(key) => {
                                view! {
                                    <Card>
                                        <div class="flex justify-between items-center mb-6">
                                            <h2 class="text-lg font-semibold">"Operations: " <span class="text-blue-600">{key}</span></h2>
                                            <div class="flex space-x-2 bg-gray-100 p-1 rounded-lg">
                                                <button
                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "encrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                    on:click=move |_| set_active_tab.set("encrypt".to_string())
                                                >
                                                    "Encrypt"
                                                </button>
                                                <button
                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "decrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                    on:click=move |_| set_active_tab.set("decrypt".to_string())
                                                >
                                                    "Decrypt"
                                                </button>
                                            </div>
                                        </div>

                                        <div class="space-y-4">
                                            <div>
                                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                                    {move || if active_tab.get() == "encrypt" { "Plaintext" } else { "Ciphertext" }}
                                                </label>
                                                <textarea
                                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 h-32 font-mono text-sm"
                                                    prop:value=input_text
                                                    on:input=move |ev| set_input_text.set(event_target_value(&ev))
                                                    placeholder=move || if active_tab.get() == "encrypt" { "Enter text to encrypt..." } else { "Enter ciphertext (vault:v1:...)" }
                                                ></textarea>
                                            </div>

                                            <div class="flex justify-end">
                                                <Button
                                                    on_click=Box::new(move |_| {
                                                        if active_tab.get() == "encrypt" {
                                                            encrypt_action.dispatch(());
                                                        } else {
                                                            decrypt_action.dispatch(());
                                                        }; // Semicolon added here
                                                    })
                                                >
                                                    {move || if active_tab.get() == "encrypt" { "Encrypt Data" } else { "Decrypt Data" }}
                                                </Button>
                                            </div>

                                            {move || error_msg.get().map(|msg| view! {
                                                <div class="p-4 bg-red-50 text-red-700 rounded-md border border-red-200">
                                                    {msg}
                                                </div>
                                            })}

                                            {move || {
                                                let res = output_result.get();
                                                if !res.is_empty() {
                                                    view! {
                                                        <div class="space-y-1">
                                                            <label class="block text-sm font-medium text-gray-700">"Result"</label>
                                                            <div class="relative">
                                                                <pre class="bg-gray-800 text-gray-100 p-4 rounded-md overflow-x-auto text-sm font-mono">
                                                                    {res}
                                                                </pre>
                                                            </div>
                                                        </div>
                                                    }.into_any()
                                                } else {
                                                    view! {}.into_any()
                                                }
                                            }}
                                        </div>
                                    </Card>
                                }.into_any()
                            }
                        }
                    }}
                </div>
            </div>
        </div>
    }
}
