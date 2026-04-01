use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use crate::api;
use crate::components::{Button, Input, Card};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use std::collections::HashMap;

// API Structures matching backend crates/api/src/handlers/secret.rs

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyResponse {
    pub id: String,
    pub name: String,
    pub key_type: String,
    pub algorithm: String,
    pub size: u32,
    pub usage: Vec<String>,
    pub metadata: KeyMetadata,
    pub version: u32,
    pub created_at: String, // Backend uses DateTime, serialized to string
    pub status: String,
    pub public_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Default, PartialEq)]
pub struct KeyMetadata {
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub owner: Option<String>,
    pub purpose: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub name: String,
    pub key_type: String,
    pub algorithm: String,
    pub size: Option<u32>,
    pub usage: Vec<String>,
    pub metadata: Option<KeyMetadata>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub key_id: String,
    pub plaintext: String,       // base64 encoded
    pub context: Option<HashMap<String, String>>,
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EncryptResponse {
    pub ciphertext: String,
    pub key_version: u32,
    pub algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecryptRequest {
    pub key_id: String,
    pub ciphertext: String,
    pub context: Option<HashMap<String, String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct DecryptResponse {
    pub plaintext: String, // base64 encoded
    pub key_version: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub key_id: String,
    pub data: String, // base64 encoded
    pub algorithm: Option<String>,
    pub format: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignResponse {
    pub signature: String,
    pub key_version: u32,
    pub algorithm: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub key_id: String,
    pub data: String, // base64 encoded
    pub signature: String,
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerifyResponse {
    pub valid: bool,
    pub key_version: u32,
}

#[component]
pub fn TransitPage() -> impl IntoView {
    // State
    let (keys, set_keys) = signal(Vec::<KeyResponse>::new());
    let (selected_key, set_selected_key) = signal(Option::<KeyResponse>::None);
    let (active_tab, set_active_tab) = signal("encrypt".to_string());

    // Create Key Form
    let (new_key_name, set_new_key_name) = signal(String::new());
    let (new_key_type, set_new_key_type) = signal("aes256-gcm".to_string());
    let (create_status, set_create_status) = signal(Option::<String>::None);

    // Operation Forms
    let (input_text, set_input_text) = signal(String::new());
    let (signature_input, set_signature_input) = signal(String::new()); // For verification
    let (output_result, set_output_result) = signal(String::new());
    let (verify_result, set_verify_result) = signal(Option::<bool>::None);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (selected_algo, set_selected_algo) = signal("AES-GCM".to_string());

    // Fetch Keys
    let fetch_keys = Action::new_local(move |_: &()| {
        async move {
            match api::get::<Vec<KeyResponse>>("/secret/keys").await {
                Ok(res) => set_keys.set(res),
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
            let req = CreateKeyRequest {
                name: name.clone(),
                key_type: k_type.clone(),
                algorithm: k_type.clone(),
                size: match k_type.as_str() {
                    "rsa-2048" => Some(2048),
                    "rsa-4096" => Some(4096),
                    _ => Some(256),
                },
                usage: match k_type.as_str() {
                    "ed25519" | "ecdsa-p256" | "ecdsa-p384" | "rsa-2048" | "rsa-4096" => vec!["sign".to_string(), "verify".to_string()],
                    _ => vec!["encrypt".to_string(), "decrypt".to_string()],
                },
                metadata: None,
            };
            match api::post::<KeyResponse, _>("/secret/keys", req).await {
                Ok(_) => {
                    set_create_status.set(Some("Key created successfully".to_string()));
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
        let algo = selected_algo.get();
        async move {
            if let Some(k) = key {
                let b64_text = BASE64.encode(text.as_bytes());
                let req = EncryptRequest {
                    key_id: k.id,
                    plaintext: b64_text,
                    context: None,
                    algorithm: Some(algo),
                };
                match api::post::<EncryptResponse, _>("/secret/encrypt", req).await {
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
                let req = DecryptRequest {
                    key_id: k.id,
                    ciphertext,
                    context: None,
                };
                match api::post::<DecryptResponse, _>("/secret/decrypt", req).await {
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

    // Sign Action
    let sign_action = Action::new_local(move |_: &()| {
        let key = selected_key.get();
        let text = input_text.get();
        let algo = selected_algo.get();
        async move {
            if let Some(k) = key {
                let b64_input = BASE64.encode(text.as_bytes());
                let req = SignRequest {
                    key_id: k.id,
                    data: b64_input,
                    algorithm: Some(algo),
                    format: None,
                };
                match api::post::<SignResponse, _>("/secret/sign", req).await {
                    Ok(res) => {
                        set_output_result.set(res.signature);
                        set_error_msg.set(None);
                    },
                    Err(e) => {
                        set_output_result.set(String::new());
                        set_error_msg.set(Some(format!("Signing failed: {:?}", e)));
                    }
                }
            }
        }
    });

    // Verify Action
    let verify_action = Action::new_local(move |_: &()| {
        let key = selected_key.get();
        let text = input_text.get(); // Data to verify
        let sig = signature_input.get();
        let algo = selected_algo.get();
        async move {
            if let Some(k) = key {
                let text_trimmed = text.trim();
                let sig_trimmed = sig.trim();

                let b64_input = BASE64.encode(text_trimmed.as_bytes());
                let req = VerifyRequest {
                    key_id: k.id,
                    data: b64_input,
                    signature: sig_trimmed.to_string(),
                    algorithm: Some(algo)
                };
                match api::post::<VerifyResponse, _>("/secret/verify", req).await {
                    Ok(res) => {
                        set_verify_result.set(Some(res.valid));
                        set_error_msg.set(None);
                    },
                    Err(e) => {
                        set_verify_result.set(None);
                        set_error_msg.set(Some(format!("Verification failed: {:?}", e)));
                    }
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
                                <option value="rsa-2048">"RSA-2048"</option>
                                <option value="rsa-4096">"RSA-4096"</option>
                                <option value="ecdsa-p256">"ECDSA-P256"</option>
                                <option value="ecdsa-p384">"ECDSA-P384"</option>
                                <option value="ed25519">"Ed25519"</option>
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
                                                let is_sel = selected_key.get().as_ref().map(|sk| sk.id == k_clone.id).unwrap_or(false);
                                                view! {
                                                    <li
                                                        class=format!(
                                                            "p-3 rounded cursor-pointer transition-colors border {}",
                                                            if is_sel { "bg-blue-50 border-blue-500 text-blue-700" } else { "hover:bg-gray-50 border-gray-200" }
                                                        )
                                                        on:click=move |_| {
                                                            set_selected_key.set(Some(k_clone.clone()));
                                                            // Auto-switch tab based on capability
                                                            match k_clone.key_type.as_str() {
                                                                "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
                                                                    set_active_tab.set("sign".to_string());
                                                                    set_selected_algo.set(match k_clone.key_type.as_str() {
                                                                        "rsa-2048" | "rsa-4096" => "RSA-PSS".to_string(),
                                                                        "ecdsa-p256" | "ecdsa-p384" => "ECDSA-SHA256".to_string(),
                                                                        "ed25519" => "ED25519".to_string(),
                                                                        _ => "RSA-PSS".to_string(),
                                                                    });
                                                                },
                                                                _ => {
                                                                    set_active_tab.set("encrypt".to_string());
                                                                    set_selected_algo.set("AES-GCM".to_string());
                                                                }
                                                            }
                                                            set_output_result.set(String::new());
                                                            set_input_text.set(String::new());
                                                            set_signature_input.set(String::new());
                                                            set_verify_result.set(None);
                                                            set_error_msg.set(None);
                                                        }
                                                    >
                                                        <div class="flex justify-between items-center">
                                                            <span class="font-medium">{k.name}</span>
                                                            <span class="text-xs bg-gray-100 px-2 py-1 rounded text-gray-500 uppercase">{k.key_type}</span>
                                                        </div>
                                                        <div class="text-[10px] text-gray-400 mt-1 truncate">{k.id}</div>
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
                                let key_for_tabs = key.clone();
                                view! {
                                    <Card>
                                        <div class="flex justify-between items-center mb-6">
                                            <h2 class="text-lg font-semibold">"Operations: " <span class="text-blue-600">{key.name}</span></h2>
                                            {
                                                let k_type = key_for_tabs.key_type.clone();
                                                view! {
                                                    <div class="flex space-x-2 bg-gray-100 p-1 rounded-lg">
                                                        <button
                                                            class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "encrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                            on:click=move |_| {
                                                                set_active_tab.set("encrypt".to_string());
                                                                set_selected_algo.set("AES-GCM".to_string());
                                                                set_output_result.set(String::new());
                                                                set_input_text.set(String::new());
                                                                set_error_msg.set(None);
                                                            }
                                                        >
                                                            "Encrypt"
                                                        </button>
                                                        <button
                                                            class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "decrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                            on:click=move |_| {
                                                                set_active_tab.set("decrypt".to_string());
                                                                set_selected_algo.set("AES-GCM".to_string());
                                                                set_output_result.set(String::new());
                                                                set_input_text.set(String::new());
                                                                set_error_msg.set(None);
                                                            }
                                                        >
                                                            "Decrypt"
                                                        </button>

                                                        {match k_type.as_str() {
                                                            "rsa-2048" | "rsa-4096" | "ecdsa-p256" | "ecdsa-p384" | "ed25519" => {
                                                                view! {
                                                                    <button
                                                                        class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "sign" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                        on:click=move |_| {
                                                                            set_active_tab.set("sign".to_string());
                                                                            set_selected_algo.set("RSA-PSS".to_string());
                                                                            set_output_result.set(String::new());
                                                                            set_input_text.set(String::new());
                                                                            set_error_msg.set(None);
                                                                        }
                                                                    >
                                                                        "Sign"
                                                                    </button>
                                                                    <button
                                                                        class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "verify" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                        on:click=move |_| {
                                                                            set_active_tab.set("verify".to_string());
                                                                            set_selected_algo.set("RSA-PSS".to_string());
                                                                            set_output_result.set(String::new());
                                                                            set_input_text.set(String::new());
                                                                            set_signature_input.set(String::new());
                                                                            set_verify_result.set(None);
                                                                            set_error_msg.set(None);
                                                                        }
                                                                    >
                                                                        "Verify"
                                                                    </button>
                                                                }.into_any()
                                                            },
                                                            _ => view! {}.into_any()
                                                        }}
                                                    </div>
                                                }
                                            }
                                        </div>

                                        <div class="space-y-4">
                                            // Input Text (Common for all)
                                            <div>
                                                <label class="block text-sm font-medium text-gray-700 mb-1">
                                                    {move || match active_tab.get().as_str() {
                                                        "encrypt" => "Plaintext",
                                                        "decrypt" => "Ciphertext (Base64)",
                                                        "sign" => "Data to Sign",
                                                        "verify" => "Original Data",
                                                        _ => "Input"
                                                    }}
                                                </label>
                                                <textarea
                                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 h-32 font-mono text-sm"
                                                    prop:value=input_text
                                                    on:input=move |ev| set_input_text.set(event_target_value(&ev))
                                                    placeholder=move || match active_tab.get().as_str() {
                                                        "encrypt" => "Enter text to encrypt...",
                                                        "decrypt" => "Enter base64 ciphertext...",
                                                        "sign" => "Enter data to sign...",
                                                        "verify" => "Enter original data...",
                                                        _ => ""
                                                    }
                                                ></textarea>
                                            </div>

                                            // Extra fields for Verify
                                            {move || if active_tab.get() == "verify" {
                                                view! {
                                                    <div>
                                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Signature (Base64)"</label>
                                                        <textarea
                                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 h-24 font-mono text-sm"
                                                            prop:value=signature_input
                                                            on:input=move |ev| set_signature_input.set(event_target_value(&ev))
                                                            placeholder="Enter base64 signature..."
                                                        ></textarea>
                                                    </div>
                                                }.into_any()
                                            } else {
                                                view! {}.into_any()
                                            }}

                                            // Algorithm Selector
                                            <div>
                                                <label class="block text-sm font-medium text-gray-700 mb-1">"Algorithm"</label>
                                                <select
                                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                                    on:change=move |ev| set_selected_algo.set(event_target_value(&ev))
                                                    prop:value=selected_algo
                                                >
                                                    {move || match active_tab.get().as_str() {
                                                        "encrypt" | "decrypt" => view! {
                                                            <option value="AES-GCM">"AES-GCM"</option>
                                                            <option value="CHACHA20-POLY1305">"CHACHA20-POLY1305"</option>
                                                        }.into_any(),
                                                        "sign" | "verify" => view! {
                                                            <option value="RSA-PSS">"RSA-PSS"</option>
                                                            <option value="RSA-PKCS1v15">"RSA-PKCS1v15"</option>
                                                            <option value="ECDSA-SHA256">"ECDSA-SHA256"</option>
                                                            <option value="ED25519">"ED25519"</option>
                                                        }.into_any(),
                                                        _ => view! {}.into_any()
                                                    }}
                                                </select>
                                            </div>

                                            <div class="flex justify-end">
                                                <Button
                                                    on_click=Box::new(move |_| {
                                                        match active_tab.get().as_str() {
                                                            "encrypt" => { encrypt_action.dispatch(()); },
                                                            "decrypt" => { decrypt_action.dispatch(()); },
                                                            "sign" => { sign_action.dispatch(()); },
                                                            "verify" => { verify_action.dispatch(()); },
                                                            _ => {}
                                                        }
                                                    })
                                                >
                                                    {move || match active_tab.get().as_str() {
                                                        "encrypt" => "Encrypt Data",
                                                        "decrypt" => "Decrypt Data",
                                                        "sign" => "Sign Data",
                                                        "verify" => "Verify Signature",
                                                        _ => "Submit"
                                                    }}
                                                </Button>
                                            </div>

                                            {move || error_msg.get().map(|msg| view! {
                                                <div class="p-4 bg-red-50 text-red-700 rounded-md border border-red-200">
                                                    {msg}
                                                </div>
                                            })}

                                            // Output for Encrypt/Decrypt/Sign
                                            {move || {
                                                let res = output_result.get();
                                                if !res.is_empty() && active_tab.get() != "verify" {
                                                    view! {
                                                        <div class="space-y-1">
                                                            <label class="block text-sm font-medium text-gray-700">"Result (Base64)"</label>
                                                            <div class="relative">
                                                                <pre class="bg-gray-800 text-gray-100 p-4 rounded-md overflow-x-auto text-sm font-mono break-all whitespace-pre-wrap">
                                                                    {res}
                                                                </pre>
                                                            </div>
                                                        </div>
                                                    }.into_any()
                                                } else {
                                                    view! {}.into_any()
                                                }
                                            }}

                                            // Output for Verify
                                            {move || {
                                                if active_tab.get() == "verify" {
                                                    if let Some(valid) = verify_result.get() {
                                                        view! {
                                                            <div class=format!("p-4 rounded-md border text-center font-bold {}", if valid { "bg-green-50 text-green-700 border-green-200" } else { "bg-red-50 text-red-700 border-red-200" })>
                                                                {if valid { "Signature Valid ✅" } else { "Signature Invalid ❌" }}
                                                            </div>
                                                        }.into_any()
                                                    } else {
                                                        view! {}.into_any()
                                                    }
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
