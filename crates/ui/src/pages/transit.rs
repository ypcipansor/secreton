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
            // Using /api/v1/transit path for list keys if we want to align with Transit API
            // Actually, backend has /api/v1/transit/keys. Let's use that.
            #[derive(Deserialize)]
            struct TransitListResponse {
                keys: Vec<String>,
            }
            match api::get::<TransitListResponse>("/transit/keys").await {
                Ok(res) => {
                    // Fetch key info for each key to get the actual key_type
                    #[derive(Deserialize)]
                    struct TransitKeyInfo {
                        name: String,
                        key_type: String,
                        latest_version: Option<u32>,
                        #[serde(default)]
                        usage: Vec<String>,
                    }
                    // Helper to map transit KeyType enum serialization to UI key_type strings
                    fn map_key_type(raw: &str) -> String {
                        match raw {
                            "Aes256Gcm" => "aes256-gcm".to_string(),
                            "ChaCha20Poly1305" => "chacha20-poly1305".to_string(),
                            "XChaCha20Poly1305" => "xchacha20-poly1305".to_string(),
                            "Ed25519" => "ed25519".to_string(),
                            "EcdsaP256" => "ecdsa-p256".to_string(),
                            "EcdsaSecp256k1" => "ecdsa-secp256k1".to_string(),
                            "X25519" => "x25519".to_string(),
                            other => other.to_lowercase(),
                        }
                    }
                    let mut k_responses = Vec::new();
                    for name in res.keys {
                        // Fetch detailed key info from transit API
                        match api::get::<TransitKeyInfo>(&format!("/transit/keys/{}", name)).await {
                            Ok(info) => {
                                let kt = map_key_type(&info.key_type);
                                k_responses.push(KeyResponse {
                                    id: info.name.clone(),
                                    name: info.name,
                                    key_type: kt,
                                    algorithm: "unknown".to_string(),
                                    size: 0,
                                    usage: info.usage,
                                    metadata: KeyMetadata::default(),
                                    version: info.latest_version.unwrap_or(1),
                                    created_at: "".to_string(),
                                    status: "active".to_string(),
                                    public_key: None,
                                });
                            }
                            Err(_) => {
                                // Fallback: create placeholder if info fetch fails
                                k_responses.push(KeyResponse {
                                    id: name.clone(),
                                    name: name.clone(),
                                    key_type: "aes256-gcm".to_string(),
                                    algorithm: "unknown".to_string(),
                                    size: 0,
                                    usage: vec![],
                                    metadata: KeyMetadata::default(),
                                    version: 1,
                                    created_at: "".to_string(),
                                    status: "active".to_string(),
                                    public_key: None,
                                });
                            }
                        }
                    }
                    set_keys.set(k_responses);
                },
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
            #[derive(Serialize)]
            struct TransitCreateRequest {
                key_type: Option<String>,
            }
            let req = TransitCreateRequest {
                key_type: Some(k_type),
            };
            match api::post::<serde_json::Value, _>(&format!("/transit/keys/{}", name), req).await {
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
        async move {
            if let Some(k) = key {
                let b64_text = BASE64.encode(text.as_bytes());
                #[derive(Serialize)]
                struct TransitEncryptRequest {
                    plaintext: String,
                    context: Option<String>,
                }
                let req = TransitEncryptRequest {
                    plaintext: b64_text,
                    context: None,
                };
                #[derive(Deserialize)]
                struct TransitEncryptResponse {
                    ciphertext: String,
                }
                match api::post::<TransitEncryptResponse, _>(&format!("/transit/encrypt/{}", k.name), req).await {
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
                #[derive(Serialize)]
                struct TransitDecryptRequest {
                    ciphertext: String,
                    context: Option<String>,
                }
                let req = TransitDecryptRequest {
                    ciphertext,
                    context: None,
                };
                #[derive(Deserialize)]
                struct TransitDecryptResponse {
                    plaintext: String,
                }
                match api::post::<TransitDecryptResponse, _>(&format!("/transit/decrypt/{}", k.name), req).await {
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
                #[derive(Serialize)]
                struct TransitSignRequest {
                    input: String,
                    algorithm: Option<String>,
                    key_version: Option<u32>,
                }
                let req = TransitSignRequest {
                    input: b64_input,
                    algorithm: Some(algo.to_lowercase()),
                    key_version: None,
                };
                #[derive(Deserialize)]
                struct TransitSignResponse {
                    signature: String,
                }
                match api::post::<TransitSignResponse, _>(&format!("/transit/sign/{}", k.name), req).await {
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
                #[derive(Serialize)]
                struct TransitVerifyRequest {
                    input: String,
                    signature: String,
                    algorithm: Option<String>,
                }
                let req = TransitVerifyRequest {
                    input: b64_input,
                    signature: sig_trimmed.to_string(),
                    algorithm: Some(algo.to_lowercase())
                };
                #[derive(Deserialize)]
                struct TransitVerifyResponse {
                    valid: bool,
                }
                match api::post::<TransitVerifyResponse, _>(&format!("/transit/verify/{}", k.name), req).await {
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
                                <option value="xchacha20-poly1305">"XChaCha20-Poly1305"</option>
                                <option value="ed25519">"Ed25519"</option>
                                <option value="ecdsa-p256">"ECDSA-P256"</option>
                                <option value="ecdsa-secp256k1">"ECDSA-secp256k1"</option>
                                <option value="x25519">"X25519"</option>
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
                                                                "ed25519" | "ecdsa-p256" | "ecdsa-secp256k1" => {
                                                                    set_active_tab.set("sign".to_string());
                                                                    set_selected_algo.set(match k_clone.key_type.as_str() {
                                                                        "ecdsa-p256" => "ecdsa-p256".to_string(),
                                                                        "ecdsa-secp256k1" => "ecdsa-secp256k1".to_string(),
                                                                        "ed25519" => "ed25519".to_string(),
                                                                        _ => "ed25519".to_string(),
                                                                    });
                                                                },
                                                                _ => {
                                                                    set_active_tab.set("encrypt".to_string());
                                                                    set_selected_algo.set(match k_clone.key_type.as_str() {
                                                                        "chacha20-poly1305" | "xchacha20-poly1305" => "CHACHA20-POLY1305".to_string(),
                                                                        _ => "AES-GCM".to_string(),
                                                                    });
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
                                                let k_type_for_sign = k_type.clone();
                                                let k_type_for_verify = k_type.clone();
                                                let k_type_for_encrypt = k_type.clone();
                                                let k_type_for_decrypt = k_type.clone();
                                                view! {
                                                    <div class="flex space-x-2 bg-gray-100 p-1 rounded-lg">
                                                        {match k_type.as_str() {
                                                            "ed25519" | "ecdsa-p256" | "ecdsa-secp256k1" => view! {}.into_any(),
                                                            _ => view! {
                                                                <button
                                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "encrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                    on:click=move |_| {
                                                                        set_active_tab.set("encrypt".to_string());
                                                                        let algo = match k_type_for_encrypt.as_str() {
                                                                            "chacha20-poly1305" => "CHACHA20-POLY1305",
                                                                            _ => "AES-GCM",
                                                                        };
                                                                        set_selected_algo.set(algo.to_string());
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
                                                                        let algo = match k_type_for_decrypt.as_str() {
                                                                            "chacha20-poly1305" => "CHACHA20-POLY1305",
                                                                            _ => "AES-GCM",
                                                                        };
                                                                        set_selected_algo.set(algo.to_string());
                                                                        set_output_result.set(String::new());
                                                                        set_input_text.set(String::new());
                                                                        set_error_msg.set(None);
                                                                    }
                                                                >
                                                                    "Decrypt"
                                                                </button>
                                                            }.into_any()
                                                        }}

                                                        {match k_type_for_sign.as_str() {
                                                            "ed25519" | "ecdsa-p256" | "ecdsa-secp256k1" => {
                                                                view! {
                                                                    <button
                                                                        class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "sign" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                        on:click=move |_| {
                                                                            set_active_tab.set("sign".to_string());
                                                                            let algo = match k_type_for_sign.as_str() {
                                                                                "ecdsa-p256" => "ecdsa-p256",
                                                                                "ecdsa-secp256k1" => "ecdsa-secp256k1",
                                                                                "ed25519" => "ed25519",
                                                                                _ => "ed25519",
                                                                            };
                                                                            set_selected_algo.set(algo.to_string());
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
                                                                            let algo = match k_type_for_verify.as_str() {
                                                                                "ecdsa-p256" => "ecdsa-p256",
                                                                                "ecdsa-secp256k1" => "ecdsa-secp256k1",
                                                                                "ed25519" => "ed25519",
                                                                                _ => "ed25519",
                                                                            };
                                                                            set_selected_algo.set(algo.to_string());
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

                                            // Algorithm Selector (hidden for decrypt — backend determines algorithm from key)
                                            {move || if active_tab.get() == "decrypt" {
                                                view! {}.into_any()
                                            } else {
                                                view! {
                                                    <div>
                                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Algorithm"</label>
                                                        <select
                                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                                            on:change=move |ev| set_selected_algo.set(event_target_value(&ev))
                                                            prop:value=selected_algo
                                                        >
                                                            {move || {
                                                                let key_type = selected_key.get().map(|k| k.key_type.clone()).unwrap_or_default();
                                                                match active_tab.get().as_str() {
                                                                    "encrypt" => match key_type.as_str() {
                                                                        "chacha20-poly1305" => view! {
                                                                            <option value="CHACHA20-POLY1305">"CHACHA20-POLY1305"</option>
                                                                        }.into_any(),
                                                                        _ => view! {
                                                                            <option value="AES-GCM">"AES-GCM"</option>
                                                                        }.into_any(),
                                                                    },
                                                                    "sign" | "verify" => match key_type.as_str() {
                                                                        "ecdsa-p256" => view! {
                                                                            <option value="ecdsa-p256">"ECDSA-P256"</option>
                                                                        }.into_any(),
                                                                        "ecdsa-secp256k1" => view! {
                                                                            <option value="ecdsa-secp256k1">"ECDSA-secp256k1"</option>
                                                                        }.into_any(),
                                                                        "ed25519" => view! {
                                                                            <option value="ed25519">"Ed25519"</option>
                                                                        }.into_any(),
                                                                        _ => view! {
                                                                            <option value="ed25519">"Ed25519"</option>
                                                                            <option value="ecdsa-p256">"ECDSA-P256"</option>
                                                                            <option value="ecdsa-secp256k1">"ECDSA-secp256k1"</option>
                                                                        }.into_any(),
                                                                    },
                                                                    _ => view! {}.into_any()
                                                                }
                                                            }}
                                                        </select>
                                                    </div>
                                                }.into_any()
                                            }}

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
