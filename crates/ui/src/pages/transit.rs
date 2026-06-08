use crate::api;
use crate::components::{Button, Card, Input};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// API Structures matching backend transit engine

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KeyType {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Ed25519,
    EcdsaP256,
    EcdsaSecp256k1,
    X25519,
    #[serde(rename = "Rsa")]
    Rsa(u32),
}

impl KeyType {
    pub fn to_string_display(&self) -> String {
        match self {
            KeyType::Aes256Gcm => "AES-256-GCM".to_string(),
            KeyType::ChaCha20Poly1305 => "ChaCha20-Poly1305".to_string(),
            KeyType::XChaCha20Poly1305 => "XChaCha20-Poly1305".to_string(),
            KeyType::Ed25519 => "Ed25519".to_string(),
            KeyType::EcdsaP256 => "ECDSA-P256".to_string(),
            KeyType::EcdsaSecp256k1 => "ECDSA-secp256k1".to_string(),
            KeyType::X25519 => "X25519".to_string(),
            KeyType::Rsa(size) => format!("RSA-{}", size),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum KeyUsage {
    Encrypt,
    Decrypt,
    Sign,
    Verify,
    Derive,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct KeyInfo {
    pub name: String,
    pub key_type: KeyType,
    pub latest_version: u32,
    pub min_decryption_version: u32,
    pub created_at: String,
    pub last_rotated_at: Option<String>,
    pub versions: Vec<u32>,
    pub usage: Vec<KeyUsage>,
    pub exportable: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateKeyRequest {
    pub key_type: Option<KeyType>,
    pub exportable: bool,
    pub usage: Vec<KeyUsage>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptRequest {
    pub plaintext: String,       // base64 encoded
    pub context: Option<String>, // base64 encoded
    pub key_version: Option<u32>,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub input: String, // base64 encoded
    pub algorithm: Option<String>,
    pub key_version: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub input: String, // base64 encoded
    pub signature: String,
    pub algorithm: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[component]
pub fn TransitPage() -> impl IntoView {
    // State
    let (keys, set_keys) = signal(Vec::<KeyInfo>::new());
    let (selected_key, set_selected_key) = signal(Option::<KeyInfo>::None);
    let (active_tab, set_active_tab) = signal("encrypt".to_string());

    // Create Key Form
    let (new_key_name, set_new_key_name) = signal(String::new());
    let (new_key_type, set_new_key_type) = signal("Aes256Gcm".to_string());
    let (create_status, set_create_status) = signal(Option::<String>::None);

    // Operation Forms
    let (input_text, set_input_text) = signal(String::new());
    let (signature_input, set_signature_input) = signal(String::new()); // For verification
    let (output_result, set_output_result) = signal(String::new());
    let (verify_result, set_verify_result) = signal(Option::<bool>::None);
    let (error_msg, set_error_msg) = signal(Option::<String>::None);
    let (selected_algo, set_selected_algo) = signal("Aes256Gcm".to_string());

    // Fetch Keys
    let fetch_keys = Action::new_local(move |_: &()| async move {
        #[derive(Deserialize)]
        struct TransitListResponse {
            keys: Vec<String>,
        }
        match api::get::<TransitListResponse>("/transit/keys").await {
            Ok(res) => {
                let mut k_infos = Vec::new();
                for name in res.keys {
                    match api::get::<KeyInfo>(&format!("/transit/keys/{}", name)).await {
                        Ok(info) => k_infos.push(info),
                        Err(e) => {
                            web_sys::console::error_2(
                                &format!("Failed to fetch key info for {}:", name).into(),
                                &format!("{:?}", e).into(),
                            );
                        }
                    }
                }
                set_keys.set(k_infos);
            }
            Err(e) => set_error_msg.set(Some(format!("Failed to fetch keys: {:?}", e))),
        }
    });

    // Initial fetch
    Effect::new(move |_| {
        fetch_keys.dispatch(());
    });

    // Create Key Action
    let create_key_action = Action::new_local(move |_: &()| {
        let name = new_key_name.get();
        let k_type_str = new_key_type.get();
        async move {
            if name.is_empty() {
                set_create_status.set(Some("Key name required".to_string()));
                return;
            }

            let k_type = match k_type_str.as_str() {
                "Aes256Gcm" => KeyType::Aes256Gcm,
                "ChaCha20Poly1305" => KeyType::ChaCha20Poly1305,
                "XChaCha20Poly1305" => KeyType::XChaCha20Poly1305,
                "Ed25519" => KeyType::Ed25519,
                "EcdsaP256" => KeyType::EcdsaP256,
                "EcdsaSecp256k1" => KeyType::EcdsaSecp256k1,
                "X25519" => KeyType::X25519,
                _ => KeyType::Aes256Gcm,
            };

            let req = CreateKeyRequest {
                key_type: Some(k_type.clone()),
                exportable: false,
                usage: match k_type {
                    KeyType::Aes256Gcm | KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => {
                        vec![KeyUsage::Encrypt, KeyUsage::Decrypt]
                    }
                    KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => {
                        vec![KeyUsage::Sign, KeyUsage::Verify]
                    }
                    _ => vec![KeyUsage::Encrypt, KeyUsage::Decrypt],
                },
            };

            match api::post::<serde_json::Value, _>(&format!("/transit/keys/{}", name), req).await {
                Ok(_) => {
                    set_create_status.set(Some("Key created successfully".to_string()));
                    set_new_key_name.set(String::new());
                    fetch_keys.dispatch(()); // Refresh list
                }
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
                let req = EncryptRequest {
                    plaintext: b64_text,
                    context: None,
                    key_version: None,
                };
                match api::post::<EncryptResponse, _>(&format!("/transit/encrypt/{}", k.name), req)
                    .await
                {
                    Ok(res) => {
                        set_output_result.set(res.ciphertext);
                        set_error_msg.set(None);
                    }
                    Err(e) => {
                        set_output_result.set(String::new());
                        set_error_msg.set(Some(format!("Encryption failed: {:?}", e)));
                    }
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
                    ciphertext,
                    context: None,
                };
                match api::post::<DecryptResponse, _>(&format!("/transit/decrypt/{}", k.name), req)
                    .await
                {
                    Ok(res) => match BASE64.decode(&res.plaintext) {
                        Ok(bytes) => {
                            let s = String::from_utf8_lossy(&bytes).to_string();
                            set_output_result.set(s);
                            set_error_msg.set(None);
                        }
                        Err(_) => {
                            set_output_result.set(String::new());
                            set_error_msg
                                .set(Some("Failed to decode plaintext result".to_string()));
                        }
                    },
                    Err(e) => {
                        set_output_result.set(String::new());
                        set_error_msg.set(Some(format!("Decryption failed: {:?}", e)));
                    }
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
                    input: b64_input,
                    algorithm: Some(algo),
                    key_version: None,
                };
                match api::post::<SignResponse, _>(&format!("/transit/sign/{}", k.name), req).await
                {
                    Ok(res) => {
                        set_output_result.set(res.signature);
                        set_error_msg.set(None);
                    }
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
                    input: b64_input,
                    signature: sig_trimmed.to_string(),
                    algorithm: Some(algo),
                };
                match api::post::<VerifyResponse, _>(&format!("/transit/verify/{}", k.name), req)
                    .await
                {
                    Ok(res) => {
                        set_verify_result.set(Some(res.valid));
                        set_error_msg.set(None);
                    }
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
                                <option value="Aes256Gcm">"AES-256-GCM"</option>
                                <option value="ChaCha20Poly1305">"ChaCha20-Poly1305"</option>
                                <option value="XChaCha20Poly1305">"XChaCha20-Poly1305"</option>
                                <option value="Ed25519">"Ed25519"</option>
                                <option value="EcdsaP256">"ECDSA-P256"</option>
                                <option value="EcdsaSecp256k1">"ECDSA-secp256k1"</option>
                                <option value="X25519">"X25519"</option>
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
                                                let is_sel = selected_key.get().as_ref().map(|sk| sk.name == k_clone.name).unwrap_or(false);
                                                view! {
                                                    <li
                                                        class=format!(
                                                            "p-3 rounded cursor-pointer transition-colors border {}",
                                                            if is_sel { "bg-blue-50 border-blue-500 text-blue-700" } else { "hover:bg-gray-50 border-gray-200" }
                                                        )
                                                        on:click=move |_| {
                                                            set_selected_key.set(Some(k_clone.clone()));
                                                            // Auto-switch tab based on capability
                                                            match k_clone.key_type {
                                                                KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => {
                                                                    set_active_tab.set("sign".to_string());
                                                                    set_selected_algo.set(match k_clone.key_type {
                                                                        KeyType::EcdsaP256 => "EcdsaP256".to_string(),
                                                                        KeyType::EcdsaSecp256k1 => "EcdsaSecp256k1".to_string(),
                                                                        KeyType::Ed25519 => "Ed25519".to_string(),
                                                                        _ => "Ed25519".to_string(),
                                                                    });
                                                                },
                                                                KeyType::X25519 => {
                                                                    set_active_tab.set("encrypt".to_string());
                                                                    set_selected_algo.set("X25519".to_string());
                                                                },
                                                                _ => {
                                                                    set_active_tab.set("encrypt".to_string());
                                                                    set_selected_algo.set(match k_clone.key_type {
                                                                        KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => "ChaCha20Poly1305".to_string(),
                                                                        _ => "Aes256Gcm".to_string(),
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
                                                            <span class="text-xs bg-gray-100 px-2 py-1 rounded text-gray-500 uppercase">{k.key_type.to_string_display()}</span>
                                                        </div>
                                                        <div class="text-[10px] text-gray-400 mt-1 truncate">"Version: " {k.latest_version}</div>
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
                                                        {match k_type {
                                                            KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => view! {}.into_any(),
                                                            _ => view! {
                                                                <button
                                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "encrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                    on:click=move |_| {
                                                                        set_active_tab.set("encrypt".to_string());
                                                                        let algo = match k_type_for_encrypt {
                                                                            KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => "ChaCha20Poly1305",
                                                                            _ => "Aes256Gcm",
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
                                                                        let algo = match k_type_for_decrypt {
                                                                            KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => "ChaCha20Poly1305",
                                                                            _ => "Aes256Gcm",
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

                                                        {match k_type_for_sign {
                                                            KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1 => {
                                                                view! {
                                                                    <button
                                                                        class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "sign" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                        on:click=move |_| {
                                                                            set_active_tab.set("sign".to_string());
                                                                            let algo = match k_type_for_sign {
                                                                                KeyType::EcdsaP256 => "EcdsaP256",
                                                                                KeyType::EcdsaSecp256k1 => "EcdsaSecp256k1",
                                                                                KeyType::Ed25519 => "Ed25519",
                                                                                _ => "Ed25519",
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
                                                                            let algo = match k_type_for_verify {
                                                                                KeyType::EcdsaP256 => "EcdsaP256",
                                                                                KeyType::EcdsaSecp256k1 => "EcdsaSecp256k1",
                                                                                KeyType::Ed25519 => "Ed25519",
                                                                                _ => "Ed25519",
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
                                                        "decrypt" => "Ciphertext",
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
                                                        "decrypt" => "Enter ciphertext...",
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
                                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Signature"</label>
                                                        <textarea
                                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500 h-24 font-mono text-sm"
                                                            prop:value=signature_input
                                                            on:input=move |ev| set_signature_input.set(event_target_value(&ev))
                                                            placeholder="Enter signature..."
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
                                                                let key_info = selected_key.get();
                                                                if let Some(info) = key_info {
                                                                    match active_tab.get().as_str() {
                                                                        "encrypt" => match info.key_type {
                                                                            KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 => view! {
                                                                                <option value="ChaCha20Poly1305">"CHACHA20-POLY1305"</option>
                                                                            }.into_any(),
                                                                            _ => view! {
                                                                                <option value="Aes256Gcm">"AES-GCM"</option>
                                                                            }.into_any(),
                                                                        },
                                                                        "sign" | "verify" => match info.key_type {
                                                                            KeyType::EcdsaP256 => view! {
                                                                                <option value="EcdsaP256">"ECDSA-P256"</option>
                                                                            }.into_any(),
                                                                            KeyType::EcdsaSecp256k1 => view! {
                                                                                <option value="EcdsaSecp256k1">"ECDSA-secp256k1"</option>
                                                                            }.into_any(),
                                                                            KeyType::Ed25519 => view! {
                                                                                <option value="Ed25519">"Ed25519"</option>
                                                                            }.into_any(),
                                                                            _ => view! {
                                                                                <option value="Ed25519">"Ed25519"</option>
                                                                                <option value="EcdsaP256">"ECDSA-P256"</option>
                                                                                <option value="EcdsaSecp256k1">"ECDSA-secp256k1"</option>
                                                                            }.into_any(),
                                                                        },
                                                                        _ => view! {}.into_any()
                                                                    }
                                                                } else {
                                                                    view! {}.into_any()
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
                                                            <label class="block text-sm font-medium text-gray-700">"Result"</label>
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
