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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignRequest {
    pub input: String, // base64 encoded
    pub algorithm: Option<String>,
    pub key_version: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SignResponse {
    pub signature: String,
    pub algorithm: Option<String>,
    pub key_version: Option<u32>,
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

// Simplified KeyInfo struct for frontend
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyInfo {
    pub name: String,
    pub key_type: KeyType,
    // other fields omitted for brevity if not needed
}

// KeyType enum matching backend
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Aes256Gcm,
    ChaCha20Poly1305,
    XChaCha20Poly1305,
    Ed25519,
    EcdsaP256,
    EcdsaSecp256k1,
    X25519,
    Rsa(u32),
}

#[component]
pub fn TransitPage() -> impl IntoView {
    // State
    let (keys, set_keys) = signal(Vec::<String>::new());
    let (selected_key, set_selected_key) = signal(Option::<String>::None);
    let (key_info, set_key_info) = signal(Option::<KeyInfo>::None);
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
    let (selected_algo, set_selected_algo) = signal("ed25519".to_string());

    // Fetch Keys
    let fetch_keys = Action::new_local(move |_: &()| {
        async move {
            match api::get::<ListKeysResponse>("/transit/keys").await {
                Ok(res) => set_keys.set(res.keys),
                Err(e) => set_error_msg.set(Some(format!("Failed to fetch keys: {:?}", e))),
            }
        }
    });

    // Fetch Key Info
    let fetch_key_info = Action::new_local(move |key_name: &String| {
        let name = key_name.clone();
        async move {
            let path = format!("/transit/keys/{}", name);
            match api::get::<KeyInfo>(&path).await {
                Ok(info) => {
                    // Auto-switch tab based on capability
                    match info.key_type {
                        KeyType::Ed25519 => {
                            set_active_tab.set("sign".to_string());
                            set_selected_algo.set("ed25519".to_string());
                        },
                        KeyType::EcdsaP256 => {
                            set_active_tab.set("sign".to_string());
                            set_selected_algo.set("ecdsa-p256".to_string());
                        },
                        KeyType::EcdsaSecp256k1 => {
                            set_active_tab.set("sign".to_string());
                            set_selected_algo.set("ecdsa-secp256k1".to_string());
                        },
                        _ => {
                            set_active_tab.set("encrypt".to_string());
                        }
                    }
                    set_key_info.set(Some(info));
                },
                Err(e) => {
                     set_error_msg.set(Some(format!("Failed to fetch key info: {:?}", e)));
                     set_key_info.set(None);
                }
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
                    key_version: None
                };
                let path = format!("/transit/sign/{}", k);
                match api::post::<SignResponse, _>(&path, req).await {
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
                // Trim inputs to avoid whitespace issues
                let text_trimmed = text.trim();
                let sig_trimmed = sig.trim();

                let b64_input = BASE64.encode(text_trimmed.as_bytes());
                let req = VerifyRequest {
                    input: b64_input,
                    signature: sig_trimmed.to_string(),
                    algorithm: Some(algo)
                };
                let path = format!("/transit/verify/{}", k);
                match api::post::<VerifyResponse, _>(&path, req).await {
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
                                <option value="ed25519">"Ed25519 (Sign)"</option>
                                <option value="ecdsa-p256">"ECDSA P-256 (Sign)"</option>
                                <option value="ecdsa-secp256k1">"ECDSA secp256k1 (Sign)"</option>
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
                                                            fetch_key_info.dispatch(k_clone.clone());
                                                            set_output_result.set(String::new());
                                                            set_input_text.set(String::new());
                                                            set_signature_input.set(String::new());
                                                            set_verify_result.set(None);
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
                                            {move || {
                                                let info = key_info.get();
                                                // X25519 supports encryption
                                                let can_encrypt = info.as_ref().map(|i| matches!(i.key_type, KeyType::Aes256Gcm | KeyType::ChaCha20Poly1305 | KeyType::XChaCha20Poly1305 | KeyType::X25519 | KeyType::Rsa(_))).unwrap_or(true);
                                                // RSA currently maps to X25519 material (placeholder) which does not support signing
                                                let can_sign = info.as_ref().map(|i| matches!(i.key_type, KeyType::Ed25519 | KeyType::EcdsaP256 | KeyType::EcdsaSecp256k1)).unwrap_or(true);

                                                view! {
                                                    <div class="flex space-x-2 bg-gray-100 p-1 rounded-lg">
                                                        {if can_encrypt {
                                                            view! {
                                                                <button
                                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "encrypt" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                    on:click=move |_| {
                                                                        set_active_tab.set("encrypt".to_string());
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
                                                                        set_output_result.set(String::new());
                                                                        set_input_text.set(String::new());
                                                                        set_error_msg.set(None);
                                                                    }
                                                                >
                                                                    "Decrypt"
                                                                </button>
                                                            }.into_any()
                                                        } else {
                                                            view! {}.into_any()
                                                        }}

                                                        {if can_sign {
                                                            view! {
                                                                <button
                                                                    class=format!("px-4 py-1.5 rounded-md text-sm font-medium transition-colors {}", if active_tab.get() == "sign" { "bg-white shadow text-gray-900" } else { "text-gray-500 hover:text-gray-700" })
                                                                    on:click=move |_| {
                                                                        set_active_tab.set("sign".to_string());
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
                                                        } else {
                                                            view! {}.into_any()
                                                        }}
                                                    </div>
                                                }
                                            }}
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
                                                        "decrypt" => "Enter ciphertext (vault:v1:...)",
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

                                            // Algorithm Selector for Sign/Verify
                                            {move || if active_tab.get() == "sign" || active_tab.get() == "verify" {
                                                view! {
                                                    <div>
                                                        <label class="block text-sm font-medium text-gray-700 mb-1">"Algorithm"</label>
                                                        <select
                                                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                                            on:change=move |ev| set_selected_algo.set(event_target_value(&ev))
                                                            prop:value=selected_algo
                                                        >
                                                            <option value="ed25519">"Ed25519"</option>
                                                            <option value="ecdsa-p256">"ECDSA P-256"</option>
                                                            <option value="ecdsa-secp256k1">"ECDSA secp256k1"</option>
                                                        </select>
                                                    </div>
                                                }.into_any()
                                            } else {
                                                view! {}.into_any()
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
