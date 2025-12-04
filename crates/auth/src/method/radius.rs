//! RADIUS authentication method
//!
//! Provides RADIUS-based authentication using the radius-rust library.

use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use chrono::Utc;
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::radius_packet::{RadiusAttribute, RadiusPacket, TypeCode};
use secreton_errors::SecretonError;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::Duration;
use uuid::Uuid;

/// RADIUS authentication method
pub struct RadiusAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    radius_config: Option<RadiusConfig>,
    #[allow(dead_code)]
    dictionary: Dictionary,
}

impl Default for RadiusAuthMethod {
    fn default() -> Self {
        Self::new()
    }
}

impl RadiusAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            radius_config: None,
            dictionary: Dictionary::default(),
        }
    }

    /// Set RADIUS configuration
    pub fn set_radius_config(&mut self, config: RadiusConfig) {
        self.radius_config = Some(config);
    }

    /// Authenticate with RADIUS server
    async fn authenticate_with_radius(
        &self,
        username: &str,
        password: &str,
    ) -> AuthMethodResult<RadiusResponse> {
        let config = self
            .radius_config
            .as_ref()
            .ok_or(SecretonError::Configuration {
                message: "RADIUS config not set".to_string(),
            })?;

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| SecretonError::RadiusError(format!("Failed to bind socket: {}", e)))?;

        socket
            .set_read_timeout(Some(Duration::from_secs(config.read_timeout.unwrap_or(30))))
            .map_err(|e| SecretonError::RadiusError(format!("Failed to set timeout: {}", e)))?;

        socket
            .connect((config.host.as_str(), config.port))
            .map_err(|e| SecretonError::RadiusError(format!("Failed to connect: {}", e)))?;

        // Initialize Access-Request packet using radius-rust API
        let mut packet = RadiusPacket::initialise_packet(TypeCode::AccessRequest);

        // Build attributes list
        let mut attributes = Vec::new();

        // Add User-Name attribute (type 1)
        if let Some(attr) =
            RadiusAttribute::create_by_id(&self.dictionary, 1, username.as_bytes().to_vec())
        {
            attributes.push(attr);
        }

        // Encode User-Password attribute (type 2) with MD5 encryption per RFC 2865
        let encrypted_password =
            Self::encode_radius_password(password, packet.authenticator(), &config.secret);
        if let Some(attr) =
            RadiusAttribute::create_by_id(&self.dictionary, 2, encrypted_password)
        {
            attributes.push(attr);
        }

        // Add NAS-IP-Address if configured (type 4)
        if let Some(nas_ip) = &config.nas_ip_address {
            if let Ok(ip) = nas_ip.parse::<std::net::Ipv4Addr>() {
                if let Some(attr) =
                    RadiusAttribute::create_by_id(&self.dictionary, 4, ip.octets().to_vec())
                {
                    attributes.push(attr);
                }
            }
        }

        // Add NAS-Identifier if configured (type 32)
        if let Some(nas_id) = &config.nas_identifier {
            if let Some(attr) =
                RadiusAttribute::create_by_id(&self.dictionary, 32, nas_id.as_bytes().to_vec())
            {
                attributes.push(attr);
            }
        }

        // Set attributes on the packet
        packet.set_attributes(attributes);

        // Encode and send the packet
        let encoded_packet = packet.to_bytes();

        socket
            .send(&encoded_packet)
            .map_err(|e| SecretonError::RadiusError(format!("Failed to send packet: {}", e)))?;

        // Receive response
        let mut buffer = [0u8; 4096];
        let size = socket.recv(&mut buffer).map_err(|e| {
            SecretonError::RadiusError(format!("Failed to receive response: {}", e))
        })?;

        // Decode response packet
        let response_packet =
            RadiusPacket::initialise_packet_from_bytes(&self.dictionary, &buffer[..size]).map_err(
                |e| SecretonError::RadiusError(format!("Failed to decode response: {:?}", e)),
            )?;

        // Verify response authenticator (RFC 2865)
        // ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
        let is_valid = Self::verify_response_authenticator(
            &buffer[..size],
            packet.authenticator(),
            &config.secret,
        );

        if !is_valid {
            return Err(SecretonError::RadiusError(
                "Invalid response authenticator".to_string(),
            ));
        }

        // Parse response based on type code
        match response_packet.code() {
            TypeCode::AccessAccept => {
                // Extract attributes from response
                let mut groups = Vec::new();
                let mut vlan_id = None;

                // Get Filter-Id attributes (type 11) - often used for group assignment
                if let Some(filter_attr) = response_packet.attribute_by_id(11) {
                    if let Ok(group) = std::str::from_utf8(filter_attr.value()) {
                        groups.push(group.to_string());
                    }
                }

                // Get Tunnel-Private-Group-Id (type 81) - used for VLAN assignment
                if let Some(vlan_attr) = response_packet.attribute_by_id(81) {
                    if let Ok(vlan) = std::str::from_utf8(vlan_attr.value()) {
                        vlan_id = Some(vlan.to_string());
                    }
                }

                Ok(RadiusResponse {
                    accepted: true,
                    groups,
                    vlan_id,
                })
            }
            TypeCode::AccessReject => Ok(RadiusResponse {
                accepted: false,
                groups: vec![],
                vlan_id: None,
            }),
            TypeCode::AccessChallenge => {
                // Handle challenge-response if needed in future
                Err(SecretonError::RadiusError(
                    "Access challenge not supported".to_string(),
                ))
            }
            other => Err(SecretonError::RadiusError(format!(
                "Unexpected response type: {:?}",
                other
            ))),
        }
    }

    /// Encode password per RFC 2865 User-Password attribute encryption
    fn encode_radius_password(password: &str, authenticator: &[u8], secret: &str) -> Vec<u8> {
        let password_bytes = password.as_bytes();
        let padded_len = ((password_bytes.len() + 15) / 16) * 16;
        let mut padded_password = vec![0u8; padded_len.max(16)];
        padded_password[..password_bytes.len()].copy_from_slice(password_bytes);

        let mut result = Vec::with_capacity(padded_password.len());
        let mut prev_cipher = authenticator.to_vec();

        for chunk in padded_password.chunks(16) {
            // MD5(secret + prev_cipher)
            let mut hash_input = Vec::with_capacity(secret.len() + prev_cipher.len());
            hash_input.extend_from_slice(secret.as_bytes());
            hash_input.extend_from_slice(&prev_cipher);
            let hash = md5::compute(&hash_input);

            let cipher: Vec<u8> = chunk
                .iter()
                .zip(hash.iter())
                .map(|(p, h)| p ^ h)
                .collect();

            result.extend_from_slice(&cipher);
            prev_cipher = cipher;
        }

        result
    }

    /// Verify RADIUS response authenticator per RFC 2865
    /// ResponseAuth = MD5(Code+ID+Length+RequestAuth+Attributes+Secret)
    fn verify_response_authenticator(
        response_bytes: &[u8],
        request_authenticator: &[u8],
        secret: &str,
    ) -> bool {
        if response_bytes.len() < 20 {
            return false;
        }

        // Extract response authenticator (bytes 4-19)
        let response_authenticator = &response_bytes[4..20];

        // Build the data to hash: Code + ID + Length + RequestAuth + Attributes + Secret
        let mut hash_input = Vec::with_capacity(response_bytes.len() + secret.len());
        hash_input.extend_from_slice(&response_bytes[..4]); // Code, ID, Length
        hash_input.extend_from_slice(request_authenticator); // Original request authenticator
        if response_bytes.len() > 20 {
            hash_input.extend_from_slice(&response_bytes[20..]); // Attributes
        }
        hash_input.extend_from_slice(secret.as_bytes());

        let expected = md5::compute(&hash_input);

        response_authenticator == expected.as_slice()
    }
}

#[async_trait]
impl AuthMethodImpl for RadiusAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Radius
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse RADIUS configuration from config
        if let (Some(host), Some(shared_secret)) = (
            config.config.get("host").and_then(|v| v.as_str()),
            config.config.get("shared_secret").and_then(|v| v.as_str()),
        ) {
            let radius_config = RadiusConfig {
                host: host.to_string(),
                port: config
                    .config
                    .get("port")
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u16)
                    .unwrap_or(1812),
                secret: shared_secret.to_string(),
                nas_identifier: config
                    .config
                    .get("nas_identifier")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                nas_ip_address: config
                    .config
                    .get("nas_ip_address")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                dial_timeout: Some(
                    config
                        .config
                        .get("timeout_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(30),
                ),
                read_timeout: Some(
                    config
                        .config
                        .get("timeout_seconds")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(30),
                ),
            };
            self.set_radius_config(radius_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(SecretonError::AuthMethodDisabled);
        }

        match credentials {
            AuthCredentials::UserPass { username, password } => {
                let radius_response = self.authenticate_with_radius(username, password).await?;

                if !radius_response.accepted {
                    return Err(SecretonError::Authentication {
                        message: "RADIUS authentication rejected".to_string(),
                    });
                }

                let user_info = UserInfo {
                    id: Some(Uuid::new_v4().to_string()),
                    username: username.to_string(),
                    email: None,
                    display_name: None,
                    roles: radius_response.groups,
                    metadata: {
                        let mut meta = HashMap::new();
                        if let Some(vlan) = radius_response.vlan_id {
                            meta.insert("vlan_id".to_string(), vlan);
                        }
                        meta
                    },
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    success: true,
                    user_info: Some(user_info),
                    policies: vec![],
                    token: None,
                    metadata: HashMap::new(),
                    mfa_required: false,
                })
            }
            _ => Err(SecretonError::Authentication {
                message: "RADIUS requires username/password credentials".to_string(),
            }),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(SecretonError::AuthMethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(SecretonError::AuthMethodNotSupported)
    }

    fn is_enabled(&self) -> bool {
        self.enabled
    }

    fn enable(&mut self) {
        self.enabled = true;
    }

    fn disable(&mut self) {
        self.enabled = false;
    }
}

/// RADIUS configuration
#[derive(Clone, Debug)]
pub struct RadiusConfig {
    /// RADIUS server hostname or IP
    pub host: String,
    /// RADIUS server port (default 1812 for authentication)
    pub port: u16,
    /// Shared secret between client and server
    pub secret: String,
    /// NAS IP address to include in requests
    pub nas_ip_address: Option<String>,
    /// NAS identifier to include in requests
    pub nas_identifier: Option<String>,
    /// Connection timeout in seconds
    pub dial_timeout: Option<u64>,
    /// Read timeout in seconds
    pub read_timeout: Option<u64>,
}

/// RADIUS authentication response
#[derive(Clone, Debug)]
pub struct RadiusResponse {
    /// Whether authentication was accepted
    pub accepted: bool,
    /// Groups assigned to the user (from Filter-Id attributes)
    pub groups: Vec<String>,
    /// VLAN ID if assigned (from Tunnel-Private-Group-Id)
    pub vlan_id: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_encoding() {
        // Test vector from RFC 2865
        let authenticator = [0u8; 16];
        let secret = "test_secret";
        let password = "test_password";

        let encoded = RadiusAuthMethod::encode_radius_password(password, &authenticator, secret);

        // Should be padded to 16 bytes minimum
        assert!(encoded.len() >= 16);
        assert_eq!(encoded.len() % 16, 0);
    }

    #[test]
    fn test_radius_config() {
        let config = RadiusConfig {
            host: "127.0.0.1".to_string(),
            port: 1812,
            secret: "testing123".to_string(),
            nas_ip_address: Some("10.0.0.1".to_string()),
            nas_identifier: Some("secreton-nas".to_string()),
            dial_timeout: Some(30),
            read_timeout: Some(30),
        };

        assert_eq!(config.port, 1812);
        assert_eq!(config.host, "127.0.0.1");
    }

    #[tokio::test]
    async fn test_radius_method_init() {
        let mut method = RadiusAuthMethod::new();
        assert!(!method.is_enabled());

        let auth_config = AuthMethod {
            method_type: AuthMethodType::Radius,
            path: "radius".to_string(),
            enabled: true,
            config: {
                let mut c = serde_json::Map::new();
                c.insert("host".to_string(), serde_json::json!("127.0.0.1"));
                c.insert("shared_secret".to_string(), serde_json::json!("test"));
                serde_json::Value::Object(c)
            },
            description: None,
            default_lease_ttl: None,
            max_lease_ttl: None,
        };

        method.init(&auth_config).await.unwrap();
        assert!(method.is_enabled());
        assert!(method.radius_config.is_some());
    }
}
