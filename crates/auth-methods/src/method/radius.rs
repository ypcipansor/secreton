//! RADIUS authentication method

use async_trait::async_trait;
use chrono::Utc;
use std::collections::HashMap;
use std::net::UdpSocket;
use std::time::Duration;
use uuid::Uuid;
use radius_rust::protocol::dictionary::Dictionary;
use radius_rust::protocol::error::RadiusError;
use radius_rust::protocol::radius_packet::{RadiusPacket, RadiusAttribute, RadiusMsgType, TypeCode};
use crate::model::*;
use crate::error::*;
use crate::service::*;

/// RADIUS authentication method
pub struct RadiusAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    radius_config: Option<RadiusConfig>,
    dictionary: Dictionary,
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
    async fn authenticate_with_radius(&self, username: &str, password: &str) -> AuthMethodResult<RadiusResponse> {
        let config = self.radius_config.as_ref()
            .ok_or(AuthMethodError::ConfigurationError("RADIUS config not set".to_string()))?;

        // Create UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to bind socket: {}", e)))?;

        socket.set_read_timeout(Some(Duration::from_secs(config.read_timeout.unwrap_or(30))))
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to set timeout: {}", e)))?;

        socket.connect((config.host.as_str(), config.port))
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to connect: {}", e)))?;

        // Generate random authenticator
        let authenticator: [u8; 16] = rand::random();

        // Create Access-Request packet
        let mut packet = Packet::new(PacketType::AccessRequest, 1, authenticator);

        // Add attributes
        let user_name_attr_id = self.dictionary.attributes().iter()
            .find(|attr| attr.name() == "User-Name")
            .map(|attr| attr.code())
            .unwrap_or(1);
        
        packet.add_attribute(Attribute::new(
            user_name_attr_id,
            Value::String(username.as_bytes().to_vec()),
        ));

        let user_password_attr_id = self.dictionary.attributes().iter()
            .find(|attr| attr.name() == "User-Password")
            .map(|attr| attr.code())
            .unwrap_or(2);
        
        packet.add_attribute(Attribute::new(
            user_password_attr_id,
            Value::String(password.as_bytes().to_vec()),
        ));

        // Add NAS-IP-Address if configured
        if let Some(nas_ip) = &config.nas_ip_address {
            if let Ok(ip_bytes) = nas_ip.parse::<std::net::IpAddr>() {
                let ip_bytes = match ip_bytes {
                    std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                    std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                };
                let nas_ip_attr_id = self.dictionary.attributes().iter()
                    .find(|attr| attr.name() == "NAS-IP-Address")
                    .map(|attr| attr.code())
                    .unwrap_or(4);
                
                packet.add_attribute(Attribute::new(
                    nas_ip_attr_id,
                    Value::IpAddr(ip_bytes),
                ));
            }
        }

        // Add NAS-Identifier if configured
        if let Some(nas_id) = &config.nas_identifier {
            let nas_id_attr_id = self.dictionary.attributes().iter()
                .find(|attr| attr.name() == "NAS-Identifier")
                .map(|attr| attr.code())
                .unwrap_or(32);
            
            packet.add_attribute(Attribute::new(
                nas_id_attr_id,
                Value::String(nas_id.as_bytes().to_vec()),
            ));
        }

        // Calculate response authenticator with shared secret
        let request_data = packet.encode();
        let response_authenticator = md5::compute(
            &[&request_data[..], config.secret.as_bytes()].concat()
        ).0;

        packet.authenticator = response_authenticator;

        // Send packet
        let encoded_packet = packet.encode();
        socket.send(&encoded_packet)
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to send packet: {}", e)))?;

        // Receive response
        let mut buffer = [0u8; 4096];
        let size = socket.recv(&mut buffer)
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to receive response: {}", e)))?;

        let response_packet = Packet::decode(&buffer[..size])
            .map_err(|e| AuthMethodError::RadiusError(format!("Failed to decode response: {:?}", e)))?;

        // Verify response authenticator
        let expected_authenticator = md5::compute(
            &[&[response_packet.code as u8], &response_packet.identifier.to_be_bytes(), &response_packet.length.to_be_bytes()[..], &request_data[4..], config.secret.as_bytes()].concat()
        ).0;

        if response_packet.authenticator != expected_authenticator {
            return Err(AuthMethodError::RadiusError("Invalid response authenticator".to_string()));
        }

        // Parse response
        match response_packet.code {
            PacketType::AccessAccept => {
                // Extract attributes
                let mut groups = Vec::new();
                let mut vlan_id = None;

                for attr in &response_packet.attributes {
                    match attr.attribute_type {
                        1 => { // User-Name
                            // Already have username
                        }
                        11 => { // Filter-Id (often used for groups)
                            if let Value::String(data) = &attr.value {
                                if let Ok(group) = std::str::from_utf8(data) {
                                    groups.push(group.to_string());
                                }
                            }
                        }
                        64 => { // Tunnel-Private-Group-Id (VLAN)
                            if let Value::String(data) = &attr.value {
                                if let Ok(vlan) = std::str::from_utf8(data) {
                                    vlan_id = Some(vlan.to_string());
                                }
                            }
                        }
                        _ => {}
                    }
                }

                Ok(RadiusResponse {
                    accepted: true,
                    groups,
                    vlan_id,
                })
            }
            PacketType::AccessReject => {
                Ok(RadiusResponse {
                    accepted: false,
                    groups: vec![],
                    vlan_id: None,
                })
            }
            _ => Err(AuthMethodError::RadiusError(format!("Unexpected packet type: {:?}", response_packet.code))),
        }
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
            config.config.get("host"),
            config.config.get("shared_secret"),
        ) {
            let radius_config = RadiusConfig {
                host: host.to_string(),
                port: config.config.get("port")
                    .and_then(|p| p.as_u64())
                    .map(|p| p as u16)
                    .unwrap_or(1812),
                secret: shared_secret.to_string(),
                nas_identifier: config.config.get("nas_identifier").and_then(|v| v.as_str()).map(|s| s.to_string()),
                dial_timeout: Some(config.config.get("timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(30)),
                read_timeout: Some(config.config.get("timeout_seconds")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(30)),
            };
            self.set_radius_config(radius_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        if !self.is_enabled() {
            return Err(AuthMethodError::MethodDisabled);
        }

        match credentials {
            AuthCredentials::UserPass { username, password } => {
                let radius_response = self.authenticate_with_radius(username, password).await?;

                if !radius_response.accepted {
                    return Err(AuthMethodError::InvalidCredentials("Invalid RADIUS credentials".to_string()));
                }

                let user_info = UserInfo {
                    username: username.to_string(),
                    id: Uuid::new_v4(), // Generate UUID since RADIUS doesn't provide separate user ID
                    groups: radius_response.groups,
                    metadata: {
                        let mut meta = HashMap::new();
                        if let Some(vlan) = radius_response.vlan_id {
                            meta.insert("vlan_id".to_string(), vlan);
                        }
                        meta
                    },
                    email: None,
                    display_name: None,
                    created_at: Utc::now(),
                    last_login: Some(Utc::now()),
                };

                Ok(AuthResult {
                    authenticated: true,
                    user_info: Some(user_info),
                    policies: vec![], // Policies would be determined by groups
                    lease_duration: None,
                    renewable: Some(true),
                    token: None,
                    accessor: None,
                    metadata: HashMap::new(),
                    mfa_required: false,
                    mfa_methods: Vec::new(),
                })
            }
            _ => Err(AuthMethodError::InvalidCredentials("Invalid RADIUS credentials".to_string())),
        }
    }

    async fn validate_token(&self, _token: &str) -> AuthMethodResult<UserInfo> {
        Err(AuthMethodError::MethodNotSupported)
    }

    async fn revoke_token(&self, _token: &str) -> AuthMethodResult<()> {
        Err(AuthMethodError::MethodNotSupported)
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
    pub host: String,
    pub port: u16,
    pub shared_secret: String,
    pub timeout_seconds: u64,
    pub nas_ip_address: Option<String>,
    pub nas_identifier: Option<String>,
}

/// RADIUS authentication response
#[derive(Clone, Debug)]
pub struct RadiusResponse {
    pub accepted: bool,
    pub groups: Vec<String>,
    pub vlan_id: Option<String>,
}