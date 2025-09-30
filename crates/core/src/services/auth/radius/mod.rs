use std::net::UdpSocket;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};
use chrono::{Utc, Duration as ChronoDuration};
use rand::Rng;
use md5;
use crate::models::auth::{AuthRequest, AuthResponse, UserInfo};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    pub server: String,
    pub port: u16,
    pub secret: String,
    pub timeout: u64,
    pub retries: u32,
    pub nas_identifier: Option<String>,
    pub nas_ip_address: Option<String>,
    pub nas_port: Option<u32>,
    pub nas_port_type: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attribute_type: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusUser {
    pub username: String,
    pub groups: Vec<String>,
    pub attributes: HashMap<String, String>,
}

pub struct RadiusAuth {
    config: RadiusConfig,
    socket: UdpSocket,
}

impl RadiusAuth {
    pub fn new(config: RadiusConfig) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_read_timeout(Some(Duration::from_secs(config.timeout)))?;
        socket.set_write_timeout(Some(Duration::from_secs(config.timeout)))?;

        Ok(Self { config, socket })
    }

    pub async fn authenticate(
        &self,
        auth_request: &AuthRequest,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        match auth_request {
            AuthRequest::Credentials { username, password } => {
                self.authenticate_credentials(username, password).await
            }
            _ => Err("RADIUS authentication only supports username/password credentials".into()),
        }
    }

    async fn authenticate_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::thread_rng();
        let identifier = rng.gen_range(0..=255) as u8;
        let mut authenticator = [0u8; 16];
        rng.fill(&mut authenticator);

        // Create Access-Request packet
        let mut attributes = Vec::new();

        // User-Name attribute (1)
        attributes.push(self.create_attribute(1, username.as_bytes().to_vec()));

        // User-Password attribute (2)
        let encrypted_password = self.encrypt_password(password, &authenticator)?;
        attributes.push(self.create_attribute(2, encrypted_password));

        // NAS-Identifier attribute (32)
        if let Some(nas_id) = &self.config.nas_identifier {
            attributes.push(self.create_attribute(32, nas_id.as_bytes().to_vec()));
        }

        // NAS-IP-Address attribute (4)
        if let Some(nas_ip) = &self.config.nas_ip_address {
            if let Ok(ip_bytes) = nas_ip.parse::<std::net::Ipv4Addr>() {
                attributes.push(self.create_attribute(4, ip_bytes.octets().to_vec()));
            }
        }

        // NAS-Port attribute (5)
        if let Some(nas_port) = self.config.nas_port {
            let port_bytes = (nas_port as u32).to_be_bytes();
            attributes.push(self.create_attribute(5, port_bytes.to_vec()));
        }

        // NAS-Port-Type attribute (61)
        if let Some(port_type) = self.config.nas_port_type {
            let type_bytes = (port_type as u32).to_be_bytes();
            attributes.push(self.create_attribute(61, type_bytes.to_vec()));
        }

        let request_packet = RadiusPacket {
            code: 1, // Access-Request
            identifier,
            length: 0, // Will be calculated
            authenticator,
            attributes,
        };

        // Send request and receive response
        let response_packet = self.send_request(request_packet).await?;

        match response_packet.code {
            2 => {
                // Access-Accept
                let user_info = self.extract_user_info(&response_packet);
                let token = self.generate_token(username);

                Ok(AuthResponse {
                    authenticated: true,
                    user_info,
                    policies: vec!["default".to_string()],
                    lease_duration: 3600, // 1 hour default
                    renewable: true,
                    token,
                    accessor: format!("radius-{}", username),
                    metadata: HashMap::new(),
                })
            }
            3 => {
                // Access-Reject
                Ok(AuthResponse {
                    authenticated: false,
                    user_info: UserInfo {
                        username: username.to_string(),
                        email: None,
                        groups: vec![],
                        metadata: HashMap::new(),
                    },
                    policies: vec![],
                    lease_duration: 0,
                    renewable: false,
                    token: "".to_string(),
                    accessor: "".to_string(),
                    metadata: HashMap::new(),
                })
            }
            _ => {
                Err(format!("Unexpected RADIUS response code: {}", response_packet.code).into())
            }
        }
    }

    async fn send_request(
        &self,
        mut packet: RadiusPacket,
    ) -> Result<RadiusPacket, Box<dyn std::error::Error + Send + Sync>> {
        // Calculate packet length
        let mut length = 20; // Header size
        for attr in &packet.attributes {
            length += attr.length as u16;
        }
        packet.length = length;

        // Serialize packet
        let packet_data = self.serialize_packet(&packet)?;

        let server_addr = format!("{}:{}", self.config.server, self.config.port);

        for attempt in 0..self.config.retries {
            // Send packet
            self.socket.send_to(&packet_data, &server_addr)?;

            // Receive response
            let mut buffer = [0u8; 4096];
            match self.socket.recv_from(&mut buffer) {
                Ok((size, _)) => {
                    let response_packet = self.deserialize_packet(&buffer[..size])?;
                    if response_packet.identifier == packet.identifier {
                        return Ok(response_packet);
                    }
                }
                Err(_) => {
                    if attempt == self.config.retries - 1 {
                        return Err("RADIUS request timeout".into());
                    }
                    // Wait before retry
                    tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
                }
            }
        }

        Err("RADIUS request failed after all retries".into())
    }

    fn create_attribute(&self, attribute_type: u8, value: Vec<u8>) -> RadiusAttribute {
        let length = (value.len() + 2) as u8; // Type + Length + Value
        RadiusAttribute {
            attribute_type,
            length,
            value,
        }
    }

    fn encrypt_password(
        &self,
        password: &str,
        request_authenticator: &[u8; 16],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let password_bytes = password.as_bytes();
        let mut encrypted = Vec::new();
        let mut previous_cipher = *request_authenticator;

        // Process password in 16-byte chunks
        for chunk in password_bytes.chunks(16) {
            let mut padded_chunk = [0u8; 16];
            padded_chunk[..chunk.len()].copy_from_slice(chunk);

            // XOR with previous cipher
            for i in 0..16 {
                padded_chunk[i] ^= previous_cipher[i];
            }

            // MD5 hash of secret + previous cipher
            let mut hash_input = self.config.secret.as_bytes().to_vec();
            hash_input.extend_from_slice(&previous_cipher);
            let hash = md5::compute(&hash_input);

            // XOR with hash
            for i in 0..16 {
                padded_chunk[i] ^= hash[i];
            }

            encrypted.extend_from_slice(&padded_chunk);
            previous_cipher = padded_chunk;
        }

        Ok(encrypted)
    }

    fn serialize_packet(&self, packet: &RadiusPacket) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut data = Vec::new();

        // Header
        data.push(packet.code);
        data.push(packet.identifier);
        data.extend_from_slice(&packet.length.to_be_bytes());
        data.extend_from_slice(&packet.authenticator);

        // Attributes
        for attr in &packet.attributes {
            data.push(attr.attribute_type);
            data.push(attr.length);
            data.extend_from_slice(&attr.value);
        }

        Ok(data)
    }

    fn deserialize_packet(&self, data: &[u8]) -> Result<RadiusPacket, Box<dyn std::error::Error + Send + Sync>> {
        if data.len() < 20 {
            return Err("Packet too short".into());
        }

        let code = data[0];
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);
        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);

        let mut attributes = Vec::new();
        let mut offset = 20;

        while offset < data.len() && offset < length as usize {
            if offset + 2 > data.len() {
                break;
            }

            let attribute_type = data[offset];
            let attr_length = data[offset + 1] as usize;

            if attr_length < 2 || offset + attr_length > data.len() {
                break;
            }

            let value = data[offset + 2..offset + attr_length].to_vec();

            attributes.push(RadiusAttribute {
                attribute_type,
                length: attr_length as u8,
                value,
            });

            offset += attr_length;
        }

        Ok(RadiusPacket {
            code,
            identifier,
            length,
            authenticator,
            attributes,
        })
    }

    fn extract_user_info(&self, packet: &RadiusPacket) -> UserInfo {
        let mut username = "unknown".to_string();
        let mut groups = Vec::new();
        let mut attributes = HashMap::new();

        for attr in &packet.attributes {
            match attr.attribute_type {
                1 => {
                    // User-Name
                    if let Ok(name) = String::from_utf8(attr.value.clone()) {
                        username = name;
                    }
                }
                11 => {
                    // Filter-Id (often used for groups)
                    if let Ok(group) = String::from_utf8(attr.value.clone()) {
                        groups.push(group);
                    }
                }
                25 => {
                    // Class (can contain group information)
                    if let Ok(class) = String::from_utf8(attr.value.clone()) {
                        attributes.insert("class".to_string(), class);
                    }
                }
                _ => {
                    // Store other attributes
                    if let Ok(value) = String::from_utf8(attr.value.clone()) {
                        attributes.insert(format!("attr_{}", attr.attribute_type), value);
                    }
                }
            }
        }

        UserInfo {
            username,
            email: None,
            groups,
            metadata: attributes,
        }
    }

    pub async fn validate_token(
        &self,
        token: &str,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For RADIUS, we don't maintain persistent sessions
        // Token validation would need to be implemented separately
        Ok(!token.is_empty() && token.starts_with("radius-token-"))
    }

    fn generate_token(&self, username: &str) -> String {
        format!("radius-token-{}-{}", username, Utc::now().timestamp())
    }

    pub async fn accounting_start(
        &self,
        username: &str,
        session_id: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::thread_rng();
        let identifier = rng.gen_range(0..=255) as u8;
        let mut authenticator = [0u8; 16];
        rng.fill(&mut authenticator);

        let mut attributes = Vec::new();

        // User-Name (1)
        attributes.push(self.create_attribute(1, username.as_bytes().to_vec()));

        // Acct-Status-Type (40) - Start
        attributes.push(self.create_attribute(40, vec![1]));

        // Acct-Session-Id (44)
        attributes.push(self.create_attribute(44, session_id.as_bytes().to_vec()));

        // Acct-Authentic (45) - RADIUS
        attributes.push(self.create_attribute(45, vec![1]));

        let packet = RadiusPacket {
            code: 4, // Accounting-Request
            identifier,
            length: 0,
            authenticator,
            attributes,
        };

        self.send_request(packet).await?;
        Ok(())
    }

    pub async fn accounting_stop(
        &self,
        username: &str,
        session_id: &str,
        session_time: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut rng = rand::thread_rng();
        let identifier = rng.gen_range(0..=255) as u8;
        let mut authenticator = [0u8; 16];
        rng.fill(&mut authenticator);

        let mut attributes = Vec::new();

        // User-Name (1)
        attributes.push(self.create_attribute(1, username.as_bytes().to_vec()));

        // Acct-Status-Type (40) - Stop
        attributes.push(self.create_attribute(40, vec![2]));

        // Acct-Session-Id (44)
        attributes.push(self.create_attribute(44, session_id.as_bytes().to_vec()));

        // Acct-Session-Time (46)
        let time_bytes = session_time.to_be_bytes();
        attributes.push(self.create_attribute(46, time_bytes.to_vec()));

        // Acct-Terminate-Cause (49) - User Request
        attributes.push(self.create_attribute(49, vec![1]));

        let packet = RadiusPacket {
            code: 4, // Accounting-Request
            identifier,
            length: 0,
            authenticator,
            attributes,
        };

        self.send_request(packet).await?;
        Ok(())
    }
}
