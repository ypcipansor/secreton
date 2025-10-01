use super::{AuthMethod, AuthResult, Credentials, TokenInfo};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, error, info};

/// Errors that can occur during RADIUS authentication
#[derive(Error, Debug)]
pub enum RadiusError {
    #[error("RADIUS server unreachable: {0}")]
    ServerUnreachable(String),

    #[error("RADIUS authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("RADIUS access rejected")]
    AccessRejected,

    #[error("RADIUS packet malformed: {0}")]
    PacketMalformed(String),

    #[error("RADIUS timeout")]
    Timeout,

    #[error("Invalid RADIUS configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Network error: {0}")]
    NetworkError(String),
}

/// RADIUS packet types
#[derive(Debug, Clone)]
pub enum RadiusPacketType {
    AccessRequest = 1,
    AccessAccept = 2,
    AccessReject = 3,
    AccessChallenge = 11,
}

/// RADIUS attribute types
#[derive(Debug, Clone)]
pub enum RadiusAttributeType {
    UserName = 1,
    UserPassword = 2,
    NasIpAddress = 4,
    NasPort = 5,
    ServiceType = 6,
    FramedProtocol = 7,
    FramedIpAddress = 8,
    FramedIpNetmask = 9,
    FramedRouting = 10,
    FilterId = 11,
    FramedMtu = 12,
    FramedCompression = 13,
    LoginIpHost = 14,
    LoginService = 15,
    LoginTcpPort = 16,
    ReplyMessage = 18,
    CallbackNumber = 19,
    CallbackId = 20,
    FramedRoute = 22,
    FramedIpxNetwork = 23,
    State = 24,
    Class = 25,
    VendorSpecific = 26,
    SessionTimeout = 27,
    IdleTimeout = 28,
    TerminationAction = 29,
    CalledStationId = 30,
    CallingStationId = 31,
    NasIdentifier = 32,
    ProxyState = 33,
    LoginLatService = 34,
    LoginLatNode = 35,
    LoginLatGroup = 36,
    FramedAppleTalkLink = 37,
    FramedAppleTalkNetwork = 38,
    FramedAppleTalkZone = 39,
    AcctStatusType = 40,
    AcctDelayTime = 41,
    AcctInputOctets = 42,
    AcctOutputOctets = 43,
    AcctSessionId = 44,
    AcctAuthentic = 45,
    AcctSessionTime = 46,
    AcctInputPackets = 47,
    AcctOutputPackets = 48,
    AcctTerminateCause = 49,
    AcctMultiSessionId = 50,
    AcctLinkCount = 51,
    AcctInputGigawords = 52,
    AcctOutputGigawords = 53,
    EventTimestamp = 55,
    EgressVlanId = 56,
    IngressFilters = 57,
    EgressVlanName = 58,
    UserPriorityTable = 59,
    ChapChallenge = 60,
    NasPortType = 61,
    PortLimit = 62,
    LoginLatPort = 63,
    TunnelType = 64,
    TunnelMediumType = 65,
    TunnelClientEndpoint = 66,
    TunnelServerEndpoint = 67,
    AcctTunnelConnection = 68,
    TunnelPassword = 69,
    ArApPassword = 70,
    ArApChallengeResponse = 71,
    AcctInterval = 85,
    AcctTunnelledRequest = 86,
    AcctTunnelledResponse = 87,
    NasPortId = 88,
    FramedPool = 89,
    TunnelClientAuthId = 90,
    TunnelServerAuthId = 91,
}

/// RADIUS packet structure
#[derive(Debug, Clone)]
pub struct RadiusPacket {
    pub code: u8,
    pub identifier: u8,
    pub length: u16,
    pub authenticator: [u8; 16],
    pub attributes: Vec<RadiusAttribute>,
}

/// RADIUS attribute structure
#[derive(Debug, Clone)]
pub struct RadiusAttribute {
    pub attribute_type: u8,
    pub length: u8,
    pub value: Vec<u8>,
}

/// RADIUS authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiusConfig {
    pub server: String,
    pub secret: String,
    pub port: u16,
    pub timeout: Duration,
    pub retries: u32,
    pub nas_identifier: String,
    pub nas_ip_address: Option<String>,
}

/// RADIUS authentication method implementation
pub struct RadiusAuth {
    config: RadiusConfig,
    socket: Option<UdpSocket>,
}

impl RadiusAuth {
    pub fn new(config: RadiusConfig) -> Self {
        Self {
            config,
            socket: None,
        }
    }

    /// Initialize RADIUS client socket
    async fn init_socket(&mut self) -> Result<(), RadiusError> {
        if self.socket.is_some() {
            return Ok(());
        }

        let local_addr = "0.0.0.0:0"; // Bind to any available port
        let socket = UdpSocket::bind(local_addr)
            .await
            .map_err(|e| RadiusError::NetworkError(e.to_string()))?;

        self.socket = Some(socket);
        Ok(())
    }

    /// Create RADIUS access request packet
    fn create_access_request(
        &self,
        username: &str,
        password: &str,
    ) -> Result<RadiusPacket, RadiusError> {
        use rand::Rng;

        let mut rng = rand::thread_rng();
        let identifier = rng.gen::<u8>();

        // Create authenticator (16 random bytes)
        let mut authenticator = [0u8; 16];
        rng.fill(&mut authenticator);

        // Build attributes
        let mut attributes = Vec::new();

        // User-Name attribute
        let username_attr = RadiusAttribute {
            attribute_type: RadiusAttributeType::UserName as u8,
            length: (username.len() + 2) as u8,
            value: username.as_bytes().to_vec(),
        };
        attributes.push(username_attr);

        // User-Password attribute (encrypted)
        let password_attr = self.encrypt_user_password(password.as_bytes(), &authenticator)?;
        attributes.push(password_attr);

        // NAS-IP-Address attribute
        if let Some(nas_ip) = &self.config.nas_ip_address {
            let nas_ip_bytes = nas_ip
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| {
                    RadiusError::InvalidConfiguration("Invalid NAS IP address".to_string())
                })?
                .octets();
            let nas_attr = RadiusAttribute {
                attribute_type: RadiusAttributeType::NasIpAddress as u8,
                length: 6,
                value: nas_ip_bytes.to_vec(),
            };
            attributes.push(nas_attr);
        }

        // NAS-Identifier attribute
        let nas_id_attr = RadiusAttribute {
            attribute_type: RadiusAttributeType::NasIdentifier as u8,
            length: (self.config.nas_identifier.len() + 2) as u8,
            value: self.config.nas_identifier.as_bytes().to_vec(),
        };
        attributes.push(nas_id_attr);

        // Calculate total length
        let attributes_length: usize = attributes.iter().map(|a| a.length as usize).sum();
        let total_length = 20 + attributes_length; // Header (20) + attributes

        Ok(RadiusPacket {
            code: RadiusPacketType::AccessRequest as u8,
            identifier,
            length: total_length as u16,
            authenticator,
            attributes,
        })
    }

    /// Encrypt user password using RADIUS password hiding algorithm
    fn encrypt_user_password(
        &self,
        password: &[u8],
        _authenticator: &[u8; 16],
    ) -> Result<RadiusAttribute, RadiusError> {
        // Simplified password encryption - in production this would use proper RADIUS algorithm
        let secret = self.config.secret.as_bytes();
        let mut encrypted = Vec::new();

        // For now, just XOR with secret (simplified implementation)
        for (i, &byte) in password.iter().enumerate() {
            let secret_byte = secret[i % secret.len()];
            encrypted.push(byte ^ secret_byte);
        }

        Ok(RadiusAttribute {
            attribute_type: RadiusAttributeType::UserPassword as u8,
            length: (encrypted.len() + 2) as u8,
            value: encrypted,
        })
    }

    /// Send RADIUS packet and receive response
    async fn send_radius_request(&self, packet: RadiusPacket) -> Result<RadiusPacket, RadiusError> {
        let socket = self
            .socket
            .as_ref()
            .ok_or(RadiusError::InvalidConfiguration(
                "Socket not initialized".to_string(),
            ))?;

        // Serialize packet
        let packet_data = self.serialize_packet(packet)?;

        // Send packet
        let server_addr: SocketAddr = format!("{}:{}", self.config.server, self.config.port)
            .parse()
            .map_err(|e: std::net::AddrParseError| {
                RadiusError::InvalidConfiguration(e.to_string())
            })?;

        socket
            .send_to(&packet_data, server_addr)
            .await
            .map_err(|e| RadiusError::NetworkError(e.to_string()))?;

        // Receive response with timeout
        let mut response_buf = [0u8; 4096];
        let timeout_duration = Duration::from_secs(5);

        match timeout(timeout_duration, socket.recv_from(&mut response_buf)).await {
            Ok(Ok((size, _))) => {
                let response_packet = self.deserialize_packet(&response_buf[..size])?;
                Ok(response_packet)
            }
            Ok(Err(e)) => Err(RadiusError::NetworkError(e.to_string())),
            Err(_) => Err(RadiusError::Timeout),
        }
    }

    /// Serialize RADIUS packet to bytes
    fn serialize_packet(&self, packet: RadiusPacket) -> Result<Vec<u8>, RadiusError> {
        let mut data = Vec::new();

        // Header
        data.push(packet.code);
        data.push(packet.identifier);
        data.extend_from_slice(&packet.length.to_be_bytes());
        data.extend_from_slice(&packet.authenticator);

        // Attributes
        for attr in packet.attributes {
            data.push(attr.attribute_type);
            data.push(attr.length);
            data.extend_from_slice(&attr.value);
        }

        // Update length in header
        let length = data.len() as u16;
        data[2..4].copy_from_slice(&length.to_be_bytes());

        Ok(data)
    }

    /// Deserialize RADIUS packet from bytes
    fn deserialize_packet(&self, data: &[u8]) -> Result<RadiusPacket, RadiusError> {
        if data.len() < 20 {
            return Err(RadiusError::PacketMalformed("Packet too short".to_string()));
        }

        let code = data[0];
        let identifier = data[1];
        let length = u16::from_be_bytes([data[2], data[3]]);

        if data.len() < length as usize {
            return Err(RadiusError::PacketMalformed(
                "Incomplete packet".to_string(),
            ));
        }

        let mut authenticator = [0u8; 16];
        authenticator.copy_from_slice(&data[4..20]);

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = 20;

        while offset < length as usize {
            if offset + 2 > data.len() {
                break;
            }

            let attr_type = data[offset];
            let attr_length = data[offset + 1] as usize;

            if attr_length < 2 || offset + attr_length > data.len() {
                return Err(RadiusError::PacketMalformed(
                    "Invalid attribute length".to_string(),
                ));
            }

            let attr_value = data[offset + 2..offset + attr_length].to_vec();

            attributes.push(RadiusAttribute {
                attribute_type: attr_type,
                length: attr_length as u8,
                value: attr_value,
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

    /// Extract user information from RADIUS response attributes
    fn extract_user_info(&self, response: &RadiusPacket) -> HashMap<String, String> {
        let user_info = HashMap::new();

        for attr in &response.attributes {
            {
                // For now, we don't extract specific attributes
                // In a real implementation, we would parse various RADIUS attributes
            }
        }

        user_info
    }
}

#[async_trait]
impl AuthMethod for RadiusAuth {
    async fn authenticate(&self, credentials: &Credentials) -> Result<AuthResult, anyhow::Error> {
        debug!("Starting RADIUS authentication");

        // Extract username and password from credentials
        let (username, password) = match credentials {
            Credentials::Password { username, password } => (username, password),
            Credentials::Ldap { username, password } => (username, password),
            _ => {
                error!("Invalid credential type for RADIUS authentication");
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some("Invalid RADIUS credentials".to_string()),
                });
            }
        };

        // Create RADIUS access request
        let access_request = match self.create_access_request(username, password) {
            Ok(request) => request,
            Err(e) => {
                error!("Failed to create RADIUS access request: {}", e);
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(format!("Failed to create RADIUS request: {}", e)),
                });
            }
        };

        // Send RADIUS request and get response
        let response = match self.send_radius_request(access_request).await {
            Ok(response) => response,
            Err(e) => {
                error!("RADIUS authentication failed: {}", e);
                return Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(format!("RADIUS server error: {}", e)),
                });
            }
        };

        // Check response code
        match response.code {
            code if code == RadiusPacketType::AccessAccept as u8 => {
                // Authentication successful
                let user_info = self.extract_user_info(&response);

                let token_info = TokenInfo {
                    id: format!("radius-token-{}", uuid::Uuid::new_v4()),
                    policies: vec!["default".to_string()],
                    metadata: user_info.clone(),
                    ttl: Some(3600), // 1 hour
                    renewable: true,
                    entity_id: Some(format!("radius-entity-{}", uuid::Uuid::new_v4())),
                };

                info!("RADIUS authentication successful for user: {}", username);

                Ok(AuthResult {
                    success: true,
                    token: Some(token_info),
                    user_info: Some(
                        user_info
                            .clone()
                            .into_iter()
                            .map(|(k, v)| (k, Value::String(v)))
                            .collect(),
                    ),
                    policies: vec!["default".to_string()],
                    metadata: user_info,
                    error: None,
                })
            }
            code if code == RadiusPacketType::AccessReject as u8 => {
                // Authentication rejected
                Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some("RADIUS authentication rejected".to_string()),
                })
            }
            _ => {
                // Other response codes (challenge, etc.)
                Ok(AuthResult {
                    success: false,
                    token: None,
                    user_info: None,
                    policies: vec![],
                    metadata: HashMap::new(),
                    error: Some(format!(
                        "RADIUS authentication failed with code: {}",
                        response.code
                    )),
                })
            }
        }
    }

    async fn validate_config(&self, _config: &Value) -> Result<(), anyhow::Error> {
        // TODO: Validate RADIUS configuration
        Ok(())
    }

    async fn list_users(&self) -> Result<Vec<String>, anyhow::Error> {
        // RADIUS doesn't provide user listing capabilities
        Ok(vec![])
    }

    async fn create_user(&self, _username: &str, _config: &Value) -> Result<(), anyhow::Error> {
        // RADIUS doesn't support creating users
        Err(anyhow::anyhow!(
            "User creation not supported for RADIUS authentication"
        ))
    }

    async fn delete_user(&self, _username: &str) -> Result<(), anyhow::Error> {
        // RADIUS doesn't support deleting users
        Err(anyhow::anyhow!(
            "User deletion not supported for RADIUS authentication"
        ))
    }

    fn name(&self) -> &'static str {
        "radius"
    }

    fn description(&self) -> &'static str {
        "RADIUS authentication for network access control"
    }

    fn supports_mfa(&self) -> bool {
        false // RADIUS can support MFA but it's not implemented here
    }
}

impl Default for RadiusConfig {
    fn default() -> Self {
        Self {
            server: "localhost".to_string(),
            secret: "radius-secret".to_string(),
            port: 1812,
            timeout: Duration::from_secs(5),
            retries: 3,
            nas_identifier: "secreton-vault".to_string(),
            nas_ip_address: Some("127.0.0.1".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::CoreError;
    
    #[test]
    fn test_radius_config_default() {
        let config = RadiusConfig::default();
        assert_eq!(config.server, "localhost");
        assert_eq!(config.port, 1812);
        assert_eq!(config.retries, 3);
        assert_eq!(config.nas_identifier, "secreton-vault");
    }
    
    #[test]
    fn test_radius_config_validation() {
        let mut config = RadiusConfig::default();
        
        // Valid configuration
        assert!(config.validate().is_ok());
        
        // Empty server should fail
        config.server = "".to_string();
        assert!(config.validate().is_err());
        
        // Empty secret should fail
        config.server = "localhost".to_string();
        config.secret = "".to_string();
        assert!(config.validate().is_err());
    }
    
    #[test]
    fn test_radius_auth_creation() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config);
        assert!(auth.is_ok());
    }
    
    #[test]
    fn test_radius_method_type() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config).unwrap();
        assert_eq!(auth.method_type(), "radius");
    }
    
    #[test]
    fn test_radius_description() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config).unwrap();
        assert_eq!(auth.description(), "RADIUS authentication for network access control");
    }
    
    #[test]
    fn test_radius_mfa_support() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config).unwrap();
        assert_eq!(auth.supports_mfa(), false);
    }
    
    #[test]
    fn test_radius_packet_type() {
        assert_eq!(RadiusPacketType::AccessRequest as u8, 1);
        assert_eq!(RadiusPacketType::AccessAccept as u8, 2);
        assert_eq!(RadiusPacketType::AccessReject as u8, 3);
        assert_eq!(RadiusPacketType::AccessChallenge as u8, 11);
    }
    
    #[test]
    fn test_radius_attribute_type() {
        assert_eq!(RadiusAttributeType::UserName as u8, 1);
        assert_eq!(RadiusAttributeType::UserPassword as u8, 2);
        assert_eq!(RadiusAttributeType::NasIpAddress as u8, 4);
        assert_eq!(RadiusAttributeType::NasIdentifier as u8, 32);
    }
    
    #[test]
    fn test_radius_config_with_custom_port() {
        let mut config = RadiusConfig::default();
        config.port = 1645; // Alternative RADIUS port
        assert!(config.validate().is_ok());
    }
    
    #[test]
    fn test_radius_config_with_timeout() {
        let mut config = RadiusConfig::default();
        config.timeout = Duration::from_secs(10);
        assert!(config.validate().is_ok());
    }
    
    #[tokio::test]
    async fn test_radius_auth_invalid_credentials() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config).unwrap();
        
        let mut credentials = HashMap::new();
        // Missing username should fail
        credentials.insert("password".to_string(), "test123".to_string());
        
        let result = auth.authenticate(credentials).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_radius_auth_missing_password() {
        let config = RadiusConfig::default();
        let auth = RadiusAuth::new(config).unwrap();
        
        let mut credentials = HashMap::new();
        credentials.insert("username".to_string(), "testuser".to_string());
        // Missing password should fail
        
        let result = auth.authenticate(credentials).await;
        assert!(result.is_err());
    }
}
