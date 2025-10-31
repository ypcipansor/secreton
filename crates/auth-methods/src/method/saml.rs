//! SAML authentication method

use crate::error::*;
use crate::model::*;
use crate::service::*;
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose};
use reqwest::Client;
use xml::reader::{EventReader, XmlEvent};

/// SAML authentication method
pub struct SamlAuthMethod {
    enabled: bool,
    config: Option<AuthMethod>,
    saml_config: Option<SamlConfig>,
    _http_client: Client,
}

impl SamlAuthMethod {
    pub fn new() -> Self {
        Self {
            enabled: false,
            config: None,
            saml_config: None,
            _http_client: Client::new(),
        }
    }

    /// Set SAML configuration
    pub fn set_saml_config(&mut self, config: SamlConfig) {
        self.saml_config = Some(config);
    }

    /// Generate SAML authentication request
    pub fn generate_authn_request(&self) -> AuthMethodResult<String> {
        let config = self
            .saml_config
            .as_ref()
            .ok_or(AuthMethodError::ConfigurationError(
                "SAML config not set".to_string(),
            ))?;

        let request_id = format!("_{}", uuid::Uuid::new_v4().simple());
        let issue_instant = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

        let authn_request = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                    ID="{}"
                    Version="2.0"
                    IssueInstant="{}"
                    AssertionConsumerServiceURL="{}">
    <saml:Issuer>{}</saml:Issuer>
</samlp:AuthnRequest>"#,
            request_id, issue_instant, config.acs_url, config.entity_id
        );

        // Compress and base64 encode
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        use std::io::Write;
        encoder
            .write_all(authn_request.as_bytes())
            .map_err(|e| AuthMethodError::SamlError(format!("Compression failed: {}", e)))?;
        let compressed = encoder
            .finish()
            .map_err(|e| AuthMethodError::SamlError(format!("Compression finish failed: {}", e)))?;

        Ok(general_purpose::URL_SAFE.encode(&compressed))
    }

    /// Parse SAML response
    pub fn parse_saml_response(&self, saml_response: &str) -> AuthMethodResult<SamlAssertion> {
        // Decode base64
        let decoded = general_purpose::URL_SAFE
            .decode(saml_response)
            .map_err(|e| AuthMethodError::SamlError(format!("Base64 decode failed: {}", e)))?;

        // Decompress if needed
        let xml_data = if decoded.len() > 2 && decoded[0] == 0x1f && decoded[1] == 0x8b {
            let mut decoder = flate2::read::GzDecoder::new(&decoded[..]);
            let mut decompressed = Vec::new();
            use std::io::Read;
            decoder
                .read_to_end(&mut decompressed)
                .map_err(|e| AuthMethodError::SamlError(format!("Decompression failed: {}", e)))?;
            decompressed
        } else {
            decoded
        };

        let xml_str = String::from_utf8(xml_data)
            .map_err(|e| AuthMethodError::SamlError(format!("UTF-8 decode failed: {}", e)))?;

        // Parse XML
        self.parse_saml_xml(&xml_str)
    }

    /// Parse SAML XML response
    fn parse_saml_xml(&self, xml: &str) -> AuthMethodResult<SamlAssertion> {
        let parser = EventReader::from_str(xml);
        let mut in_assertion = false;
        let mut in_subject = false;
        let mut in_attribute_statement = false;
        let mut current_element = String::new();
        let mut assertion = SamlAssertion::default();
        let mut current_attribute = None;

        for event in parser {
            match event {
                Ok(XmlEvent::StartElement { name, .. }) => {
                    current_element = name.local_name.to_string();
                    match name.local_name.as_str() {
                        "Assertion" => in_assertion = true,
                        "Subject" => in_subject = true,
                        "AttributeStatement" => in_attribute_statement = true,
                        "Attribute" => {
                            if in_attribute_statement {
                                current_attribute = Some(SamlAttribute::default());
                            }
                        }
                        _ => {}
                    }
                }
                Ok(XmlEvent::Characters(text)) => {
                    if in_assertion && in_subject && current_element == "NameID" {
                        assertion.name_id = text;
                    } else if in_attribute_statement && current_element == "AttributeValue" {
                        if let Some(ref mut attr) = current_attribute {
                            attr.values.push(text);
                        }
                    }
                }
                Ok(XmlEvent::EndElement { name }) => {
                    match name.local_name.as_str() {
                        "Assertion" => in_assertion = false,
                        "Subject" => in_subject = false,
                        "AttributeStatement" => in_attribute_statement = false,
                        "Attribute" => {
                            if let Some(attr) = current_attribute.take() {
                                assertion.attributes.push(attr);
                            }
                        }
                        _ => {}
                    }
                    current_element = String::new();
                }
                Err(e) => {
                    return Err(AuthMethodError::SamlError(format!(
                        "XML parsing error: {}",
                        e
                    )));
                }
                _ => {}
            }
        }

        Ok(assertion)
    }
}

#[async_trait]
impl AuthMethodImpl for SamlAuthMethod {
    fn method_type(&self) -> AuthMethodType {
        AuthMethodType::Saml
    }

    async fn init(&mut self, config: &AuthMethod) -> AuthMethodResult<()> {
        self.config = Some(config.clone());

        // Parse SAML configuration from config
        if let (Some(idp_sso_url), Some(idp_entity_id), Some(entity_id), Some(acs_url)) = (
            config.config.get("idp_sso_url").and_then(|v| v.as_str()),
            config.config.get("idp_entity_id").and_then(|v| v.as_str()),
            config.config.get("entity_id").and_then(|v| v.as_str()),
            config.config.get("acs_url").and_then(|v| v.as_str()),
        ) {
            let saml_config = SamlConfig {
                idp_sso_url: idp_sso_url.to_string(),
                idp_entity_id: idp_entity_id.to_string(),
                entity_id: entity_id.to_string(),
                acs_url: acs_url.to_string(),
                certificate: config
                    .config
                    .get("certificate")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                private_key: config
                    .config
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            };
            self.set_saml_config(saml_config);
        }

        self.enabled = true;
        Ok(())
    }

    async fn authenticate(&self, _credentials: &AuthCredentials) -> AuthMethodResult<AuthResult> {
        // SAML authentication requires browser-based flow
        // This method should not be called directly for SAML
        Err(AuthMethodError::MethodNotSupported)
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

/// SAML configuration
#[derive(Clone, Debug)]
pub struct SamlConfig {
    pub idp_sso_url: String,
    pub idp_entity_id: String,
    pub entity_id: String,
    pub acs_url: String,
    pub certificate: Option<String>,
    pub private_key: Option<String>,
}

/// SAML assertion
#[derive(Clone, Debug, Default)]
pub struct SamlAssertion {
    pub issuer: String,
    pub name_id: String,
    pub audience: Vec<String>,
    pub not_before: Option<chrono::DateTime<chrono::Utc>>,
    pub not_after: Option<chrono::DateTime<chrono::Utc>>,
    pub attributes: Vec<SamlAttribute>,
}

/// SAML attribute
#[derive(Clone, Debug, Default)]
pub struct SamlAttribute {
    pub name: String,
    pub friendly_name: Option<String>,
    pub name_format: Option<String>,
    pub values: Vec<String>,
}
