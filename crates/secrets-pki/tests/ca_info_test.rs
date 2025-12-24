use secreton_secrets_pki::{PkiEngine, PkiConfig};
use rcgen::{CertificateParams, KeyPair};

#[tokio::test]
async fn test_get_ca_info_real_parsing() {
    // 1. Generate a CA certificate
    let mut params = CertificateParams::new(vec![]).unwrap();
    params.distinguished_name.push(rcgen::DnType::CommonName, "Test CA");
    params.distinguished_name.push(rcgen::DnType::OrganizationName, "Test Org");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    let ca_pem = cert.pem();
    let ca_key_pem = key_pair.serialize_pem();

    // 2. Configure Engine with this CA
    let config = PkiConfig {
        default_lease_ttl: 3600,
        max_lease_ttl: 7200,
        ca_cert: Some(ca_pem.clone()),
        ca_key: Some(ca_key_pem),
        crl: None,
    };

    let engine = PkiEngine::new(config);

    // 3. Call get_ca_info
    let result = engine.get_ca_info().await;

    // 4. Verify
    assert!(result.is_ok());
    let ca_info = result.unwrap();

    // Check if it matches our generated CA
    // We expect exact match now

    assert_eq!(ca_info.certificate, ca_pem);

    assert_eq!(ca_info.subject.get("common_name").map(|s| s.as_str()), Some("Test CA"));
    assert_eq!(ca_info.subject.get("organization").map(|s| s.as_str()), Some("Test Org"));
}
