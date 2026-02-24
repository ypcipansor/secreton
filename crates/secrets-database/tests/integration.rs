use secreton_secrets_database::{DatabaseConfig, DatabaseEngine, DatabaseRole};
use tokio_postgres::NoTls;

#[tokio::test]
#[ignore] // Ignored in CI/Sandbox due to missing DB
async fn test_postgres_credentials() {
    let mut config = DatabaseConfig::default();
    // Use env vars or defaults
    config.connection_url = std::env::var("SECRETON_DATABASE__URL")
        .unwrap_or_else(|_| "postgres://secreton:secreton-password@localhost:5432/secreton".to_string());
    // In our implementation, config.username/password override the connection URL for the admin connection
    config.username = Some("secreton".to_string());
    config.password = Some("secreton-password".to_string());

    let mut engine = DatabaseEngine::new(config);
    engine.enable();

    let role = DatabaseRole {
        sql: "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";".to_string(),
        max_ttl: 3600,
        default_ttl: 600,
    };

    engine.add_role("readonly".to_string(), role);

    let creds = engine.generate_credentials("readonly").await.expect("Failed to generate credentials");

    assert!(creds.contains_key("username"));
    assert!(creds.contains_key("password"));
    assert!(creds.contains_key("expiration"));

    // Connect using new creds
    let username = creds.get("username").unwrap().as_str().unwrap();
    let password = creds.get("password").unwrap().as_str().unwrap();
    let connection_string = creds.get("connection_string").unwrap().as_str().unwrap();

    // Construct new config for the generated user
    let mut pg_config: tokio_postgres::Config = connection_string.parse().unwrap();
    pg_config.user(username);
    pg_config.password(password);

    let (client, connection) = pg_config.connect(NoTls).await.expect("Failed to connect with new creds");

    tokio::spawn(async move {
        if let Err(e) = connection.await {
            eprintln!("connection error: {}", e);
        }
    });

    let rows = client.query("SELECT current_user", &[]).await.expect("Failed to query");
    let current_user: String = rows[0].get(0);
    assert_eq!(current_user, username);
}
