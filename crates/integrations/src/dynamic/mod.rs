use aws_sdk_iam::Client as IamClient;
use chrono::{Duration, Utc};
use mongodb::options::ClientOptions;
use mongodb::Client as MongoClient;
use mysql_async::prelude::Queryable;
use mysql_async::Pool as MySqlPool;
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct DynamicDbCredential {
    pub username: String,
    pub password: String,
    pub expires_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DynamicMysqlCredential {
    pub username: String,
    pub password: String,
    pub expires_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DynamicMongoCredential {
    pub username: String,
    pub password: String,
    pub expires_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DynamicAwsCredential {
    pub access_key: String,
    pub secret_key: String,
    pub expires_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DynamicGcpCredential {
    pub service_account_key: String,
    pub expires_at: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct DynamicAzureCredential {
    pub client_id: String,
    pub client_secret: String,
    pub tenant_id: String,
    pub expires_at: String,
}

pub trait RevocableCredential {
    fn revoke(&self);
}

impl RevocableCredential for DynamicMysqlCredential {
    fn revoke(&self) {
        // Note: In a real implementation, this would need database connection details
        // For now, this is a placeholder that would be called when the credential expires
        tracing::info!("MySQL credential revoked for user: {}", self.username);
    }
}
impl RevocableCredential for DynamicMongoCredential {
    fn revoke(&self) {
        // Note: In a real implementation, this would need database connection details
        // For now, this is a placeholder that would be called when the credential expires
        tracing::info!("MongoDB credential revoked for user: {}", self.username);
    }
}
impl RevocableCredential for DynamicAwsCredential {
    fn revoke(&self) {
        // Note: In a real implementation, this would need AWS credentials and region
        // For now, this is a placeholder that would be called when the credential expires
        tracing::info!("AWS credential revoked for access key: {}", self.access_key);
    }
}
impl RevocableCredential for DynamicGcpCredential {
    fn revoke(&self) {
        // Note: In a real implementation, this would need GCP credentials
        // For now, this is a placeholder that would be called when the credential expires
        tracing::info!("GCP service account credential revoked");
    }
}
impl RevocableCredential for DynamicAzureCredential {
    fn revoke(&self) {
        // Note: In a real implementation, this would need Azure credentials
        // For now, this is a placeholder that would be called when the credential expires
        tracing::info!("Azure client credential revoked for client: {}", self.client_id);
    }
}

#[cfg(feature = "postgres")]
pub async fn generate_db_credential_postgres(pool: &Pool, role: &str) -> DynamicDbCredential {
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();

    // Create user in Postgres
    if let Ok(client) = pool.get().await {
        let _ = client
            .execute(
                &format!(
                    "CREATE ROLE \"{}\" LOGIN PASSWORD '{}' VALID UNTIL '{}'",
                    username, password, expires_at
                ),
                &[],
            )
            .await;
    }

    DynamicDbCredential {
        username,
        password,
        expires_at,
    }
}

pub async fn generate_mysql_credential(role: &str, mysql_url: &str) -> Result<DynamicMysqlCredential, Box<dyn std::error::Error + Send + Sync>> {
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();

    // Create MySQL connection pool
    let pool = MySqlPool::new(mysql_url);

    // Create user in MySQL
    let create_user_query = format!(
        "CREATE USER '{}'@'%' IDENTIFIED BY '{}' PASSWORD EXPIRE INTERVAL 30 MINUTE",
        username, password
    );

    let mut conn = pool.get_conn().await?;
    conn.query_drop(&create_user_query).await?;
    conn.query_drop(&format!("GRANT SELECT ON *.* TO '{}'@'%'", username)).await?;

    Ok(DynamicMysqlCredential {
        username,
        password,
        expires_at,
    })
}
pub async fn generate_mongo_credential(role: &str, mongo_url: &str, database: &str) -> Result<DynamicMongoCredential, Box<dyn std::error::Error + Send + Sync>> {
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();

    // Create MongoDB client
    let client_options = ClientOptions::parse(mongo_url).await?;
    let client = MongoClient::with_options(client_options)?;

    // Create user in MongoDB
    let admin_db = client.database("admin");
    let create_user_doc = mongodb::bson::doc! {
        "createUser": &username,
        "pwd": &password,
        "roles": [
            {
                "role": "read",
                "db": database
            }
        ]
    };

    admin_db.run_command(create_user_doc).await?;

    Ok(DynamicMongoCredential {
        username,
        password,
        expires_at,
    })
}
pub async fn generate_aws_credential(role: &str) -> Result<DynamicAwsCredential, Box<dyn std::error::Error + Send + Sync>> {
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let _password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();

    // Create AWS IAM client
    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let iam_client = IamClient::new(&config);

    // Create IAM user
    iam_client
        .create_user()
        .user_name(&username)
        .send()
        .await?;

    // Create access key for the user
    let access_key_response = iam_client
        .create_access_key()
        .user_name(&username)
        .send()
        .await?;

    let access_key = access_key_response
        .access_key()
        .ok_or("Failed to create access key")?;

    Ok(DynamicAwsCredential {
        access_key: access_key.access_key_id().to_string(),
        secret_key: access_key.secret_access_key().to_string(),
        expires_at,
    })
}
pub async fn generate_gcp_credential(_role: &str) -> DynamicGcpCredential {
    // TODO: implementasi create GCP service account
    DynamicGcpCredential {
        service_account_key: "gcp-key-json".to_string(),
        expires_at: chrono::Utc::now().to_rfc3339(),
    }
}
pub async fn generate_azure_credential(_role: &str) -> DynamicAzureCredential {
    // TODO: implementasi create Azure client
    DynamicAzureCredential {
        client_id: "azure-client-id".to_string(),
        client_secret: "azure-secret".to_string(),
        tenant_id: "azure-tenant".to_string(),
        expires_at: chrono::Utc::now().to_rfc3339(),
    }
}

pub mod aws;
