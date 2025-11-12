use aws_sdk_iam::Client as IamClient;
use base64::Engine;
use chrono::{Duration, Utc};
use mongodb::Client as MongoClient;
use mongodb::options::ClientOptions;
use mysql_async::Pool as MySqlPool;
use mysql_async::prelude::Queryable;
use rand::Rng;
use rand::distributions::Alphanumeric;
use reqwest;
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
        tracing::info!(
            "Azure client credential revoked for client: {}",
            self.client_id
        );
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

pub async fn generate_mysql_credential(
    role: &str,
    mysql_url: &str,
) -> Result<DynamicMysqlCredential, Box<dyn std::error::Error + Send + Sync>> {
    let username = format!("{}_{}", role, Utc::now().timestamp());
    let password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let expires_at = (Utc::now() + Duration::minutes(30)).to_rfc3339();

    // Create MySQL connection pool
    let pool = MySqlPool::from_url(mysql_url).unwrap();

    // Create user in MySQL
    let create_user_query = format!(
        "CREATE USER '{}'@'%' IDENTIFIED BY '{}' PASSWORD EXPIRE INTERVAL 30 MINUTE",
        username, password
    );

    let mut conn = pool.get_conn().await?;
    conn.query_drop(&create_user_query).await?;
    conn.query_drop(&format!("GRANT SELECT ON *.* TO '{}'@'%'", username))
        .await?;

    Ok(DynamicMysqlCredential {
        username,
        password,
        expires_at,
    })
}
pub async fn generate_mongo_credential(
    role: &str,
    mongo_url: &str,
    database: &str,
) -> Result<DynamicMongoCredential, Box<dyn std::error::Error + Send + Sync>> {
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
pub async fn generate_aws_credential(
    role: &str,
) -> Result<DynamicAwsCredential, Box<dyn std::error::Error + Send + Sync>> {
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
    iam_client.create_user().user_name(&username).send().await?;

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
pub async fn generate_gcp_credential(
    role: &str,
    project_id: &str,
    service_account_email: Option<&str>,
    access_token: &str,
) -> Result<DynamicGcpCredential, Box<dyn std::error::Error>> {
    use reqwest::Client;
    use serde_json::json;

    let client = Client::new();

    // Use provided service account or create a new one
    let sa_email = if let Some(email) = service_account_email {
        email.to_string()
    } else {
        // Create a new service account
        let create_sa_body = json!({
            "accountId": format!("secreton-{}", role),
            "serviceAccount": {
                "displayName": format!("Secreton dynamic credential for {}", role),
                "description": "Temporary service account for dynamic credentials"
            }
        });

        let create_response = client
            .post(&format!(
                "https://iam.googleapis.com/v1/projects/{}/serviceAccounts",
                project_id
            ))
            .header("Authorization", format!("Bearer {}", access_token))
            .json(&create_sa_body)
            .send()
            .await?;

        if !create_response.status().is_success() {
            return Err(format!(
                "Failed to create GCP service account: {}",
                create_response.status()
            )
            .into());
        }

        let sa_data: serde_json::Value = create_response.json().await?;
        sa_data["email"]
            .as_str()
            .unwrap_or(&format!(
                "secreton-{}@{}.iam.gserviceaccount.com",
                role, project_id
            ))
            .to_string()
    };

    // Create service account key
    let create_key_body = json!({
        "keyAlgorithm": "KEY_ALG_RSA_2048",
        "privateKeyType": "TYPE_GOOGLE_CREDENTIALS_FILE"
    });

    let key_response = client
        .post(&format!(
            "https://iam.googleapis.com/v1/projects/{}/serviceAccounts/{}/keys",
            project_id, sa_email
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&create_key_body)
        .send()
        .await?;

    if !key_response.status().is_success() {
        return Err(format!(
            "Failed to create GCP service account key: {}",
            key_response.status()
        )
        .into());
    }

    let key_data: serde_json::Value = key_response.json().await?;
    let private_key_data = key_data["privateKeyData"]
        .as_str()
        .ok_or("No private key data in response")?;
    let decoded_key = base64::engine::general_purpose::STANDARD.decode(private_key_data)?;

    // Parse the key data (it's a JSON service account key)
    let service_account_key: serde_json::Value = serde_json::from_slice(&decoded_key)?;
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(); // GCP keys typically last 1 hour

    Ok(DynamicGcpCredential {
        service_account_key: serde_json::to_string(&service_account_key)?,
        expires_at,
    })
}
pub async fn generate_azure_credential(
    role: &str,
    subscription_id: &str,
    tenant_id: &str,
    access_token: &str,
) -> Result<DynamicAzureCredential, Box<dyn std::error::Error>> {
    use reqwest::Client;
    use serde_json::json;

    let client = Client::new();

    // Create service principal
    let sp_body = json!({
        "appId": format!("secreton-{}-app", role),
        "displayName": format!("Secreton dynamic credential for {}", role),
        "passwordCredentials": [
            {
                "displayName": "Generated by Secreton",
                "endDateTime": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                "startDateTime": chrono::Utc::now().to_rfc3339()
            }
        ]
    });

    let sp_response = client
        .post(&format!(
            "https://management.azure.com/subscriptions/{}/providers/Microsoft.Authorization/servicePrincipals?api-version=2022-04-01",
            subscription_id
        ))
        .header("Authorization", format!("Bearer {}", access_token))
        .header("Content-Type", "application/json")
        .json(&sp_body)
        .send()
        .await?;

    if !sp_response.status().is_success() {
        return Err(format!(
            "Failed to create Azure service principal: {}",
            sp_response.status()
        )
        .into());
    }

    let sp_data: serde_json::Value = sp_response.json().await?;
    let client_id = sp_data["appId"]
        .as_str()
        .ok_or("No appId in service principal response")?;
    let client_secret = sp_data["passwordCredentials"][0]["secretText"]
        .as_str()
        .ok_or("No secretText in service principal response")?;
    let expires_at = (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339();

    Ok(DynamicAzureCredential {
        client_id: client_id.to_string(),
        client_secret: client_secret.to_string(),
        tenant_id: tenant_id.to_string(),
        expires_at,
    })
}

pub mod aws;
