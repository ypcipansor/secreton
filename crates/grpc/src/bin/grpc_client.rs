use secreton_grpc::secreton::v1::secret_service_client::SecretServiceClient;
use secreton_grpc::secreton::v1::{GetSecretRequest, PutSecretRequest};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_static("http://127.0.0.1:50051")
        .connect()
        .await?;

    let token: MetadataValue<_> = "Bearer admin-token".parse()?;

    let mut client =
        SecretServiceClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
            req.metadata_mut().insert("authorization", token.clone());
            Ok(req)
        });

    println!("Putting secret...");
    let mut data = std::collections::HashMap::new();
    data.insert("grpc_key".to_string(), "grpc_value".to_string());

    let request = tonic::Request::new(PutSecretRequest {
        path: "grpc/secret".into(),
        data,
    });
    let response = client.put_secret(request).await?;
    println!("RESPONSE PUT: {:?}", response);

    println!("Getting secret...");
    let request = tonic::Request::new(GetSecretRequest {
        path: "grpc/secret".into(),
    });
    let response = client.get_secret(request).await?;
    println!("RESPONSE GET: {:?}", response);

    Ok(())
}
