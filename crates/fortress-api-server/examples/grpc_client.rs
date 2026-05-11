use fortress_api_server::grpc::fortress::{
    fortress_service_client::FortressServiceClient,
    CreateDatabaseRequest, DatabaseConfig, EncryptRequest, DecryptRequest,
};
use tonic::transport::Channel;
use tracing::{info, error};

#[derive(Clone)]
pub struct FortressGrpcClient {
    client: FortressServiceClient<Channel>,
}

impl FortressGrpcClient {
    pub async fn connect(addr: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = FortressServiceClient::connect(addr.to_string()).await?;
        Ok(Self { client })
    }

    pub async fn create_database(
        &mut self,
        name: String,
        description: String,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let request = tonic::Request::new(CreateDatabaseRequest {
            name,
            description,
            config: Some(DatabaseConfig {
                encryption_algorithm: "aes-256-gcm".to_string(),
                key_rotation_interval_days: 30,
                enable_audit_logging: true,
                custom_settings: std::collections::HashMap::new(),
            }),
        });

        match self.client.create_database(request).await {
            Ok(response) => {
                let db = response.into_inner().database.unwrap();
                info!("Created database: {} (ID: {})", db.name, db.id);
                Ok(())
            }
            Err(e) => {
                error!("Failed to create database: {}", e);
                Err(Box::new(e))
            }
        }
    }

    pub async fn encrypt_data(
        &mut self,
        database_id: String,
        plaintext: Vec<u8>,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let request = tonic::Request::new(EncryptRequest {
            database_id,
            plaintext,
            key_id: "".to_string(),
            metadata: std::collections::HashMap::new(),
        });

        match self.client.encrypt_data(request).await {
            Ok(response) => {
                let ciphertext = response.into_inner().ciphertext;
                info!("Data encrypted successfully");
                Ok(ciphertext)
            }
            Err(e) => {
                error!("Failed to encrypt data: {}", e);
                Err(Box::new(e))
            }
        }
    }

    pub async fn decrypt_data(
        &mut self,
        database_id: String,
        ciphertext: Vec<u8>,
        key_id: String,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let request = tonic::Request::new(DecryptRequest {
            database_id,
            ciphertext,
            key_id,
        });

        match self.client.decrypt_data(request).await {
            Ok(response) => {
                let plaintext = response.into_inner().plaintext;
                info!("Data decrypted successfully");
                Ok(plaintext)
            }
            Err(e) => {
                error!("Failed to decrypt data: {}", e);
                Err(Box::new(e))
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let mut client = FortressGrpcClient::connect("http://127.0.0.1:50051").await?;

    // Create a database
    client.create_database(
        "test-db".to_string(),
        "Test database for gRPC demo".to_string(),
    ).await?;

    // Encrypt some data
    let plaintext = b"Hello, gRPC World!".to_vec();
    let ciphertext = client.encrypt_data("test-db-id".to_string(), plaintext.clone()).await?;

    println!("Original: {:?}", String::from_utf8(plaintext)?);
    println!("Encrypted: {:?}", ciphertext);

    // Decrypt the data
    let decrypted = client.decrypt_data("test-db-id".to_string(), ciphertext, "key-id".to_string()).await?;
    println!("Decrypted: {:?}", String::from_utf8(decrypted)?);

    Ok(())
}
