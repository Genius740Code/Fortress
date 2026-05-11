#![cfg(feature = "grpc")]

use fortress_api_server::grpc::{GrpcServer, FortressGrpcService};
use fortress_core::field_encryption::FieldEncryptionManager;
use fortress_core::key::InMemoryKeyManager;
use fortress_api_server::grpc::fortress::{
    fortress_service_client::FortressServiceClient,
    CreateDatabaseRequest, DatabaseConfig, EncryptRequest, DecryptRequest,
    HealthCheckRequest,
};
use std::sync::Arc;
use tokio::time::{timeout, Duration};
use tonic::transport::Channel;
use tonic::Request;

async fn setup_test_server() -> (String, FortressGrpcService) {
    let key_manager = Arc::new(InMemoryKeyManager::new());
    let encryption_manager = Arc::new(DefaultFieldEncryptionManager::new(key_manager));
    let service = FortressGrpcService::new(encryption_manager);
    
    // Start server on a random port
    let server = GrpcServer::new("127.0.0.1:0".parse().unwrap(), Arc::new(service.clone()));
    let addr = server.start().await.unwrap();
    
    (format!("http://{}", addr), service)
}

async fn create_client(addr: &str) -> FortressServiceClient<Channel> {
    FortressServiceClient::connect(addr.to_string()).await.unwrap()
}

#[tokio::test]
async fn test_health_check() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    let request = Request::new(HealthCheckRequest {});
    let response = client.health_check(request).await;

    assert!(response.is_ok());
    let health_response = response.unwrap().into_inner();
    assert_eq!(health_response.status, 1); // Healthy
    assert_eq!(health_response.version, "0.1.0");
}

#[tokio::test]
async fn test_create_database() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    let request = Request::new(CreateDatabaseRequest {
        name: "test-db".to_string(),
        description: "Test database".to_string(),
        config: Some(DatabaseConfig {
            encryption_algorithm: "aes-256-gcm".to_string(),
            key_rotation_interval_days: 30,
            enable_audit_logging: true,
            custom_settings: std::collections::HashMap::new(),
        }),
    });

    let response = client.create_database(request).await;
    assert!(response.is_ok());
    
    let db_response = response.unwrap().into_inner();
    let database = db_response.database.unwrap();
    assert_eq!(database.name, "test-db");
    assert_eq!(database.description, "Test database");
    assert!(!database.id.is_empty());
}

#[tokio::test]
async fn test_encrypt_decrypt_data() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    let database_id = "test-db-id".to_string();
    let plaintext = b"Hello, gRPC World!".to_vec();

    // Test encryption
    let encrypt_request = Request::new(EncryptRequest {
        database_id: database_id.clone(),
        plaintext: plaintext.clone(),
        key_id: "".to_string(),
        metadata: std::collections::HashMap::new(),
    });

    let encrypt_response = client.encrypt_data(encrypt_request).await;
    assert!(encrypt_response.is_ok());
    
    let encrypt_result = encrypt_response.unwrap().into_inner();
    let ciphertext = encrypt_result.ciphertext;
    let key_id = encrypt_result.key_id;
    assert!(!ciphertext.is_empty());
    assert!(!key_id.is_empty());

    // Test decryption
    let decrypt_request = Request::new(DecryptRequest {
        database_id,
        ciphertext,
        key_id,
    });

    let decrypt_response = client.decrypt_data(decrypt_request).await;
    assert!(decrypt_response.is_ok());
    
    let decrypt_result = decrypt_response.unwrap().into_inner();
    let decrypted_plaintext = decrypt_result.plaintext;
    assert_eq!(decrypted_plaintext, plaintext);
}

#[tokio::test]
async fn test_batch_operations_timeout() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    // Test that batch operations don't hang indefinitely
    let result = timeout(
        Duration::from_secs(5),
        async {
            let _stream = client.batch_encrypt(Request::new(
                tokio_stream::empty()
            )).await;
        }
    ).await;

    assert!(result.is_ok(), "Batch operation should complete or timeout within 5 seconds");
}

#[tokio::test]
async fn test_error_handling() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    // Test getting non-existent database
    let request = Request::new(fortress_server::grpc::fortress::GetDatabaseRequest {
        database_id: "non-existent".to_string(),
    });

    let response = client.get_database(request).await;
    assert!(response.is_err());
    
    let status = response.unwrap_err();
    assert_eq!(status.code(), tonic::Code::NotFound);
}

#[tokio::test]
async fn test_metrics_endpoint() {
    let (addr, _) = setup_test_server().await;
    let mut client = create_client(&addr).await;

    let request = Request::new(fortress_server::grpc::fortress::MetricsRequest {});
    let response = client.get_metrics(request).await;

    assert!(response.is_ok());
    
    let metrics_response = response.unwrap().into_inner();
    assert!(metrics_response.timestamp.is_some());
    // Metrics should be empty initially but structure should be valid
    assert!(metrics_response.counters.is_empty());
    assert!(metrics_response.gauges.is_empty());
    assert!(metrics_response.histograms.is_empty());
}
