// Simple gRPC example to test our implementation
use fortress_api_server::prelude::{GrpcServer, FortressGrpcService};
use fortress_core::prelude::{FieldEncryptionManager, DefaultFieldEncryptionManager};
use fortress_core::key::InMemoryKeyManager;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let key_manager = Arc::new(InMemoryKeyManager::new());
    let encryption_manager = Arc::new(DefaultFieldEncryptionManager::new(key_manager));
    let addr = "127.0.0.1:50051".parse()?;

    let server = GrpcServer::new(addr, encryption_manager);
    
    println!("Starting gRPC-compatible server on {}", addr);
    server.start().await?;

    Ok(())
}
