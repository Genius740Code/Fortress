// Simple gRPC example to test our implementation
use fortress_server::grpc::{GrpcServer, FortressGrpcService};
use fortress_core::encryption::EncryptionManager;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let encryption_manager = Arc::new(EncryptionManager::default());
    let addr = "127.0.0.1:50051".parse()?;

    let server = GrpcServer::new(addr, encryption_manager);
    
    println!("Starting gRPC-compatible server on {}", addr);
    server.start().await?;

    Ok(())
}
