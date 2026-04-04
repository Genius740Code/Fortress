//! Simple Fortress server example
//!
//! This example demonstrates how to set up and run a basic Fortress server
//! with the REST API for secure data storage and retrieval.

use fortress_server::prelude::*;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fortress_server=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Create server configuration
    let mut config = ServerConfig::default();
    
    // Customize configuration if needed
    config.network.port = 8080;
    config.network.host = "127.0.0.1".to_string();
    config.features.auth_enabled = true;
    config.features.metrics_enabled = true;
    config.features.health_enabled = true;

    println!("🚀 Starting Fortress server...");
    println!("📍 Server will bind to {}:{}", config.network.host, config.network.port);
    println!("🔐 Authentication: {}", if config.features.auth_enabled { "enabled" } else { "disabled" });
    println!("📊 Metrics: {}", if config.features.metrics_enabled { "enabled" } else { "disabled" });
    println!("💚 Health checks: {}", if config.features.health_enabled { "enabled" } else { "disabled" });

    // Create and start the server
    let server = FortressServer::new(config).await?;
    
    let bind_addr = format!("{}:{}", server.config.network.host, server.config.network.port);
    server.listen(&bind_addr).await?;

    Ok(())
}
