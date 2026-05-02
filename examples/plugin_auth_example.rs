//! Plugin-Based Authentication Example
//!
//! This example demonstrates how to use the hot-swappable authentication system
//! with JWT, OAuth, and SAML plugins.
//!
//! NOTE: This example is temporarily disabled due to missing module dependencies.
//! The core authentication functionality is available in the main fortress-core library.

use fortress_core::prelude::*;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Plugin-Based Authentication Example");
    info!("NOTE: This example is temporarily disabled pending module dependencies");
    info!("Core authentication functionality is available in fortress-core");

    println!("Plugin authentication example temporarily disabled");
    println!("Core authentication functionality is available in the main fortress-core library");

    Ok(())
}
