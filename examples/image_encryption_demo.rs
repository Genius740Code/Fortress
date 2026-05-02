//! Image Encryption Demo for Fortress
//!
//! This example demonstrates how to use Fortress's image encryption capabilities
//! including basic encryption, thumbnail generation, and streaming encryption.
//!
//! NOTE: This example is temporarily disabled due to missing module dependencies.
//! Core encryption functionality is available in the main fortress-core library.

use fortress_core::prelude::*;
use tracing::info;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Image Encryption Demo");
    info!("NOTE: This example is temporarily disabled pending module dependencies");
    info!("Core encryption functionality is available in fortress-core");

    println!("Image encryption demo temporarily disabled");
    println!("Core encryption functionality is available in the main fortress-core library");

    Ok(())
}
