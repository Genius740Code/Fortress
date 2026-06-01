//! Working Plugin Example
//!
//! This example demonstrates a complete end-to-end plugin workflow:
//! 1. Loading a plugin from the testplugin directory
//! 2. Registering it with the plugin manager
//! 3. Executing plugin actions
//! 4. Handling results and errors
//!
//! NOTE: This example is temporarily disabled due to missing module dependencies.
//! Core plugin functionality is available in the main fortress-core library.

use tracing::info;

#[tokio::main]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    info!("Working Plugin Example");
    info!("NOTE: This example is temporarily disabled pending module dependencies");
    info!("Core plugin functionality is available in fortress-core");

    println!("Plugin example temporarily disabled");
    println!("Core plugin functionality is available in the main fortress-core library");

    Ok(())
}
