use color_eyre::eyre::{Result, Context};
use console::style;
use std::path::PathBuf;
use tracing::info;

pub async fn handle_status(data_dir: Option<String>) -> Result<()> {
    println!("{}", style("📊 Fortress Database Status").bold().cyan());
    println!();
    
    let db_path = PathBuf::from(data_dir.unwrap_or_else(|| "./fortress".to_string()));
    
    if !db_path.exists() {
        println!("{} Database not found at: {}", 
            style("❌").red(), 
            style(db_path.display()).bold()
        );
        return Ok(());
    }
    
    // Check configuration
    let config_path = db_path.join("config").join("fortress.toml");
    if config_path.exists() {
        println!("{} Configuration: {}", 
            style("✅").green(), 
            style("Found").green()
        );
    } else {
        println!("{} Configuration: {}", 
            style("❌").red(), 
            style("Missing").red()
        );
    }
    
    // Check keys
    let keys_path = db_path.join("keys");
    if keys_path.exists() {
        println!("{} Encryption keys: {}", 
            style("✅").green(), 
            style("Found").green()
        );
    } else {
        println!("{} Encryption keys: {}", 
            style("❌").red(), 
            style("Missing").red()
        );
    }
    
    // Check data directory
    let data_path = db_path.join("data");
    if data_path.exists() {
        println!("{} Data storage: {}", 
            style("✅").green(), 
            style("Found").green()
        );
    } else {
        println!("{} Data storage: {}", 
            style("❌").red(), 
            style("Missing").red()
        );
    }
    
    println!();
    println!("Database path: {}", style(db_path.display()).bold());
    
    // TODO: Check if server is running
    println!("Server status: {}", style("Not running").yellow());
    
    Ok(())
}
