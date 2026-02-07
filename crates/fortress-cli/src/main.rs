use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use tracing::{info, error};

mod commands;
mod utils;

use commands::create_simple;

#[derive(Parser)]
#[command(name = "fortress")]
#[command(about = "Fortress - Turnkey Simplicity + HashiCorp Vault Security")]
#[command(version = "0.1.0")]
#[command(author = "Fortress Team <team@fortress-db.com>")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,
    
    /// Configuration file path
    #[arg(short, long, global = true)]
    pub config: Option<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Create a new Fortress database
    Create {
        /// Database name
        #[arg(short, long)]
        name: Option<String>,
        
        /// Template to use (startup, enterprise, custom)
        #[arg(short, long, default_value = "startup")]
        template: String,
        
        /// Data directory path
        #[arg(short, long)]
        data_dir: Option<String>,
        
        /// Interactive mode
        #[arg(short, long)]
        interactive: bool,
    },
    /// Start Fortress server
    Start {
        /// Data directory path
        #[arg(short, long)]
        data_dir: Option<String>,
        
        /// Port to listen on
        #[arg(short = 'p', long, default_value = "8080")]
        port: u16,
        
        /// Host to bind to
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
    },
    /// Stop Fortress server
    Stop,
    /// Show database status
    Status {
        /// Data directory path
        #[arg(short, long)]
        data_dir: Option<String>,
    },
    /// Manage encryption keys
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },
    /// Manage configuration
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Generate new encryption key
    Generate,
    /// List all keys
    List,
    /// Rotate encryption key
    Rotate,
    /// Show key information
    Show {
        /// Key ID
        key_id: String,
    },
}

#[derive(Subcommand)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Set configuration value
    Set {
        /// Configuration key
        key: String,
        /// Configuration value
        value: String,
    },
    /// Reset configuration to defaults
    Reset,
    /// Validate configuration
    Validate,
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();
    
    info!("Fortress CLI v0.1.0 starting");
    
    match run_command(cli.command).await {
        Ok(_) => {
            info!("Command completed successfully");
            Ok(())
        }
        Err(e) => {
            error!("Command failed: {}", e);
            std::process::exit(1);
        }
    }
}

async fn run_command(command: Commands) -> Result<()> {
    match command {
        Commands::Create { name, template, data_dir, interactive } => {
            create_simple::handle_create_simple(name, template, data_dir, interactive).await
        }
        Commands::Start { data_dir, port, host } => {
            println!("🚀 Starting Fortress Server");
            println!("Start command not yet implemented.");
            Ok(())
        }
        Commands::Stop => {
            println!("🛑 Stopping Fortress Server");
            println!("Stop command not yet implemented.");
            Ok(())
        }
        Commands::Status { data_dir } => {
            println!("📊 Fortress Database Status");
            println!("Status command not yet implemented.");
            Ok(())
        }
        Commands::Key { action } => {
            println!("🔑 Key Management");
            println!("Key command not yet implemented.");
            Ok(())
        }
        Commands::Config { action } => {
            println!("⚙️ Configuration Management");
            println!("Config command not yet implemented.");
            Ok(())
        }
    }
}
