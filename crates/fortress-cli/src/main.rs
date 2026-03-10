use clap::{Parser, Subcommand};
use color_eyre::eyre::Result;
use tracing::{info, error};

mod commands;
mod utils;

use commands::{create_simple, cluster, tenant, plugin, start, status, key, config};

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
    /// Manage cluster operations
    Cluster {
        #[command(subcommand)]
        action: cluster::ClusterCommands,
    },
    /// Manage tenant operations
    Tenant {
        #[command(subcommand)]
        action: tenant::TenantCommands,
    },
    /// Manage plugins
    Plugin {
        #[command(subcommand)]
        action: plugin::PluginAction,
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
            start::handle_start(data_dir, port, host).await
        }
        Commands::Stop => {
            println!("🛑 Stopping Fortress Server");
            println!("Stop command not yet implemented.");
            Ok(())
        }
        Commands::Status { data_dir } => {
            status::handle_status(data_dir).await
        }
        Commands::Key { action } => {
            key::handle_key_action(action).await
        }
        Commands::Config { action } => {
            config::handle_config_action(action).await
        }
        Commands::Cluster { action } => {
            cluster::execute_cluster_command(action).await.map_err(|e| color_eyre::eyre::eyre!("Cluster command failed: {}", e))
        }
        Commands::Tenant { action } => {
            tenant::execute_tenant_command(action).await.map_err(|e| color_eyre::eyre::eyre!("Tenant command failed: {}", e))
        }
        Commands::Plugin { action } => {
            plugin::execute_plugin_command(action).await.map_err(|e| color_eyre::eyre::eyre!("Plugin command failed: {}", e))
        }
    }
}

/// Public function to run CLI with custom arguments (for NAPI bindings)
pub async fn run_cli_with_args(args: &[&str]) -> Result<String> {
    use std::io::{self, Write};
    
    // Capture stdout
    let mut buffer = Vec::new();
    
    // Override stdout temporarily
    let original_stdout = io::stdout();
    
    // Parse CLI with custom args
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(e) => {
            return Ok(format!("CLI Error: {}", e));
        }
    };
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    
    // Run the command and capture output
    match run_command(cli.command).await {
        Ok(_) => {
            Ok("Command completed successfully".to_string())
        }
        Err(e) => {
            Ok(format!("Command failed: {}", e))
        }
    }
}
