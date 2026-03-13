use clap::Parser;
use color_eyre::eyre::Result;
use tracing::{info, error};

mod commands;
mod utils;
mod types;

use commands::{create_simple, cluster, tenant, plugin, start, status, key, config, migrate};
use types::{Commands, KeyAction, ConfigAction};
use commands::cluster::ClusterCommands;
use commands::tenant::TenantCommands;
use commands::plugin::PluginAction;

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
        Commands::Create { name, template, data_dir, interactive, dry_run } => {
            create_simple::handle_create_simple(name, template, data_dir, interactive, dry_run).await
        }
        Commands::Migrate { from, to, source, data_dir, table, batch_size, progress } => {
            migrate::handle_migrate(from, to, source, data_dir, table, batch_size, progress).await
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
            let actual_action = crate::commands::cluster::ClusterCommands::from(action);
            cluster::execute_cluster_command(actual_action).await.map_err(|e| color_eyre::eyre::eyre!("Cluster command failed: {}", e))
        }
        Commands::Tenant { action } => {
            let actual_action = crate::commands::tenant::TenantCommands::from(action);
            tenant::execute_tenant_command(actual_action).await.map_err(|e| color_eyre::eyre::eyre!("Tenant command failed: {}", e))
        }
        Commands::Plugin { action } => {
            let actual_action = crate::commands::plugin::PluginAction::from(action);
            plugin::execute_plugin_command(actual_action).await.map_err(|e| color_eyre::eyre::eyre!("Plugin command failed: {}", e))
        }
    }
}

/// Public function to run CLI with custom arguments (for NAPI bindings)
pub async fn run_cli_with_args(args: &[&str]) -> Result<String> {
    use std::io::{self, Write};
    
    // Capture stdout
    let mut buffer: Vec<u8> = Vec::new();
    
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
