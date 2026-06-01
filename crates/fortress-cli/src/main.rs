use clap::Parser;

use color_eyre::eyre::Result;

use tracing::{error, info};

mod commands;

mod utils;

mod types;

use commands::{cluster, config, create_simple, key, migrate, plugin, start, status, tenant};

use types::{Commands, ConfigAction, KeyAction};

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

/// Get suggestions for similar commands using strsim library
fn get_suggestions(input: &str, commands: &[&str]) -> Vec<String> {
    let mut suggestions: Vec<(String, usize)> = commands
        .iter()
        .map(|&cmd| {
            let similarity = strsim::levenshtein(input, cmd);
            (cmd.to_string(), similarity)
        })
        .filter(|(_, similarity)| *similarity <= 2) // Only suggest if distance is 2 or less
        .collect();

    // Sort by similarity (lower distance = closer match)
    suggestions.sort_by_key(|(_, similarity)| *similarity);

    suggestions.into_iter().map(|(cmd, _)| cmd).collect()
}

/// Display suggestions to the user
fn display_suggestions(invalid_command: &str) {
    let available_commands = vec![
        "create", "migrate", "start", "stop", "status", "key", "config", "cluster", "tenant",
        "plugin",
    ];

    let suggestions = get_suggestions(invalid_command, &available_commands);

    if !suggestions.is_empty() {
        eprintln!("\nDid you mean:");
        for suggestion in suggestions.iter().take(3) {
            // Show max 3 suggestions
            eprintln!("   fortress {}", suggestion);
        }
        eprintln!("\nAvailable commands: {}", available_commands.join(", "));
        eprintln!("Use 'fortress --help' for detailed usage information.");
    } else {
        eprintln!("\nAvailable commands: {}", available_commands.join(", "));
        eprintln!("Use 'fortress --help' for detailed usage information.");
    }
}

#[tokio::main]

async fn main() -> Result<()> {
    color_eyre::install()?;

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,

        Err(e) => {
            // Extract the invalid command from the error message

            let error_msg = e.to_string();

            // Check if it's an unrecognized subcommand error

            if error_msg.contains("unrecognized subcommand") {
                // Try to extract the command name

                let parts: Vec<&str> = error_msg.split_whitespace().collect();

                if let Some(pos) = parts.iter().position(|&p| p == "subcommand") {
                    if pos + 1 < parts.len() {
                        let invalid_command = parts[pos + 1].trim_matches('"');

                        eprintln!("✗ Unrecognized command: '{}'", invalid_command);

                        display_suggestions(invalid_command);
                    }
                }
            } else {
                eprintln!("✗ {}", e);

                eprintln!("Use 'fortress --help' for usage information.");
            }

            std::process::exit(1);
        }
    };

    // Initialize logging

    let log_level = if cli.verbose { "debug" } else { "info" };

    tracing_subscriber::fmt().with_env_filter(log_level).init();

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
        Commands::Create {
            name,
            template,
            data_dir,
            interactive,
            dry_run,
        } => {
            create_simple::handle_create_simple(name, template, data_dir, interactive, dry_run)
                .await
        }

        Commands::Migrate {
            from,
            to,
            source,
            data_dir,
            table,
            batch_size,
            progress,
        } => migrate::handle_migrate(from, to, source, data_dir, table, batch_size, progress).await,

        Commands::Start {
            data_dir,
            port,
            host,
        } => start::handle_start(data_dir, port, host).await,

        Commands::Stop => {
            println!("Stopping Fortress Server");

            println!("Stop command not yet implemented.");

            Ok(())
        }

        Commands::Status { data_dir } => status::handle_status(data_dir).await,

        Commands::Key { action } => key::handle_key_action(action).await,

        Commands::Config { action } => config::handle_config_action(action).await,

        Commands::Cluster { action } => {
            let actual_action = crate::commands::cluster::ClusterCommands::from(action);

            cluster::execute_cluster_command(actual_action)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Cluster command failed: {}", e))
        }

        Commands::Tenant { action } => {
            let actual_action = crate::commands::tenant::TenantCommands::from(action);

            tenant::execute_tenant_command(actual_action)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Tenant command failed: {}", e))
        }

        Commands::Plugin { action } => {
            let actual_action = crate::commands::plugin::PluginAction::from(action);

            plugin::execute_plugin_command(actual_action)
                .await
                .map_err(|e| color_eyre::eyre::eyre!("Plugin command failed: {}", e))
        }
    }
}

/// Public function to run CLI with custom arguments (for NAPI bindings)

pub async fn run_cli_with_args(args: &[&str]) -> Result<String> {
    use std::io;

    // Capture stdout

    let _buffer: Vec<u8> = Vec::new();

    // Override stdout temporarily

    let _original_stdout = io::stdout();

    // Parse CLI with custom args

    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,

        Err(e) => {
            return Ok(format!("CLI Error: {}", e));
        }
    };

    // Initialize logging

    let _log_level = if cli.verbose { "debug" } else { "info" };

    // Run the command and capture output

    match run_command(cli.command).await {
        Ok(_) => Ok("Command completed successfully".to_string()),

        Err(e) => Ok(format!("Command failed: {}", e)),
    }
}
