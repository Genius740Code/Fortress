//! CLI type definitions

//!

//! This module contains the common types used across the CLI commands.



use clap::Subcommand;



// Placeholder types to avoid circular dependencies

// These will be replaced with actual implementations when the modules are properly structured



/// Cluster management commands

#[derive(Debug, Clone, Subcommand)]

pub enum ClusterCommands {

    /// Initialize a new cluster

    Init,

    /// Show cluster status

    Status,

}



/// Tenant management commands

#[derive(Debug, Clone, Subcommand)]

pub enum TenantCommands {

    /// Create a new tenant

    Create,

    /// List tenants

    List,

}



/// Plugin management actions

#[derive(Debug, Subcommand)]

pub enum PluginAction {

    /// List plugins

    List {

        /// Show detailed information

        #[arg(long)]

        detailed: bool,

        

        /// Filter by category

        #[arg(long)]

        category: Option<String>,

    },

    /// Install a plugin

    Install {

        /// Plugin name

        #[arg(long)]

        plugin_name: Option<String>,

        

        /// Plugin path

        #[arg(long)]

        plugin_path: Option<String>,

        

        /// Force installation

        #[arg(long)]

        force: bool,

    },

}



/// Main CLI commands

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

        

        /// Show template preview without creating

        #[arg(long)]

        dry_run: bool,

    },

    /// Migrate data from PostgreSQL to Fortress

    Migrate {

        /// Source database type

        #[arg(short = 'f', long, default_value = "postgres")]

        from: String,

        

        /// Fortress database name

        #[arg(short, long)]

        to: String,

        

        /// Source database connection string

        #[arg(short, long)]

        source: String,

        

        /// Target data directory

        #[arg(short, long)]

        data_dir: Option<String>,

        

        /// Specific table to migrate

        #[arg(short = 'T', long)]

        table: Option<String>,

        

        /// Batch size for migration

        #[arg(short, long, default_value = "1000")]

        batch_size: usize,

        

        /// Enable progress reporting

        #[arg(short, long)]

        progress: bool,

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

        /// Key management action

        #[command(subcommand)]

        action: KeyAction,

    },

    /// Manage configuration

    Config {

        /// Configuration management action

        #[command(subcommand)]

        action: ConfigAction,

    },

    /// Manage cluster operations

    Cluster {

        /// Cluster management action

        #[command(subcommand)]

        action: ClusterCommands,

    },

    /// Manage tenant operations

    Tenant {

        /// Tenant management action

        #[command(subcommand)]

        action: TenantCommands,

    },

    /// Manage plugins

    Plugin {

        /// Plugin management action

        #[command(subcommand)]

        action: PluginAction,

    },

}



/// Key management actions

#[derive(Subcommand)]

pub enum KeyAction {

    /// Generate new encryption key

    Generate {

        /// Algorithm to use (aegis256, aes256, chacha20, hex64)

        #[arg(long, default_value = "aegis256")]

        algorithm: String,

        

        /// Key length in bytes (for hex64 algorithm)

        #[arg(long, default_value = "64")]

        length: usize,

        

        /// Output format (raw, hex, base64)

        #[arg(long, default_value = "hex")]

        format: String,

    },

    /// List all keys

    List,

    /// Rotate encryption key

    Rotate {

        /// Dry run mode (no actual rotation)

        #[arg(long)]

        dry_run: bool,

        

        /// Force rotation (skip safety checks)

        #[arg(long)]

        force: bool,

    },

    /// Rollback to previous key

    Rollback {

        /// Key version to rollback to

        #[arg(long)]

        version: Option<String>,

    },

    /// Show key information

    Show {

        /// Key ID

        key_id: String,

    },

}



/// Configuration management actions

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



// Conversion functions from placeholder types to actual command types

impl From<ClusterCommands> for crate::commands::cluster::ClusterCommands {

    fn from(placeholder: ClusterCommands) -> Self {

        match placeholder {

            ClusterCommands::Init => crate::commands::cluster::ClusterCommands::Init(

                crate::commands::cluster::InitArgs {

                    bind_address: "127.0.0.1:8080".parse().unwrap_or_else(|_| "127.0.0.1:8080".parse().unwrap()),

                    min_nodes: 3,

                    replication_factor: 3,

                    heartbeat_interval: 500,

                    election_timeout: 5000,

                }

            ),

            ClusterCommands::Status => crate::commands::cluster::ClusterCommands::Status,

        }

    }

}



impl From<TenantCommands> for crate::commands::tenant::TenantCommands {

    fn from(placeholder: TenantCommands) -> Self {

        match placeholder {

            TenantCommands::Create => crate::commands::tenant::TenantCommands::Create(

                crate::commands::tenant::CreateArgs {

                    name: "default".to_string(),

                    description: None,

                    max_databases: None,

                    max_storage: None,

                    max_connections: None,

                    resources: None,

                }

            ),

            TenantCommands::List => crate::commands::tenant::TenantCommands::List(

                crate::commands::tenant::ListArgs {

                    detailed: false,

                    status: None,

                    limit: None,

                }

            ),

        }

    }

}



impl From<PluginAction> for crate::commands::plugin::PluginAction {

    fn from(placeholder: PluginAction) -> Self {

        match placeholder {

            PluginAction::List { detailed, category } => {

                crate::commands::plugin::PluginAction::List {

                    detailed,

                    category,

                }

            }

            PluginAction::Install { plugin_name, plugin_path: _, force: _ } => {

                crate::commands::plugin::PluginAction::Search {

                    query: plugin_name.unwrap_or_default(),

                    limit: 10,

                }

            }

        }

    }

}

