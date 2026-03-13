//! CLI type definitions
//!
//! This module contains the common types used across the CLI commands.

use clap::Subcommand;

// Placeholder types to avoid circular dependencies
// These will be replaced with actual implementations when the modules are properly structured
#[derive(Debug, Clone, Subcommand)]
pub enum ClusterCommands {
    /// Initialize a new cluster
    Init,
    /// Show cluster status
    Status,
}

#[derive(Debug, Clone, Subcommand)]
pub enum TenantCommands {
    /// Create a new tenant
    Create,
    /// List tenants
    List,
}

#[derive(Debug, Clone, Subcommand)]
pub enum PluginAction {
    /// List plugins
    List,
    /// Install a plugin
    Install,
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
        
        /// Show template preview without creating
        #[arg(long)]
        dry_run: bool,
    },
    /// Migrate data from PostgreSQL to Fortress
    Migrate {
        /// Source database type
        #[arg(short, long, default_value = "postgres")]
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
        #[arg(short, long)]
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
        action: ClusterCommands,
    },
    /// Manage tenant operations
    Tenant {
        #[command(subcommand)]
        action: TenantCommands,
    },
    /// Manage plugins
    Plugin {
        #[command(subcommand)]
        action: PluginAction,
    },
}

#[derive(Subcommand)]
pub enum KeyAction {
    /// Generate new encryption key
    Generate,
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
    fn from(_placeholder: ClusterCommands) -> Self {
        // For now, return a default value
        // In a real implementation, this would convert the placeholder to the actual type
        crate::commands::cluster::ClusterCommands::Status
    }
}

impl From<TenantCommands> for crate::commands::tenant::TenantCommands {
    fn from(_placeholder: TenantCommands) -> Self {
        // For now, return a default value
        crate::commands::tenant::TenantCommands::List
    }
}

impl From<PluginAction> for crate::commands::plugin::PluginAction {
    fn from(_placeholder: PluginAction) -> Self {
        // For now, return a default value
        crate::commands::plugin::PluginAction::List { detailed: false, category: None }
    }
}
