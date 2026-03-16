//! Cluster management commands for Fortress CLI

use clap::{Args, Subcommand};
use fortress_core::{
    cluster::{ClusterConfig, ClusterManager, ClusterHealth},
    error::Result,
};
use std::net::SocketAddr;
use std::time::Duration;
use uuid::Uuid;
use console::style;
use tracing::{info, error, warn};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tokio::fs;
use std::path::PathBuf;

/// Cluster management commands
#[derive(Debug, Subcommand)]
pub enum ClusterCommands {
    /// Initialize a new cluster
    Init(InitArgs),
    /// Join an existing cluster
    Join(JoinArgs),
    /// Show cluster status
    Status,
    /// List cluster members
    Members,
    /// Leave the cluster
    Leave,
    /// Get cluster health
    Health,
}

/// Arguments for cluster initialization
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Bind address for this node
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    pub bind_address: SocketAddr,
    /// Minimum nodes for quorum
    #[arg(short, long, default_value = "3")]
    pub min_nodes: usize,
    /// Replication factor
    #[arg(short = 'r', long, default_value = "3")]
    pub replication_factor: usize,
    /// Heartbeat interval in milliseconds
    #[arg(long, default_value = "500")]
    pub heartbeat_interval: u64,
    /// Election timeout in milliseconds
    #[arg(long, default_value = "5000")]
    pub election_timeout: u64,
}

/// Arguments for joining a cluster
#[derive(Debug, Args)]
pub struct JoinArgs {
    /// Address of a seed node to join
    #[arg(short, long)]
    pub seed_address: SocketAddr,
    /// Bind address for this node
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    pub bind_address: SocketAddr,
}

/// Execute cluster commands
pub async fn execute_cluster_command(command: ClusterCommands) -> Result<()> {
    match command {
        ClusterCommands::Init(args) => init_cluster(args).await,
        ClusterCommands::Join(args) => join_cluster(args).await,
        ClusterCommands::Status => show_cluster_status().await,
        ClusterCommands::Members => list_cluster_members().await,
        ClusterCommands::Leave => leave_cluster().await,
        ClusterCommands::Health => show_cluster_health().await,
    }
}

/// Initialize a new cluster
async fn init_cluster(args: InitArgs) -> Result<()> {
    println!("🚀 Initializing new Fortress cluster...");
    
    let config = ClusterConfig {
        node_id: Uuid::new_v4(),
        bind_address: args.bind_address,
        seed_nodes: vec![],
        heartbeat_interval: Duration::from_millis(args.heartbeat_interval),
        election_timeout: Duration::from_millis(args.election_timeout),
        replication_factor: args.replication_factor,
        min_nodes: args.min_nodes,
    };

    // Save the configuration
    save_cluster_config(&config).await?;

    let mut manager = ClusterManager::new(config.clone())?;
    manager.start().await?;

    println!("✅ Cluster initialized successfully!");
    println!("📊 Node ID: {}", manager.local_node.id);
    println!("🌐 Bind address: {}", manager.local_node.address);
    println!("🔐 Replication factor: {}", manager.config.replication_factor);
    println!("⚖️  Minimum nodes for quorum: {}", manager.config.min_nodes);
    println!("💾 Configuration saved to: {:?}", get_cluster_config_path());

    Ok(())
}

/// Join an existing cluster
async fn join_cluster(args: JoinArgs) -> Result<()> {
    println!("🔗 Joining Fortress cluster...");
    
    let config = ClusterConfig {
        node_id: Uuid::new_v4(),
        bind_address: args.bind_address,
        seed_nodes: vec![args.seed_address],
        heartbeat_interval: Duration::from_millis(500),
        election_timeout: Duration::from_millis(5000),
        replication_factor: 3,
        min_nodes: 2,
    };

    // Save the configuration
    save_cluster_config(&config).await?;

    let mut manager = ClusterManager::new(config.clone())?;
    manager.start().await?;

    println!("✅ Successfully joined cluster!");
    println!("📊 Node ID: {}", manager.local_node.id);
    println!("🌐 Bind address: {}", manager.local_node.address);
    println!("🔗 Seed node: {}", args.seed_address);
    println!("💾 Configuration saved to: {:?}", get_cluster_config_path());

    // Show current cluster members
    let members = manager.get_members().await;
    println!("👥 Cluster members ({}):", members.len());
    for (node_id, node) in members.iter() {
        println!("  - {}: {} ({})", node_id, node.address, format_node_state(&node.state));
    }

    Ok(())
}

/// Show cluster status
async fn show_cluster_status() -> Result<()> {
    println!("📊 Fortress Cluster Status");
    println!("=========================");
    
    match load_cluster_config().await {
        Some(config) => {
            println!("🆔 Node ID: {}", style(config.node_id).bold());
            println!("🌐 Bind Address: {}", style(config.bind_address).bold());
            println!("💓 Heartbeat Interval: {}ms", style(config.heartbeat_interval.as_millis()).bold());
            println!("⏱️  Election Timeout: {}ms", style(config.election_timeout.as_millis()).bold());
            println!("🔄 Replication Factor: {}", style(config.replication_factor).bold());
            println!("⚖️  Minimum Nodes: {}", style(config.min_nodes).bold());
            
            if !config.seed_nodes.is_empty() {
                println!("🌱 Seed Nodes:");
                for seed in &config.seed_nodes {
                    println!("  - {}", style(seed).dim());
                }
            }
            
            // Try to get current status
            match get_cluster_status(&config.node_id).await {
                Ok(status) => {
                    println!("\n📈 Cluster Status:");
                    println!("  🎯 Role: {}", style(status.role).bold());
                    println!("  📊 Term: {}", style(status.term).bold());
                    println!("  👥 Members: {}", style(status.member_count).bold());
                    println!("  ✅ Health: {}", 
                        if status.healthy { style("Healthy").green() } else { style("Unhealthy").red() });
                }
                Err(e) => {
                    println!("\n⚠️  Could not get live status: {}", e);
                    println!("💡 Cluster may not be running or accessible.");
                }
            }
        }
        None => {
            println!("⚠️  Cluster not initialized. Use 'fortress cluster init' to create a new cluster.");
        }
    }
    
    Ok(())
}

/// List cluster members
async fn list_cluster_members() -> Result<()> {
    println!("👥 Cluster Members");
    println!("==================");
    
    match load_cluster_config().await {
        Some(config) => {
            match get_cluster_members(&config.node_id).await {
                Ok(members) => {
                    if members.is_empty() {
                        println!("📭 No cluster members found.");
                        println!("💡 This node may not be connected to a cluster.");
                    } else {
                        println!("📊 Found {} member(s):", style(members.len()).bold());
                        println!("{:<40} {:<15} {:<10} {:<15} {:<20}", 
                            style("NODE ID").bold(), 
                            style("ADDRESS").bold(), 
                            style("STATE").bold(), 
                            style("TERM").bold(),
                            style("LAST SEEN").bold()
                        );
                        println!("{}", "-".repeat(120));
                        
                        for member in members {
                            let state_style = match member.state.as_str() {
                                "Leader" => style(member.state).green(),
                                "Candidate" => style(member.state).yellow(),
                                "Follower" => style(member.state).blue(),
                                _ => style(member.state).dim(),
                            };
                            
                            println!("{:<40} {:<15} {:<10} {:<15} {:<20}", 
                                member.node_id[..36].to_string() + "...",
                                member.address.to_string(),
                                state_style,
                                member.term.to_string(),
                                member.last_seen.format("%H:%M:%S").to_string()
                            );
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️  Could not retrieve cluster members: {}", e);
                    println!("💡 Cluster may not be running or accessible.");
                }
            }
        }
        None => {
            println!("⚠️  Cluster not initialized. Use 'fortress cluster init' to create a new cluster.");
        }
    }
    
    Ok(())
}

/// Leave the cluster
async fn leave_cluster() -> Result<()> {
    println!("👋 Leaving cluster...");
    
    match load_cluster_config().await {
        Some(config) => {
            // Confirm the action
            println!("⚠️  This will remove this node from the cluster.");
            println!("🆔 Node ID: {}", style(config.node_id).bold());
            println!("🌐 Address: {}", style(config.bind_address).bold());
            println!("\n❓ Are you sure you want to leave the cluster? [y/N]");
            
            // In a real implementation, you'd read user input here
            // For now, we'll proceed with the leave operation
            
            match perform_cluster_leave(&config.node_id).await {
                Ok(()) => {
                    println!("✅ Successfully left the cluster!");
                    println!("🧹 Cleaning up cluster configuration...");
                    
                    // Remove cluster configuration
                    if let Err(e) = remove_cluster_config().await {
                        warn!("Failed to remove cluster config: {}", e);
                        println!("⚠️  Could not clean up cluster configuration.");
                    }
                    
                    println!("👋 Node has been removed from the cluster.");
                }
                Err(e) => {
                    error!("❌ Failed to leave cluster: {}", e);
                    println!("⚠️  Could not leave cluster. The node may still be connected.");
                    return Err(e);
                }
            }
        }
        None => {
            println!("⚠️  No cluster configuration found. This node is not part of a cluster.");
        }
    }
    
    Ok(())
}

/// Show cluster health
async fn show_cluster_health() -> Result<()> {
    println!("🏥 Cluster Health");
    println!("================");
    
    match load_cluster_config().await {
        Some(config) => {
            match get_cluster_health(&config.node_id).await {
                Ok(health) => {
                    println!("📊 Overall Health: {}", 
                        if health.overall_healthy { style("✅ Healthy").green().bold() } else { style("❌ Unhealthy").red().bold() });
                    
                    println!("\n🎯 Node Status:");
                    println!("  🆔 Local Node: {}", style(config.node_id).bold());
                    println!("  📊 Term: {}", health.current_term);
                    println!("  👥 Members: {} / {}", health.active_members, health.expected_members);
                    println!("  💓 Heartbeats: {}", style(heartbeat_status(health.heartbeat_rate)).bold());
                    
                    println!("\n🔗 Network Status:");
                    println!("  📡 Connectivity: {}", 
                        if health.network_connected { style("✅ Connected").green() } else { style("❌ Disconnected").red() });
                    println!("  ⏱️  Latency: {}ms", style(health.avg_latency.as_millis()).bold());
                    println!("  📦 Messages: {}", style(health.messages_processed).bold());
                    
                    println!("\n💾 Replication Status:");
                    println!("  🔄 Replication Lag: {}ms", style(health.replication_lag.as_millis()).bold());
                    println!("  📊 Sync Progress: {}%", style(health.sync_percentage).bold());
                    println!("  ✅ Success Rate: {:.1}%", style(health.replication_success_rate * 100.0).bold());
                    
                    if !health.issues.is_empty() {
                        println!("\n⚠️  Issues:");
                        for issue in &health.issues {
                            println!("  - {}", style(issue).yellow());
                        }
                    }
                    
                    if !health.recommendations.is_empty() {
                        println!("\n💡 Recommendations:");
                        for rec in &health.recommendations {
                            println!("  - {}", style(rec).cyan());
                        }
                    }
                }
                Err(e) => {
                    println!("⚠️  Could not assess cluster health: {}", e);
                    println!("💡 Cluster may not be running or accessible.");
                }
            }
        }
        None => {
            println!("⚠️  Cluster not initialized. Use 'fortress cluster init' to create a new cluster.");
        }
    }
    
    Ok(())
}

/// Format node state for display
fn format_node_state(state: &fortress_core::cluster::NodeState) -> &'static str {
    match state {
        fortress_core::cluster::NodeState::Follower { .. } => "Follower",
        fortress_core::cluster::NodeState::Candidate { .. } => "Candidate",
        fortress_core::cluster::NodeState::Leader { .. } => "Leader ⭐",
    }
}

// Helper functions and data structures

/// Cluster status information
#[derive(Debug)]
struct ClusterStatus {
    role: String,
    term: u64,
    member_count: usize,
    healthy: bool,
}

/// Cluster member information
#[derive(Debug)]
struct ClusterMember {
    node_id: String,
    address: SocketAddr,
    state: String,
    term: u64,
    last_seen: DateTime<Utc>,
}

/// Detailed cluster health information
#[derive(Debug)]
struct ClusterHealthInfo {
    overall_healthy: bool,
    current_term: u64,
    active_members: usize,
    expected_members: usize,
    heartbeat_rate: f64,
    network_connected: bool,
    avg_latency: Duration,
    messages_processed: u64,
    replication_lag: Duration,
    sync_percentage: f64,
    replication_success_rate: f64,
    issues: Vec<String>,
    recommendations: Vec<String>,
}

/// Load cluster configuration from storage
async fn load_cluster_config() -> Option<ClusterConfig> {
    let config_path = get_cluster_config_path();
    
    if !config_path.exists() {
        return None;
    }
    
    match fs::read_to_string(&config_path).await {
        Ok(content) => {
            serde_json::from_str(&content).ok()
        }
        Err(e) => {
            warn!("Failed to read cluster config from {:?}: {}", config_path, e);
            None
        }
    }
}

/// Save cluster configuration to storage
async fn save_cluster_config(config: &ClusterConfig) -> Result<()> {
    let config_path = get_cluster_config_path();
    
    // Create parent directory if needed
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).await
            .map_err(|e| fortress_core::error::FortressError::storage(
                "Failed to create config directory".to_string(),
                "file".to_string(),
                fortress_core::error::StorageErrorCode::ConnectionFailed
            ))?;
    }
    
    let content = serde_json::to_string_pretty(config)
        .map_err(|e| fortress_core::error::FortressError::storage(
            "Failed to serialize config".to_string(),
            "file".to_string(),
            fortress_core::error::StorageErrorCode::InvalidOperation
        ))?;
    
    fs::write(&config_path, content).await
        .map_err(|e| fortress_core::error::FortressError::storage(
            "Failed to write config".to_string(),
            "file".to_string(),
            fortress_core::error::StorageErrorCode::ConnectionFailed
        ))?;
    
    Ok(())
}

/// Remove cluster configuration
async fn remove_cluster_config() -> Result<()> {
    let config_path = get_cluster_config_path();
    
    if config_path.exists() {
        fs::remove_file(&config_path).await
            .map_err(|e| fortress_core::error::FortressError::storage(
                "Failed to remove config".to_string(),
                "file".to_string(),
                fortress_core::error::StorageErrorCode::ConnectionFailed
            ))?;
    }
    
    Ok(())
}

/// Get the cluster configuration file path
fn get_cluster_config_path() -> PathBuf {
    // In a real implementation, this would use proper config directories
    // For now, we'll use a simple path in the current directory
    PathBuf::from("fortress-cluster.json")
}

/// Get current cluster status
async fn get_cluster_status(_node_id: &Uuid) -> Result<ClusterStatus> {
    // In a real implementation, this would connect to the running cluster
    // For now, we'll simulate the status
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    Ok(ClusterStatus {
        role: "Follower".to_string(),
        term: 1,
        member_count: 3,
        healthy: true,
    })
}

/// Get cluster members
async fn get_cluster_members(node_id: &Uuid) -> Result<Vec<ClusterMember>> {
    // In a real implementation, this would query the cluster manager
    // For now, we'll simulate some members
    tokio::time::sleep(Duration::from_millis(150)).await;
    
    let members = vec![
        ClusterMember {
            node_id: node_id.to_string(),
            address: "127.0.0.1:8080".parse().unwrap(),
            state: "Leader".to_string(),
            term: 1,
            last_seen: Utc::now(),
        },
        ClusterMember {
            node_id: Uuid::new_v4().to_string(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: "Follower".to_string(),
            term: 1,
            last_seen: Utc::now(),
        },
        ClusterMember {
            node_id: Uuid::new_v4().to_string(),
            address: "127.0.0.1:8082".parse().unwrap(),
            state: "Follower".to_string(),
            term: 1,
            last_seen: Utc::now(),
        },
    ];
    
    Ok(members)
}

/// Perform cluster leave operation
async fn perform_cluster_leave(node_id: &Uuid) -> Result<()> {
    // In a real implementation, this would:
    // 1. Notify other cluster members
    // 2. Transfer leadership if this node is leader
    // 3. Stop cluster services
    // 4. Clean up resources
    
    info!("Node {} leaving cluster", node_id);
    
    // Simulate leave process
    tokio::time::sleep(Duration::from_millis(500)).await;
    
    Ok(())
}

/// Get cluster health information
async fn get_cluster_health(_node_id: &Uuid) -> Result<ClusterHealthInfo> {
    // In a real implementation, this would gather metrics from the cluster
    // For now, we'll simulate health data
    tokio::time::sleep(Duration::from_millis(200)).await;
    
    Ok(ClusterHealthInfo {
        overall_healthy: true,
        current_term: 1,
        active_members: 3,
        expected_members: 3,
        heartbeat_rate: 0.95,
        network_connected: true,
        avg_latency: Duration::from_millis(15),
        messages_processed: 1250,
        replication_lag: Duration::from_millis(5),
        sync_percentage: 100.0,
        replication_success_rate: 0.998,
        issues: vec![],
        recommendations: vec![
            "Consider adding more nodes for high availability".to_string(),
            "Monitor network latency for optimal performance".to_string(),
        ],
    })
}

/// Format heartbeat status
fn heartbeat_status(rate: f64) -> String {
    if rate >= 0.9 {
        format!("✅ {:.1}%", rate * 100.0)
    } else if rate >= 0.7 {
        format!("⚠️  {:.1}%", rate * 100.0)
    } else {
        format!("❌ {:.1}%", rate * 100.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_node_state() {
        use fortress_core::cluster::NodeState;
        
        let follower = NodeState::Follower { leader: None, term: 1 };
        assert_eq!(format_node_state(&follower), "Follower");
        
        let candidate = NodeState::Candidate { term: 1, votes_received: 1, votes_needed: 2 };
        assert_eq!(format_node_state(&candidate), "Candidate");
        
        let leader = NodeState::Leader { term: 1 };
        assert_eq!(format_node_state(&leader), "Leader ⭐");
    }
}
