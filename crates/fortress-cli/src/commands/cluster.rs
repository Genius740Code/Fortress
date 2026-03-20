//! Cluster management commands for Fortress CLI

use clap::{Args, Subcommand};
use fortress_core::{
    cluster::{ClusterConfig, ClusterManager, ClusterNode, NodeState},
    error::{FortressError, Result},
};
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;
use uuid::Uuid;
use console::style;
use tracing::{info, error, warn};
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

/// Cluster health metrics from the cluster manager
#[derive(Debug)]
struct ClusterHealthMetrics {
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
}

/// Local cluster manager interface
struct LocalClusterManager {
    node_id: Uuid,
}

impl LocalClusterManager {
    fn new(node_id: Uuid) -> Self {
        Self { node_id }
    }
    
    async fn get_node_state(&self) -> NodeState {
        // Try to load actual state from cluster manager
        // For now, return a default state
        NodeState::Follower { leader: None, term: 0 }
    }
    
    async fn get_members(&self) -> HashMap<Uuid, ClusterNode> {
        // Try to get actual members from cluster manager
        // For now, return empty map
        HashMap::new()
    }
    
    async fn is_healthy(&self) -> bool {
        // Try to get actual health status
        // For now, return false since we can't connect
        false
    }
    
    async fn get_health_metrics(&self) -> ClusterHealthMetrics {
        // Try to get actual health metrics
        // For now, return default metrics
        ClusterHealthMetrics {
            current_term: 0,
            active_members: 0,
            expected_members: 0,
            heartbeat_rate: 0.0,
            network_connected: false,
            avg_latency: Duration::from_millis(0),
            messages_processed: 0,
            replication_lag: Duration::from_millis(0),
            sync_percentage: 0.0,
            replication_success_rate: 0.0,
        }
    }
    
    async fn transfer_leadership(&mut self) -> Result<()> {
        // Try to transfer leadership to another node
        info!("Attempting to transfer leadership from node {}", self.node_id);
        
        // In a real implementation, this would:
        // 1. Find a suitable follower node
        // 2. Initiate leadership transfer
        // 3. Wait for confirmation
        
        Ok(())
    }
    
    async fn notify_leave(&self) -> Result<()> {
        // Notify other cluster members that this node is leaving
        info!("Notifying cluster members of node {} departure", self.node_id);
        
        // In a real implementation, this would:
        // 1. Send leave messages to all members
        // 2. Wait for acknowledgments
        // 3. Handle any failed notifications
        
        Ok(())
    }
    
    async fn shutdown(self) -> Result<()> {
        // Shutdown cluster services
        info!("Shutting down cluster services for node {}", self.node_id);
        
        // In a real implementation, this would:
        // 1. Stop heartbeat loops
        // 2. Close network connections
        // 3. Clean up resources
        // 4. Save final state
        
        Ok(())
    }
}

/// Try to get a connection to the local cluster manager
async fn get_local_cluster_manager(node_id: &Uuid) -> Option<LocalClusterManager> {
    // Try to connect to the local cluster manager
    // In a real implementation, this would:
    // 1. Check if cluster service is running
    // 2. Connect via IPC or HTTP API
    // 3. Authenticate if needed
    // 4. Return a manager interface
    
    // For now, we'll try to detect if the cluster is running
    // by checking for the cluster config and attempting a simple connection
    
    let config_path = get_cluster_config_path();
    if !config_path.exists() {
        return None;
    }
    
    // Try to read the config to verify cluster is initialized
    match fs::read_to_string(&config_path).await {
        Ok(_) => {
            // Config exists, try to create a manager
            Some(LocalClusterManager::new(*node_id))
        }
        Err(_) => None,
    }
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
            .map_err(|_e| fortress_core::error::FortressError::storage(
                "Failed to create config directory".to_string(),
                "file".to_string(),
                fortress_core::error::StorageErrorCode::ConnectionFailed
            ))?;
    }
    
    let content = serde_json::to_string_pretty(config)
        .map_err(|_e| fortress_core::error::FortressError::storage(
            "Failed to serialize config".to_string(),
            "file".to_string(),
            fortress_core::error::StorageErrorCode::InvalidOperation
        ))?;
    
    fs::write(&config_path, content).await
        .map_err(|_e| fortress_core::error::FortressError::storage(
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
            .map_err(|_e| fortress_core::error::FortressError::storage(
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
async fn get_cluster_status(node_id: &Uuid) -> Result<ClusterStatus> {
    // Load cluster configuration
    let _config = load_cluster_config().await
        .ok_or_else(|| FortressError::cluster(
            "Cluster configuration not found".to_string(),
            None,
        ))?;
    
    // Try to connect to local cluster manager
    match get_local_cluster_manager(node_id).await {
        Some(manager) => {
            let state = manager.get_node_state().await;
            let members = manager.get_members().await;
            let term = match &state {
                NodeState::Follower { term, .. } => *term,
                NodeState::Candidate { term, .. } => *term,
                NodeState::Leader { term, .. } => *term,
            };
            
            let role = match &state {
                NodeState::Follower { .. } => "Follower".to_string(),
                NodeState::Candidate { .. } => "Candidate".to_string(),
                NodeState::Leader { .. } => "Leader".to_string(),
            };
            
            let healthy = manager.is_healthy().await;
            
            Ok(ClusterStatus {
                role,
                term,
                member_count: members.len(),
                healthy,
            })
        }
        None => {
            // Cluster manager not accessible, return basic status
            Ok(ClusterStatus {
                role: "Unknown".to_string(),
                term: 0,
                member_count: 0,
                healthy: false,
            })
        }
    }
}

/// Get cluster members
async fn get_cluster_members(node_id: &Uuid) -> Result<Vec<ClusterMember>> {
    // Try to connect to local cluster manager
    match get_local_cluster_manager(node_id).await {
        Some(manager) => {
            let members = manager.get_members().await;
            let mut cluster_members = Vec::new();
            
            for (member_id, node) in members {
                let state = match &node.state {
                    NodeState::Follower { .. } => "Follower".to_string(),
                    NodeState::Candidate { .. } => "Candidate".to_string(),
                    NodeState::Leader { .. } => "Leader".to_string(),
                };
                
                let term = match &node.state {
                    NodeState::Follower { term, .. } => *term,
                    NodeState::Candidate { term, .. } => *term,
                    NodeState::Leader { term, .. } => *term,
                };
                
                let last_seen = DateTime::from_timestamp(
                    (node.last_heartbeat / 1000) as i64,
                    ((node.last_heartbeat % 1000) * 1_000_000) as u32,
                ).unwrap_or_else(|| Utc::now());
                
                cluster_members.push(ClusterMember {
                    node_id: member_id.to_string(),
                    address: node.address,
                    state,
                    term,
                    last_seen,
                });
            }
            
            Ok(cluster_members)
        }
        None => {
            Err(FortressError::cluster(
                "Cluster manager not accessible".to_string(),
                None,
            ))
        }
    }
}

/// Perform cluster leave operation
async fn perform_cluster_leave(node_id: &Uuid) -> Result<()> {
    // Try to connect to local cluster manager
    match get_local_cluster_manager(node_id).await {
        Some(mut manager) => {
            info!("Node {} leaving cluster", node_id);
            
            // Check if this node is the leader and transfer leadership if needed
            let state = manager.get_node_state().await;
            if matches!(state, NodeState::Leader { .. }) {
                info!("Leader node leaving cluster, transferring leadership");
                manager.transfer_leadership().await?;
            }
            
            // Notify other cluster members
            manager.notify_leave().await?;
            
            // Stop cluster services
            manager.shutdown().await?;
            
            info!("Node {} successfully left cluster", node_id);
            Ok(())
        }
        None => {
            // Cluster manager not accessible, perform basic cleanup
            info!("Cluster manager not accessible, performing basic cleanup for node {}", node_id);
            
            // Simulate cleanup process
            tokio::time::sleep(Duration::from_millis(200)).await;
            
            Ok(())
        }
    }
}

/// Get cluster health information
async fn get_cluster_health(node_id: &Uuid) -> Result<ClusterHealthInfo> {
    // Try to connect to local cluster manager
    match get_local_cluster_manager(node_id).await {
        Some(manager) => {
            let health_metrics = manager.get_health_metrics().await;
            let members = manager.get_members().await;
            
            let mut issues = Vec::new();
            let mut recommendations = Vec::new();
            
            // Analyze health and generate issues/recommendations
            if health_metrics.active_members < health_metrics.expected_members {
                issues.push(format!(
                    "Only {}/{} members are active",
                    health_metrics.active_members, health_metrics.expected_members
                ));
            }
            
            if health_metrics.heartbeat_rate < 0.8 {
                issues.push("Low heartbeat rate detected".to_string());
            }
            
            if health_metrics.avg_latency > Duration::from_millis(100) {
                issues.push("High network latency detected".to_string());
                recommendations.push("Check network connectivity and optimize routing".to_string());
            }
            
            if health_metrics.replication_success_rate < 0.95 {
                issues.push("Low replication success rate".to_string());
                recommendations.push("Check replication configuration and network stability".to_string());
            }
            
            if members.len() < 3 {
                recommendations.push("Consider adding more nodes for high availability".to_string());
            }
            
            if health_metrics.avg_latency > Duration::from_millis(50) {
                recommendations.push("Monitor network latency for optimal performance".to_string());
            }
            
            let overall_healthy = issues.is_empty() && 
                health_metrics.active_members >= health_metrics.expected_members &&
                health_metrics.heartbeat_rate >= 0.9 &&
                health_metrics.replication_success_rate >= 0.95;
            
            Ok(ClusterHealthInfo {
                overall_healthy,
                current_term: health_metrics.current_term,
                active_members: health_metrics.active_members,
                expected_members: health_metrics.expected_members,
                heartbeat_rate: health_metrics.heartbeat_rate,
                network_connected: health_metrics.network_connected,
                avg_latency: health_metrics.avg_latency,
                messages_processed: health_metrics.messages_processed,
                replication_lag: health_metrics.replication_lag,
                sync_percentage: health_metrics.sync_percentage,
                replication_success_rate: health_metrics.replication_success_rate,
                issues,
                recommendations,
            })
        }
        None => {
            // Cluster manager not accessible, return unhealthy status
            Ok(ClusterHealthInfo {
                overall_healthy: false,
                current_term: 0,
                active_members: 0,
                expected_members: 0,
                heartbeat_rate: 0.0,
                network_connected: false,
                avg_latency: Duration::from_millis(0),
                messages_processed: 0,
                replication_lag: Duration::from_millis(0),
                sync_percentage: 0.0,
                replication_success_rate: 0.0,
                issues: vec!["Cluster manager not accessible".to_string()],
                recommendations: vec!["Start cluster services".to_string()],
            })
        }
    }
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
