//! # Cluster Management Module
//!
//! This module provides high-level cluster management capabilities,
//! including administration, monitoring, and configuration management.

use crate::cluster::ClusterResult;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};
use tokio::time::interval;
use tracing::{error, info};
use uuid::Uuid;

/// Cluster management configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagementConfig {
    /// Management API port
    pub management_port: u16,
    /// Enable cluster metrics collection
    pub enable_metrics: bool,
    /// Metrics collection interval in seconds
    pub metrics_interval_secs: u64,
    /// Enable cluster auto-scaling
    pub enable_auto_scaling: bool,
    /// Auto-scaling thresholds
    pub auto_scaling_thresholds: AutoScalingThresholds,
    /// Enable cluster rebalancing
    pub enable_rebalancing: bool,
    /// Rebalancing interval in seconds
    pub rebalancing_interval_secs: u64,
    /// Enable cluster backup
    pub enable_backup: bool,
    /// Backup interval in seconds
    pub backup_interval_secs: u64,
    /// Maximum number of backups to retain
    pub max_backups: usize,
}

impl Default for ManagementConfig {
    fn default() -> Self {
        Self {
            management_port: 8083,
            enable_metrics: true,
            metrics_interval_secs: 60,
            enable_auto_scaling: false,
            auto_scaling_thresholds: AutoScalingThresholds::default(),
            enable_rebalancing: true,
            rebalancing_interval_secs: 300, // 5 minutes
            enable_backup: true,
            backup_interval_secs: 3600, // 1 hour
            max_backups: 10,
        }
    }
}

/// Auto-scaling thresholds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutoScalingThresholds {
    /// CPU usage threshold for scaling up (percentage)
    pub cpu_threshold_up: f64,
    /// CPU usage threshold for scaling down (percentage)
    pub cpu_threshold_down: f64,
    /// Memory usage threshold for scaling up (percentage)
    pub memory_threshold_up: f64,
    /// Memory usage threshold for scaling down (percentage)
    pub memory_threshold_down: f64,
    /// Load average threshold for scaling up
    pub load_threshold_up: f64,
    /// Load average threshold for scaling down
    pub load_threshold_down: f64,
    /// Minimum number of nodes
    pub min_nodes: usize,
    /// Maximum number of nodes
    pub max_nodes: usize,
}

impl Default for AutoScalingThresholds {
    fn default() -> Self {
        Self {
            cpu_threshold_up: 80.0,
            cpu_threshold_down: 30.0,
            memory_threshold_up: 85.0,
            memory_threshold_down: 40.0,
            load_threshold_up: 2.0,
            load_threshold_down: 0.5,
            min_nodes: 3,
            max_nodes: 10,
        }
    }
}

/// Cluster state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterState {
    /// Cluster identifier
    pub cluster_id: Uuid,
    /// Cluster name
    pub cluster_name: String,
    /// Current cluster size
    pub size: usize,
    /// Cluster status
    pub status: ClusterStatus,
    /// Leader node
    pub leader: Option<Uuid>,
    /// Member nodes
    pub members: HashMap<Uuid, ClusterMember>,
    /// Cluster configuration
    pub configuration: ClusterConfiguration,
    /// Cluster metrics
    pub metrics: ClusterMetrics,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

/// Cluster status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterStatus {
    /// Cluster is forming
    Forming,
    /// Cluster is healthy
    Healthy,
    /// Cluster is degraded
    Degraded,
    /// Cluster is in maintenance mode
    Maintenance,
    /// Cluster is failed
    Failed,
    /// Cluster is rebalancing
    Rebalancing,
}

/// Cluster member information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMember {
    /// Member node ID
    pub node_id: Uuid,
    /// Member address
    pub address: String,
    /// Member port
    pub port: u16,
    /// Member role
    pub role: ClusterRole,
    /// Member status
    pub status: MemberStatus,
    /// Member capabilities
    pub capabilities: Vec<String>,
    /// Member metrics
    pub metrics: NodeMetrics,
    /// Last heartbeat
    pub last_heartbeat: chrono::DateTime<chrono::Utc>,
    /// Member metadata
    pub metadata: HashMap<String, String>,
}

/// Cluster role
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClusterRole {
    /// Leader node
    Leader,
    /// Follower node
    Follower,
    /// Backup node
    Backup,
    /// Observer node (read-only)
    Observer,
}

/// Member status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemberStatus {
    /// Member is online
    Online,
    /// Member is offline
    Offline,
    /// Member is joining
    Joining,
    /// Member is leaving
    Leaving,
    /// Member is in maintenance
    Maintenance,
}

/// Cluster configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterConfiguration {
    /// Replication factor
    pub replication_factor: usize,
    /// Consistency level
    pub consistency_level: String,
    /// Enable encryption
    pub enable_encryption: bool,
    /// Enable compression
    pub enable_compression: bool,
    /// Network configuration
    pub network_config: NetworkConfiguration,
    /// Security configuration
    pub security_config: SecurityConfiguration,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfiguration {
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    /// Election timeout in milliseconds
    pub election_timeout_ms: u64,
    /// Connection timeout in milliseconds
    pub connection_timeout_ms: u64,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Enable TLS
    pub enable_tls: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfiguration {
    /// Enable authentication
    pub enable_authentication: bool,
    /// Enable authorization
    pub enable_authorization: bool,
    /// Token expiration in seconds
    pub token_expiry_secs: u64,
    /// Enable audit logging
    pub enable_audit_logging: bool,
}

/// Cluster metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterMetrics {
    /// Total operations
    pub total_operations: u64,
    /// Operations per second
    pub operations_per_second: f64,
    /// Average latency in milliseconds
    pub average_latency_ms: f64,
    /// Error rate
    pub error_rate: f64,
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Network throughput in bytes per second
    pub network_throughput: f64,
    /// Disk usage percentage
    pub disk_usage: f64,
}

/// Node metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// CPU usage percentage
    pub cpu_usage: f64,
    /// Memory usage percentage
    pub memory_usage: f64,
    /// Disk usage percentage
    pub disk_usage: f64,
    /// Network I/O in bytes per second
    pub network_io: f64,
    /// Load average
    pub load_average: f64,
    /// Uptime in seconds
    pub uptime_secs: u64,
    /// Number of connections
    pub connections: u32,
}

/// Management message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ManagementMessage {
    /// Cluster state request
    ClusterStateRequest {
        /// ID of the requesting node
        requester_id: Uuid,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Cluster state response
    ClusterStateResponse {
        /// ID of the requesting node
        requester_id: Uuid,
        /// Current cluster state
        cluster_state: ClusterState,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Node join request
    NodeJoinRequest {
        /// Information about the joining node
        node_info: ClusterMember,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Node join response
    NodeJoinResponse {
        /// ID of the responding node
        node_id: Uuid,
        /// Whether the join was accepted
        accepted: bool,
        /// Cluster configuration (if accepted)
        cluster_config: Option<ClusterConfiguration>,
        /// Response message
        message: String,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Node leave request
    NodeLeaveRequest {
        /// ID of the leaving node
        node_id: Uuid,
        /// Reason for leaving
        reason: String,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Configuration update request
    ConfigUpdateRequest {
        /// New cluster configuration
        configuration: ClusterConfiguration,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Configuration update response
    ConfigUpdateResponse {
        /// Whether the update was successful
        success: bool,
        /// Response message
        message: String,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Metrics request
    MetricsRequest {
        /// ID of the requesting node
        requester_id: Uuid,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Metrics response
    MetricsResponse {
        /// ID of the requesting node
        requester_id: Uuid,
        /// Cluster metrics
        metrics: ClusterMetrics,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Rebalance request
    RebalanceRequest {
        /// Reason for rebalancing
        reason: String,
        /// When the request was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },

    /// Rebalance response
    RebalanceResponse {
        /// Whether rebalancing was successful
        success: bool,
        /// Response message
        message: String,
        /// When the response was sent
        timestamp: chrono::DateTime<chrono::Utc>,
    },
}

/// Management-specific errors
#[derive(Debug, thiserror::Error)]
pub enum ManagementError {
    /// Cluster not found
    #[error("Cluster not found")]
    ClusterNotFound,

    /// Node not found in cluster
    #[error("Node not found: {0}")]
    NodeNotFound(Uuid),

    /// Invalid cluster configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Operation not allowed in current state
    #[error("Operation not allowed: {0}")]
    OperationNotAllowed(String),

    /// Cluster is not ready for operation
    #[error("Cluster is not ready")]
    ClusterNotReady,

    /// Rebalancing operation failed
    #[error("Rebalancing failed: {0}")]
    RebalancingFailed(String),

    /// Auto-scaling operation failed
    #[error("Auto-scaling failed: {0}")]
    AutoScalingFailed(String),

    /// Backup operation failed
    #[error("Backup failed: {0}")]
    BackupFailed(String),

    /// Management operation timed out
    #[error("Management timeout")]
    ManagementTimeout,
}

/// Cluster manager
pub struct ClusterManager {
    /// This node's ID
    node_id: Uuid,
    /// Configuration
    config: ManagementConfig,
    /// Cluster state
    cluster_state: Arc<RwLock<ClusterState>>,
    /// Management callbacks
    callbacks: Arc<Mutex<Vec<Box<dyn ManagementCallback + Send + Sync>>>>,
    /// Network sender
    network_sender: Arc<Mutex<dyn ManagementNetworkSender + Send + Sync>>,
    /// Metrics collector
    metrics_collector: Arc<Mutex<dyn MetricsCollector + Send + Sync>>,
}

/// Callback trait for management events
#[async_trait::async_trait]
pub trait ManagementCallback {
    /// Called when a new node joins the cluster
    async fn on_node_joined(&self, node_info: &ClusterMember);

    /// Called when a node leaves the cluster
    async fn on_node_left(&self, node_id: Uuid, reason: &str);

    /// Called when cluster configuration is updated
    async fn on_configuration_updated(
        &self,
        old_config: &ClusterConfiguration,
        new_config: &ClusterConfiguration,
    );

    /// Called when rebalancing starts
    async fn on_rebalancing_started(&self, reason: &str);

    /// Called when rebalancing completes
    async fn on_rebalancing_completed(&self, success: bool, message: &str);

    /// Called when auto-scaling is triggered
    async fn on_auto_scaling_triggered(&self, action: &str, reason: &str);
}

/// Trait for network management operations
#[async_trait::async_trait]
pub trait ManagementNetworkSender {
    /// Send a management message to a specific node
    async fn send_management_message(
        &self,
        target: Uuid,
        message: ManagementMessage,
    ) -> ClusterResult<()>;

    /// Broadcast a management message to all nodes
    async fn broadcast_management_message(&self, message: ManagementMessage) -> ClusterResult<()>;
}

/// Trait for metrics collection
#[async_trait::async_trait]
pub trait MetricsCollector {
    /// Collect metrics for the entire cluster
    async fn collect_cluster_metrics(&self) -> ClusterResult<ClusterMetrics>;

    /// Collect metrics for a specific node
    async fn collect_node_metrics(&self, node_id: Uuid) -> ClusterResult<NodeMetrics>;

    /// Get historical metrics for a time period
    async fn get_historical_metrics(
        &self,
        duration: Duration,
    ) -> ClusterResult<Vec<ClusterMetrics>>;
}

impl ClusterManager {
    /// Create a new cluster manager
    pub fn new(
        node_id: Uuid,
        config: ManagementConfig,
        network_sender: Arc<Mutex<dyn ManagementNetworkSender + Send + Sync>>,
        metrics_collector: Arc<Mutex<dyn MetricsCollector + Send + Sync>>,
    ) -> Self {
        let cluster_state = ClusterState {
            cluster_id: Uuid::new_v4(),
            cluster_name: "fortress-cluster".to_string(),
            size: 1,
            status: ClusterStatus::Forming,
            leader: Some(node_id),
            members: HashMap::new(),
            configuration: ClusterConfiguration::default(),
            metrics: ClusterMetrics::default(),
            last_updated: chrono::Utc::now(),
        };

        Self {
            node_id,
            config,
            cluster_state: Arc::new(RwLock::new(cluster_state)),
            callbacks: Arc::new(Mutex::new(Vec::new())),
            network_sender,
            metrics_collector,
        }
    }

    /// Start the cluster manager
    pub async fn start(&self) -> ClusterResult<()> {
        info!("Starting cluster manager for node {}", self.node_id);

        // Start metrics collection loop
        if self.config.enable_metrics {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.metrics_collection_loop().await;
            });
        }

        // Start auto-scaling loop
        if self.config.enable_auto_scaling {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.auto_scaling_loop().await;
            });
        }

        // Start rebalancing loop
        if self.config.enable_rebalancing {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.rebalancing_loop().await;
            });
        }

        // Start backup loop
        if self.config.enable_backup {
            let manager = self.clone();
            tokio::spawn(async move {
                manager.backup_loop().await;
            });
        }

        Ok(())
    }

    /// Metrics collection loop
    async fn metrics_collection_loop(&self) {
        let mut interval = interval(Duration::from_secs(self.config.metrics_interval_secs));

        loop {
            interval.tick().await;

            if let Err(e) = self.collect_metrics().await {
                error!("Metrics collection failed: {}", e);
            }
        }
    }

    /// Auto-scaling loop
    async fn auto_scaling_loop(&self) {
        let mut interval = interval(Duration::from_secs(300)); // Check every 5 minutes

        loop {
            interval.tick().await;

            if let Err(e) = self.check_auto_scaling().await {
                error!("Auto-scaling check failed: {}", e);
            }
        }
    }

    /// Rebalancing loop
    async fn rebalancing_loop(&self) {
        let mut interval = interval(Duration::from_secs(self.config.rebalancing_interval_secs));

        loop {
            interval.tick().await;

            if let Err(e) = self.check_rebalancing().await {
                error!("Rebalancing check failed: {}", e);
            }
        }
    }

    /// Backup loop
    async fn backup_loop(&self) {
        let mut interval = interval(Duration::from_secs(self.config.backup_interval_secs));

        loop {
            interval.tick().await;

            if let Err(e) = self.perform_backup().await {
                error!("Backup failed: {}", e);
            }
        }
    }

    /// Collect cluster metrics
    async fn collect_metrics(&self) -> ClusterResult<()> {
        let metrics_collector = self.metrics_collector.lock().await;
        let metrics = metrics_collector.collect_cluster_metrics().await?;
        drop(metrics_collector);

        // Update cluster state with new metrics
        {
            let mut state = self.cluster_state.write().await;
            state.metrics = metrics;
            state.last_updated = chrono::Utc::now();
        }

        Ok(())
    }

    /// Check auto-scaling conditions
    async fn check_auto_scaling(&self) -> ClusterResult<()> {
        let state = self.cluster_state.read().await;
        let metrics = &state.metrics;
        let thresholds = &self.config.auto_scaling_thresholds;
        let current_size = state.size;

        // Check if we need to scale up
        if metrics.cpu_usage > thresholds.cpu_threshold_up
            || metrics.memory_usage > thresholds.memory_threshold_up
            || metrics.error_rate > 10.0
        {
            // High error rate
            if current_size < thresholds.max_nodes {
                self.trigger_auto_scaling("scale_up", "High resource usage")
                    .await?;
            }
        }

        // Check if we need to scale down
        if metrics.cpu_usage < thresholds.cpu_threshold_down
            && metrics.memory_usage < thresholds.memory_threshold_down
            && metrics.error_rate < 1.0
        {
            // Low error rate
            if current_size > thresholds.min_nodes {
                self.trigger_auto_scaling("scale_down", "Low resource usage")
                    .await?;
            }
        }

        Ok(())
    }

    /// Trigger auto-scaling action
    async fn trigger_auto_scaling(&self, action: &str, reason: &str) -> ClusterResult<()> {
        info!("Triggering auto-scaling: {} - {}", action, reason);

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback.on_auto_scaling_triggered(action, reason).await;
        }

        // In a real implementation, this would interact with cloud provider APIs
        // or container orchestration systems to add/remove nodes

        Ok(())
    }

    /// Check if rebalancing is needed
    async fn check_rebalancing(&self) -> ClusterResult<()> {
        let state = self.cluster_state.read().await;

        // Check if cluster is imbalanced
        let members: Vec<&ClusterMember> = state.members.values().collect();
        let mut cpu_usage_sum = 0.0;
        let mut memory_usage_sum = 0.0;

        for member in &members {
            cpu_usage_sum += member.metrics.cpu_usage;
            memory_usage_sum += member.metrics.memory_usage;
        }

        if !members.is_empty() {
            let avg_cpu = cpu_usage_sum / members.len() as f64;
            let avg_memory = memory_usage_sum / members.len() as f64;

            // Check if any node is significantly above or below average
            for member in &members {
                let cpu_diff = (member.metrics.cpu_usage - avg_cpu).abs();
                let memory_diff = (member.metrics.memory_usage - avg_memory).abs();

                if cpu_diff > 20.0 || memory_diff > 20.0 {
                    // Trigger rebalancing
                    drop(state);
                    self.trigger_rebalancing("Resource imbalance detected")
                        .await?;
                    break;
                }
            }
        }

        Ok(())
    }

    /// Trigger rebalancing
    async fn trigger_rebalancing(&self, reason: &str) -> ClusterResult<()> {
        info!("Triggering rebalancing: {}", reason);

        // Update cluster status
        {
            let mut state = self.cluster_state.write().await;
            state.status = ClusterStatus::Rebalancing;
            state.last_updated = chrono::Utc::now();
        }

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback.on_rebalancing_started(reason).await;
        }

        // In a real implementation, this would move data between nodes
        // to achieve better balance

        // Simulate rebalancing completion
        tokio::time::sleep(Duration::from_secs(30)).await;

        // Update cluster status back to healthy
        {
            let mut state = self.cluster_state.write().await;
            state.status = ClusterStatus::Healthy;
            state.last_updated = chrono::Utc::now();
        }

        // Notify callbacks of completion
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            let _ = callback.on_rebalancing_completed(true, "Rebalancing completed successfully");
        }

        Ok(())
    }

    /// Perform cluster backup
    async fn perform_backup(&self) -> ClusterResult<()> {
        info!("Performing cluster backup");

        // In a real implementation, this would create a consistent snapshot
        // of the cluster state and data

        Ok(())
    }

    /// Handle incoming management message
    pub async fn handle_message(
        &self,
        _source: Uuid,
        message: ManagementMessage,
    ) -> ClusterResult<Option<ManagementMessage>> {
        match message {
            ManagementMessage::ClusterStateRequest {
                requester_id,
                timestamp,
            } => {
                self.handle_cluster_state_request(requester_id, timestamp)
                    .await
            }
            ManagementMessage::NodeJoinRequest {
                node_info,
                timestamp,
            } => self.handle_node_join_request(node_info, timestamp).await,
            ManagementMessage::NodeLeaveRequest {
                node_id,
                reason,
                timestamp,
            } => {
                self.handle_node_leave_request(node_id, reason, timestamp)
                    .await?;
                Ok(None)
            }
            ManagementMessage::ConfigUpdateRequest {
                configuration,
                timestamp,
            } => {
                self.handle_config_update_request(configuration, timestamp)
                    .await
            }
            ManagementMessage::MetricsRequest {
                requester_id,
                timestamp,
            } => self.handle_metrics_request(requester_id, timestamp).await,
            ManagementMessage::RebalanceRequest { reason, timestamp } => {
                self.handle_rebalance_request(reason, timestamp).await
            }
            _ => {
                // Handle other message types
                Ok(None)
            }
        }
    }

    /// Handle cluster state request
    async fn handle_cluster_state_request(
        &self,
        requester_id: Uuid,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ManagementMessage>> {
        let state = self.cluster_state.read().await;

        let response = ManagementMessage::ClusterStateResponse {
            requester_id,
            cluster_state: state.clone(),
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(response))
    }

    /// Handle node join request
    async fn handle_node_join_request(
        &self,
        node_info: ClusterMember,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ManagementMessage>> {
        info!("Handling node join request from {}", node_info.node_id);

        let cluster_config = {
            let mut state = self.cluster_state.write().await;

            // Check if node can join
            let accepted = state.members.len() < self.config.auto_scaling_thresholds.max_nodes;

            if accepted {
                // Add node to cluster
                state.members.insert(node_info.node_id, node_info.clone());
                state.size = state.members.len();
                state.last_updated = chrono::Utc::now();

                // Update cluster status
                if state.status == ClusterStatus::Forming {
                    state.status = ClusterStatus::Healthy;
                }
            }

            if accepted {
                Some(state.configuration.clone())
            } else {
                None
            }
        };

        // Notify callbacks if accepted
        if cluster_config.is_some() {
            let callbacks = self.callbacks.lock().await;
            for callback in callbacks.iter() {
                callback.on_node_joined(&node_info).await;
            }
        }

        let response = ManagementMessage::NodeJoinResponse {
            node_id: node_info.node_id,
            accepted: cluster_config.is_some(),
            cluster_config: cluster_config.clone(),
            message: if cluster_config.is_some() {
                "Node accepted".to_string()
            } else {
                "Cluster full".to_string()
            },
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(response))
    }

    /// Handle node leave request
    async fn handle_node_leave_request(
        &self,
        node_id: Uuid,
        reason: String,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<()> {
        info!("Handling node leave request from {}: {}", node_id, reason);

        let mut state = self.cluster_state.write().await;

        if state.members.remove(&node_id).is_some() {
            state.size = state.members.len();
            state.last_updated = chrono::Utc::now();

            // Update cluster status if needed
            if state.members.is_empty() {
                state.status = ClusterStatus::Failed;
            } else if state.size < 3 {
                state.status = ClusterStatus::Degraded;
            }
        }

        drop(state);

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback.on_node_left(node_id, &reason).await;
        }

        Ok(())
    }

    /// Handle configuration update request
    async fn handle_config_update_request(
        &self,
        configuration: ClusterConfiguration,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ManagementMessage>> {
        info!("Handling configuration update request");

        let mut state = self.cluster_state.write().await;
        let old_config = state.configuration.clone();
        state.configuration = configuration.clone();
        state.last_updated = chrono::Utc::now();
        drop(state);

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback
                .on_configuration_updated(&old_config, &configuration)
                .await;
        }

        let response = ManagementMessage::ConfigUpdateResponse {
            success: true,
            message: "Configuration updated successfully".to_string(),
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(response))
    }

    /// Handle metrics request
    async fn handle_metrics_request(
        &self,
        requester_id: Uuid,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ManagementMessage>> {
        let state = self.cluster_state.read().await;
        let metrics = state.metrics.clone();
        drop(state);

        let response = ManagementMessage::MetricsResponse {
            requester_id,
            metrics,
            timestamp: chrono::Utc::now(),
        };

        Ok(Some(response))
    }

    /// Handle rebalance request
    async fn handle_rebalance_request(
        &self,
        reason: String,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> ClusterResult<Option<ManagementMessage>> {
        info!("Handling rebalance request: {}", reason);

        match self.trigger_rebalancing(&reason).await {
            Ok(()) => {
                let response = ManagementMessage::RebalanceResponse {
                    success: true,
                    message: "Rebalancing initiated".to_string(),
                    timestamp: chrono::Utc::now(),
                };
                Ok(Some(response))
            }
            Err(e) => {
                let response = ManagementMessage::RebalanceResponse {
                    success: false,
                    message: format!("Rebalancing failed: {}", e),
                    timestamp: chrono::Utc::now(),
                };
                Ok(Some(response))
            }
        }
    }

    /// Get cluster state
    pub async fn get_cluster_state(&self) -> ClusterState {
        self.cluster_state.read().await.clone()
    }

    /// Add management callback
    pub async fn add_callback(&self, callback: Box<dyn ManagementCallback + Send + Sync>) {
        let mut callbacks = self.callbacks.lock().await;
        callbacks.push(callback);
    }

    /// Update cluster configuration
    pub async fn update_configuration(
        &self,
        configuration: ClusterConfiguration,
    ) -> ClusterResult<()> {
        let mut state = self.cluster_state.write().await;
        let old_config = state.configuration.clone();
        state.configuration = configuration.clone();
        state.last_updated = chrono::Utc::now();
        drop(state);

        // Notify callbacks
        let callbacks = self.callbacks.lock().await;
        for callback in callbacks.iter() {
            callback
                .on_configuration_updated(&old_config, &configuration)
                .await;
        }

        Ok(())
    }
}

impl Default for ClusterConfiguration {
    fn default() -> Self {
        Self {
            replication_factor: 3,
            consistency_level: "quorum".to_string(),
            enable_encryption: true,
            enable_compression: true,
            network_config: NetworkConfiguration::default(),
            security_config: SecurityConfiguration::default(),
        }
    }
}

impl Default for NetworkConfiguration {
    fn default() -> Self {
        Self {
            heartbeat_interval_ms: 1000,
            election_timeout_ms: 5000,
            connection_timeout_ms: 30000,
            max_message_size: 1048576, // 1MB
            enable_tls: false,
        }
    }
}

impl Default for SecurityConfiguration {
    fn default() -> Self {
        Self {
            enable_authentication: true,
            enable_authorization: true,
            token_expiry_secs: 3600,
            enable_audit_logging: true,
        }
    }
}

impl Default for ClusterMetrics {
    fn default() -> Self {
        Self {
            total_operations: 0,
            operations_per_second: 0.0,
            average_latency_ms: 0.0,
            error_rate: 0.0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
            network_throughput: 0.0,
            disk_usage: 0.0,
        }
    }
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            network_io: 0.0,
            load_average: 0.0,
            uptime_secs: 0,
            connections: 0,
        }
    }
}

impl Clone for ClusterManager {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            config: self.config.clone(),
            cluster_state: Arc::clone(&self.cluster_state),
            callbacks: Arc::clone(&self.callbacks),
            network_sender: Arc::clone(&self.network_sender),
            metrics_collector: Arc::clone(&self.metrics_collector),
        }
    }
}
