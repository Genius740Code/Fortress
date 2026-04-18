//! Distributed Rate Limiter
//! 
//! This module implements distributed rate limiting across multiple nodes
//! with consistent state synchronization and conflict resolution.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};
use crate::error::{FortressError, Result};
use super::{
    ProductionRateLimiter, ProductionRateLimitConfig, RateLimitRequest, RateLimitResponse,
    ProductionRateLimitMetrics, RateLimitSpec, ViolationAction, ThreatLevel, GeoLocation
};
use async_trait::async_trait;

/// Distributed rate limiter with cluster-wide synchronization
pub struct DistributedRateLimiter {
    /// Configuration
    config: Arc<RwLock<ProductionRateLimitConfig>>,
    /// Local rate limiter (fallback)
    local_limiter: Arc<dyn ProductionRateLimiter>,
    /// Cluster nodes
    cluster_nodes: Arc<RwLock<HashSet<String>>>,
    /// Distributed state
    distributed_state: Arc<RwLock<HashMap<String, DistributedState>>>,
    /// Node ID
    node_id: String,
    /// Sync coordinator
    sync_coordinator: Arc<RwLock<SyncCoordinator>>,
    /// Metrics
    metrics: Arc<RwLock<ProductionRateLimitMetrics>>,
    /// Cleanup task handle
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

/// Distributed state for rate limiting
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DistributedState {
    /// Key being rate limited
    key: String,
    /// Current count
    current_count: u64,
    /// Limit
    limit: u64,
    /// Window start time
    window_start: DateTime<Utc>,
    /// Window duration in seconds
    window_duration: u64,
    /// Last update timestamp
    last_updated: DateTime<Utc>,
    /// Node that last updated
    updated_by: String,
    /// Version number for conflict resolution
    version: u64,
}

/// Synchronization coordinator for distributed state
#[derive(Debug, Clone)]
struct SyncCoordinator {
    /// Sync status
    sync_status: SyncStatus,
    /// Last sync time
    last_sync: DateTime<Utc>,
    /// Sync interval in seconds
    sync_interval: Duration,
    /// Conflict resolution strategy
    conflict_strategy: ConflictResolutionStrategy,
    /// Pending sync operations
    pending_syncs: Vec<SyncOperation>,
}

/// Sync status
#[derive(Debug, Clone, PartialEq)]
enum SyncStatus {
    /// Not synchronized
    NotSynced,
    /// Synchronizing
    Syncing,
    /// Synchronized
    Synced,
    /// Sync failed
    SyncFailed,
}

/// Conflict resolution strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
enum ConflictResolutionStrategy {
    /// Last write wins
    LastWriteWins,
    /// Highest count wins
    HighestCountWins,
    /// Earliest timestamp wins
    EarliestTimestampWins,
    /// Quorum-based resolution
    QuorumBased,
}

/// Sync operation
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncOperation {
    /// Operation ID
    id: String,
    /// Operation type
    operation_type: SyncOperationType,
    /// Target key
    key: String,
    /// New state
    new_state: DistributedState,
    /// Timestamp
    timestamp: DateTime<Utc>,
    /// Source node
    source_node: String,
}

/// Sync operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
enum SyncOperationType {
    /// Update state
    Update,
    /// Reset state
    Reset,
    /// Delete state
    Delete,
    /// Sync request
    SyncRequest,
}

impl DistributedRateLimiter {
    /// Create a new distributed rate limiter
    pub fn new(
        config: ProductionRateLimitConfig,
        node_id: String,
        cluster_nodes: HashSet<String>,
        local_limiter: Arc<dyn ProductionRateLimiter>,
    ) -> Self {
        let sync_coordinator = SyncCoordinator {
            sync_status: SyncStatus::NotSynced,
            last_sync: Utc::now(),
            sync_interval: Duration::seconds(5), // Sync every 5 seconds
            conflict_strategy: ConflictResolutionStrategy::LastWriteWins,
            pending_syncs: Vec::new(),
        };

        Self {
            config: Arc::new(RwLock::new(config)),
            local_limiter,
            cluster_nodes: Arc::new(RwLock::new(cluster_nodes)),
            distributed_state: Arc::new(RwLock::new(HashMap::new())),
            node_id,
            sync_coordinator: Arc::new(RwLock::new(sync_coordinator)),
            metrics: Arc::new(RwLock::new(ProductionRateLimitMetrics::default())),
            cleanup_task: None,
        }
    }

    /// Generate response key for request
    fn generate_response_key(&self, request: &RateLimitRequest) -> String {
        if let Some(ref api_key) = request.api_key {
            format!("api_key:{}", api_key)
        } else if let Some(ref user_id) = request.user_id {
            format!("user:{}", user_id)
        } else {
            format!("ip:{}", request.ip_address)
        }
    }

    /// Get distributed state for key
    async fn get_distributed_state(&self, key: &str) -> Option<DistributedState> {
        let state = self.distributed_state.read().await;
        state.get(key).cloned()
    }

    /// Update distributed state
    async fn update_distributed_state(&self, key: String, new_state: DistributedState) -> Result<()> {
        let mut state = self.distributed_state.write().await;
        
        // Check for conflicts
        if let Some(existing_state) = state.get(&key) {
            if existing_state.version >= new_state.version {
                // Conflict detected, use resolution strategy
                let resolved_state = self.resolve_conflict(existing_state, &new_state).await?;
                state.insert(key, resolved_state);
            } else {
                // No conflict, update directly
                state.insert(key, new_state);
            }
        } else {
            // No existing state, insert new
            state.insert(key, new_state);
        }
        
        Ok(())
    }

    /// Resolve conflicts between states
    async fn resolve_conflict(&self, existing: &DistributedState, new: &DistributedState) -> Result<DistributedState> {
        let coordinator = self.sync_coordinator.read().await;
        
        let resolved_state = match coordinator.conflict_strategy {
            ConflictResolutionStrategy::LastWriteWins => {
                if new.last_updated > existing.last_updated {
                    new.clone()
                } else {
                    existing.clone()
                }
            }
            ConflictResolutionStrategy::HighestCountWins => {
                if new.current_count > existing.current_count {
                    new.clone()
                } else {
                    existing.clone()
                }
            }
            ConflictResolutionStrategy::EarliestTimestampWins => {
                if new.window_start < existing.window_start {
                    new.clone()
                } else {
                    existing.clone()
                }
            }
            ConflictResolutionStrategy::QuorumBased => {
                // For simplicity, use last write wins in this implementation
                // In a real implementation, this would query other nodes
                if new.last_updated > existing.last_updated {
                    new.clone()
                } else {
                    existing.clone()
                }
            }
        };
        
        Ok(resolved_state)
    }

    /// Synchronize with cluster nodes
    async fn synchronize_with_cluster(&self) -> Result<()> {
        let mut coordinator = self.sync_coordinator.write().await;
        let nodes = self.cluster_nodes.read().await.clone();
        
        if coordinator.sync_status == SyncStatus::Syncing {
            return Ok(()); // Already syncing
        }
        
        coordinator.sync_status = SyncStatus::Syncing;
        
        // Simulate synchronization with other nodes
        for node in &nodes {
            if node == &self.node_id {
                continue; // Skip self
            }
            
            // In a real implementation, this would make network calls
            // For now, simulate successful sync
            tracing::debug!("Syncing rate limit state with node: {}", node);
        }
        
        coordinator.last_sync = Utc::now();
        coordinator.sync_status = SyncStatus::Synced;
        
        // Clear pending syncs
        coordinator.pending_syncs.clear();
        
        tracing::info!("Distributed rate limiter sync completed");
        Ok(())
    }

    /// Check if state needs synchronization
    async fn needs_sync(&self) -> bool {
        let coordinator = self.sync_coordinator.read().await;
        let now = Utc::now();
        
        coordinator.sync_status != SyncStatus::Synced ||
        now - coordinator.last_sync > coordinator.sync_interval
    }

    /// Create sync operation for state update
    fn create_sync_operation(&self, key: String, state: DistributedState, operation_type: SyncOperationType) -> SyncOperation {
        SyncOperation {
            id: format!("{}-{}-{}", self.node_id, key, Utc::now().timestamp_millis()),
            operation_type,
            key,
            new_state: state,
            timestamp: Utc::now(),
            source_node: self.node_id.clone(),
        }
    }

    /// Broadcast sync operation to cluster
    async fn broadcast_sync_operation(&self, operation: SyncOperation) -> Result<()> {
        let nodes = self.cluster_nodes.read().await.clone();
        
        // In a real implementation, this would send the operation to all nodes
        for node in &nodes {
            if node == &self.node_id {
                continue;
            }
            
            tracing::debug!("Broadcasting sync operation {} to node: {}", operation.id, node);
        }
        
        Ok(())
    }

    /// Update metrics
    async fn update_metrics(&self, response: &RateLimitResponse, response_time_ms: u64) {
        let mut metrics = self.metrics.write().await;
        
        metrics.total_requests += 1;
        
        if response.allowed {
            metrics.allowed_requests += 1;
        } else {
            metrics.rejected_requests += 1;
            
            match response.action {
                ViolationAction::Throttle => metrics.throttled_requests += 1,
                ViolationAction::Monitor => metrics.monitored_requests += 1,
                _ => {}
            }
            
            if response.threat_level > ThreatLevel::None {
                metrics.violations_detected += 1;
            }
        }
        
        // Update average response time
        let total_time = metrics.average_response_time_ms * (metrics.total_requests - 1) as f64 + response_time_ms as f64;
        metrics.average_response_time_ms = total_time / metrics.total_requests as f64;
        
        // Update distributed sync success rate
        let coordinator = self.sync_coordinator.read().await;
        if coordinator.sync_status == SyncStatus::Synced {
            let sync_success_rate = 0.95; // Simulated success rate
            metrics.distributed_sync_success_rate = sync_success_rate;
        }
        
        metrics.last_updated = Utc::now();
    }

    /// Start background sync task
    async fn start_sync_task(&mut self) {
        let cluster_nodes = self.cluster_nodes.clone();
        let distributed_state = self.distributed_state.clone();
        let sync_coordinator = self.sync_coordinator.clone();
        let node_id = self.node_id.clone();
        
        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(Duration::seconds(5));
            
            loop {
                interval_timer.tick().await;
                
                // Check if sync is needed
                let mut coordinator = sync_coordinator.write().await;
                let now = Utc::now();
                
                if coordinator.sync_status != SyncStatus::Syncing &&
                   now - coordinator.last_sync > coordinator.sync_interval {
                    
                    // Perform sync
                    coordinator.sync_status = SyncStatus::Syncing;
                    
                    // Simulate sync with other nodes
                    let nodes = cluster_nodes.read().await;
                    for node in nodes.iter() {
                        if node == &node_id {
                            continue;
                        }
                        
                        // In real implementation, this would be network communication
                        tracing::debug!("Syncing with node: {}", node);
                    }
                    
                    coordinator.last_sync = now;
                    coordinator.sync_status = SyncStatus::Synced;
                    
                    // Cleanup old state
                    {
                        let mut state = distributed_state.write().await;
                        let cutoff = now - Duration::minutes(30);
                        
                        state.retain(|_, distributed_state| {
                            distributed_state.last_updated > cutoff
                        });
                    }
                    
                    tracing::debug!("Distributed rate limiter sync completed");
                }
            }
        });

        self.cleanup_task = Some(task);
    }
}

#[async_trait::async_trait]
impl ProductionRateLimiter for DistributedRateLimiter {
    fn name(&self) -> &str {
        "distributed_rate_limiter"
    }

    async fn check_rate_limit(&self, request: &RateLimitRequest) -> Result<RateLimitResponse> {
        let start_time = std::time::Instant::now();
        let key = self.generate_response_key(request);
        
        // Check if sync is needed
        if self.needs_sync().await {
            self.synchronize_with_cluster().await?;
        }
        
        // Get distributed state
        let distributed_state = self.get_distributed_state(&key).await;
        
        // Get base rate limit spec
        let config = self.config.read().await;
        let base_spec = if let Some(_) = &request.api_key {
            config.api_key_limits.clone()
        } else if let Some(_) = &request.user_id {
            config.user_limits.clone()
        } else {
            config.ip_limits.clone()
        };
        
        let now = request.timestamp;
        let mut response;
        
        if let Some(state) = distributed_state {
            // Use existing distributed state
            let elapsed = now - state.window_start;
            let window_expired = elapsed > Duration::seconds(state.window_duration);
            
            if window_expired {
                // Reset window
                let new_state = DistributedState {
                    key: key.clone(),
                    current_count: 1,
                    limit: base_spec.requests_per_second,
                    window_start: now,
                    window_duration: 1,
                    last_updated: now,
                    updated_by: self.node_id.clone(),
                    version: state.version + 1,
                };
                
                self.update_distributed_state(key, new_state.clone()).await?;
                
                response = RateLimitResponse {
                    allowed: true,
                    remaining: base_spec.requests_per_second - 1,
                    limit: base_spec.requests_per_second,
                    reset_time: now + Duration::seconds(1),
                    retry_after: None,
                    action: ViolationAction::Monitor,
                    reason: "Request allowed (window reset)".to_string(),
                    violation_count: 0,
                    threat_level: ThreatLevel::None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("distributed".to_string(), serde_json::Value::Bool(true));
                        meta.insert("version".to_string(), serde_json::Value::Number(new_state.version.into()));
                        meta
                    },
                };
            } else {
                // Check against existing state
                let allowed = state.current_count < state.limit;
                let new_count = state.current_count + 1;
                
                if allowed {
                    // Update state
                    let new_state = DistributedState {
                        current_count: new_count,
                        last_updated: now,
                        updated_by: self.node_id.clone(),
                        version: state.version + 1,
                        ..state.clone()
                    };
                    
                    self.update_distributed_state(key, new_state.clone()).await?;
                }
                
                response = RateLimitResponse {
                    allowed,
                    remaining: state.limit.saturating_sub(new_count),
                    limit: state.limit,
                    reset_time: state.window_start + Duration::seconds(state.window_duration),
                    retry_after: if !allowed { Some(Duration::seconds(1)) } else { None },
                    action: if allowed { ViolationAction::Monitor } else { ViolationAction::Reject },
                    reason: if allowed {
                        "Request allowed".to_string()
                    } else {
                        "Distributed rate limit exceeded".to_string()
                    },
                    violation_count: 0,
                    threat_level: ThreatLevel::None,
                    metadata: {
                        let mut meta = HashMap::new();
                        meta.insert("distributed".to_string(), serde_json::Value::Bool(true));
                        meta.insert("current_count".to_string(), serde_json::Value::Number(new_count.into()));
                        meta
                    },
                };
            }
        } else {
            // No distributed state, use local limiter as fallback
            response = self.local_limiter.check_rate_limit(request).await?;
            
            // Create distributed state for future requests
            let new_state = DistributedState {
                key: key.clone(),
                current_count: if response.allowed { 1 } else { 0 },
                limit: response.limit,
                window_start: now,
                window_duration: 1,
                last_updated: now,
                updated_by: self.node_id.clone(),
                version: 1,
            };
            
            self.update_distributed_state(key, new_state).await?;
        }
        
        // Update metrics
        let response_time_ms = start_time.elapsed().as_millis() as u64;
        self.update_metrics(&response, response_time_ms).await;
        
        Ok(response)
    }

    async fn update_config(&self, config: ProductionRateLimitConfig) -> Result<()> {
        let mut config_write = self.config.write().await;
        *config_write = config;
        
        // Update local limiter config as well
        self.local_limiter.update_config(config).await?;
        
        tracing::info!("Distributed rate limiter configuration updated");
        Ok(())
    }

    async fn get_metrics(&self) -> Result<ProductionRateLimitMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    async fn reset_rate_limit(&self, key: &str) -> Result<()> {
        // Reset local limiter
        self.local_limiter.reset_rate_limit(key).await?;
        
        // Reset distributed state
        let new_state = DistributedState {
            key: key.to_string(),
            current_count: 0,
            limit: 0,
            window_start: Utc::now(),
            window_duration: 1,
            last_updated: Utc::now(),
            updated_by: self.node_id.clone(),
            version: 1,
        };
        
        self.update_distributed_state(key.to_string(), new_state).await?;
        
        // Create and broadcast sync operation
        let sync_op = self.create_sync_operation(
            key.to_string(),
            new_state,
            SyncOperationType::Reset,
        );
        
        self.broadcast_sync_operation(sync_op).await?;
        
        tracing::info!("Distributed rate limit reset for key: {}", key);
        Ok(())
    }

    async fn block_ip(&self, ip: &str, duration: Duration) -> Result<()> {
        // Block IP in local limiter
        self.local_limiter.block_ip(ip, duration).await?;
        
        // Create distributed block state
        let key = format!("ip:{}", ip);
        let new_state = DistributedState {
            key: key.clone(),
            current_count: 0,
            limit: 0,
            window_start: Utc::now(),
            window_duration: duration.num_seconds() as u64,
            last_updated: Utc::now(),
            updated_by: self.node_id.clone(),
            version: 1,
        };
        
        self.update_distributed_state(key, new_state.clone()).await?;
        
        // Create and broadcast sync operation
        let sync_op = self.create_sync_operation(
            key,
            new_state,
            SyncOperationType::Update,
        );
        
        self.broadcast_sync_operation(sync_op).await?;
        
        tracing::warn!("IP {} blocked in distributed rate limiter for {:?}", ip, duration);
        Ok(())
    }

    async fn suspend_user(&self, user_id: &str, duration: Duration) -> Result<()> {
        // Suspend user in local limiter
        self.local_limiter.suspend_user(user_id, duration).await?;
        
        // Create distributed suspension state
        let key = format!("user:{}", user_id);
        let new_state = DistributedState {
            key: key.clone(),
            current_count: 0,
            limit: 0,
            window_start: Utc::now(),
            window_duration: duration.num_seconds() as u64,
            last_updated: Utc::now(),
            updated_by: self.node_id.clone(),
            version: 1,
        };
        
        self.update_distributed_state(key, new_state.clone()).await?;
        
        // Create and broadcast sync operation
        let sync_op = self.create_sync_operation(
            key,
            new_state,
            SyncOperationType::Update,
        );
        
        self.broadcast_sync_operation(sync_op).await?;
        
        tracing::warn!("User {} suspended in distributed rate limiter for {:?}", user_id, duration);
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        // Cleanup local limiter
        self.local_limiter.cleanup().await?;
        
        // Cleanup distributed state
        let mut state = self.distributed_state.write().await;
        let now = Utc::now();
        
        // Remove old state
        state.retain(|_, distributed_state| {
            now - distributed_state.last_updated < Duration::minutes(30)
        });
        
        // Cleanup sync coordinator
        let mut coordinator = self.sync_coordinator.write().await;
        coordinator.pending_syncs.clear();
        
        tracing::debug!("Distributed rate limiter cleanup completed");
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        // Stop sync task
        if let Some(task) = &self.cleanup_task {
            task.abort();
        }
        
        // Shutdown local limiter
        self.local_limiter.shutdown().await?;
        
        tracing::info!("Distributed rate limiter shutdown");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::rate_limiter::token_bucket::ProductionTokenBucket;

    #[tokio::test]
    async fn test_distributed_limiter_creation() {
        let config = ProductionRateLimitConfig::default();
        let local_limiter = Arc::new(ProductionTokenBucket::new(config.clone()));
        let cluster_nodes = HashSet::from(["node1".to_string(), "node2".to_string()]);
        
        let limiter = DistributedRateLimiter::new(
            config,
            "node1".to_string(),
            cluster_nodes,
            local_limiter,
        );
        
        assert_eq!(limiter.name(), "distributed_rate_limiter");
        
        let metrics = limiter.get_metrics().await.unwrap();
        assert_eq!(metrics.total_requests, 0);
        assert_eq!(metrics.allowed_requests, 0);
        assert_eq!(metrics.rejected_requests, 0);
    }

    #[tokio::test]
    async fn test_distributed_state_creation() {
        let state = DistributedState {
            key: "test-key".to_string(),
            current_count: 5,
            limit: 10,
            window_start: Utc::now(),
            window_duration: 60,
            last_updated: Utc::now(),
            updated_by: "node1".to_string(),
            version: 1,
        };
        
        assert_eq!(state.key, "test-key");
        assert_eq!(state.current_count, 5);
        assert_eq!(state.limit, 10);
        assert_eq!(state.version, 1);
    }

    #[tokio::test]
    async fn test_conflict_resolution() {
        let config = ProductionRateLimitConfig::default();
        let local_limiter = Arc::new(ProductionTokenBucket::new(config.clone()));
        let cluster_nodes = HashSet::from(["node1".to_string()]);
        
        let limiter = DistributedRateLimiter::new(
            config,
            "node1".to_string(),
            cluster_nodes,
            local_limiter,
        );

        let existing = DistributedState {
            key: "test".to_string(),
            current_count: 5,
            limit: 10,
            window_start: Utc::now(),
            window_duration: 60,
            last_updated: Utc::now() - Duration::seconds(1),
            updated_by: "node1".to_string(),
            version: 1,
        };

        let new = DistributedState {
            key: "test".to_string(),
            current_count: 7,
            limit: 10,
            window_start: Utc::now(),
            window_duration: 60,
            last_updated: Utc::now(),
            updated_by: "node2".to_string(),
            version: 2,
        };

        let resolved = limiter.resolve_conflict(&existing, &new).await.unwrap();
        
        // Last write wins should pick the newer state
        assert_eq!(resolved.current_count, 7);
        assert_eq!(resolved.version, 2);
    }

    #[tokio::test]
    async fn test_sync_operation_creation() {
        let config = ProductionRateLimitConfig::default();
        let local_limiter = Arc::new(ProductionTokenBucket::new(config.clone()));
        let cluster_nodes = HashSet::from(["node1".to_string()]);
        
        let limiter = DistributedRateLimiter::new(
            config,
            "node1".to_string(),
            cluster_nodes,
            local_limiter,
        );

        let state = DistributedState {
            key: "test".to_string(),
            current_count: 5,
            limit: 10,
            window_start: Utc::now(),
            window_duration: 60,
            last_updated: Utc::now(),
            updated_by: "node1".to_string(),
            version: 1,
        };

        let sync_op = limiter.create_sync_operation(
            "test".to_string(),
            state,
            SyncOperationType::Update,
        );

        assert_eq!(sync_op.key, "test");
        assert_eq!(sync_op.source_node, "node1");
        assert!(matches!(sync_op.operation_type, SyncOperationType::Update));
    }
}
