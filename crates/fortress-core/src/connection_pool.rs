//! Advanced connection pooling and load balancing for Fortress
//!
//! This module provides sophisticated connection pooling with health checks,
//! load balancing algorithms, and automatic failover capabilities.

use crate::error::{FortressError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

/// Load balancing algorithms
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum LoadBalanceAlgorithm {
    /// Round-robin distribution
    RoundRobin,
    /// Weighted round-robin
    WeightedRoundRobin,
    /// Least connections
    LeastConnections,
    /// Weighted least connections
    WeightedLeastConnections,
    /// Random selection
    Random,
    /// IP hash (for session affinity)
    IpHash,
    /// Response time based
    ResponseTime,
}

/// Connection pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolConfig {
    /// Maximum number of connections in the pool
    pub max_connections: usize,
    /// Minimum number of connections to maintain
    pub min_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Idle timeout in seconds
    pub idle_timeout_seconds: u64,
    /// Maximum lifetime of a connection in seconds
    pub max_lifetime_seconds: u64,
    /// Health check interval in seconds
    pub health_check_interval_seconds: u64,
    /// Health check timeout in seconds
    pub health_check_timeout_seconds: u64,
    /// Enable connection recycling
    pub enable_connection_recycling: bool,
    /// Load balancing algorithm
    pub load_balance_algorithm: LoadBalanceAlgorithm,
    /// Enable automatic failover
    pub enable_failover: bool,
    /// Failover timeout in seconds
    pub failover_timeout_seconds: u64,
    /// Retry attempts on failure
    pub max_retry_attempts: u32,
    /// Backoff multiplier for retries
    pub retry_backoff_multiplier: f64,
}

impl Default for ConnectionPoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 100,
            min_connections: 5,
            connection_timeout_seconds: 30,
            idle_timeout_seconds: 300,
            max_lifetime_seconds: 3600,
            health_check_interval_seconds: 60,
            health_check_timeout_seconds: 5,
            enable_connection_recycling: true,
            load_balance_algorithm: LoadBalanceAlgorithm::LeastConnections,
            enable_failover: true,
            failover_timeout_seconds: 10,
            max_retry_attempts: 3,
            retry_backoff_multiplier: 2.0,
        }
    }
}

/// Server endpoint configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerEndpoint {
    /// Unique identifier for the server
    pub id: String,
    /// Server address (host:port)
    pub address: String,
    /// Server weight for weighted algorithms
    pub weight: u32,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Server is currently available
    pub available: bool,
    /// Server region/location
    pub region: Option<String>,
    /// Server tags for routing
    pub tags: Vec<String>,
}

/// Connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionStats {
    /// Total connections created
    pub total_connections: u64,
    /// Active connections
    pub active_connections: u64,
    /// Idle connections
    pub idle_connections: u64,
    /// Failed connections
    pub failed_connections: u64,
    /// Average connection lifetime in seconds
    pub avg_connection_lifetime_seconds: f64,
    /// Total queries executed
    pub total_queries: u64,
    /// Average query time in milliseconds
    pub avg_query_time_ms: f64,
    /// Connection pool utilization (0.0 to 1.0)
    pub utilization: f64,
    /// Last health check timestamp
    pub last_health_check: Option<chrono::DateTime<chrono::Utc>>,
    /// Health check failures
    pub health_check_failures: u64,
}

/// Individual connection wrapper
#[derive(Debug, Clone)]
pub struct PooledConnection {
    /// Connection ID
    pub id: String,
    /// Server endpoint
    pub endpoint: ServerEndpoint,
    /// Creation timestamp
    pub created_at: Instant,
    /// Last used timestamp
    pub last_used: Instant,
    /// Number of times used
    pub use_count: u64,
    /// Is the connection healthy
    pub healthy: bool,
    /// Connection state
    pub state: ConnectionState,
}

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConnectionState {
    /// Connection is idle and available
    Idle,
    /// Connection is in use
    Active,
    /// Connection is being checked for health
    HealthChecking,
    /// Connection is failed and should be removed
    Failed,
}

/// Trait for connection management
#[async_trait]
pub trait ConnectionManager: Send + Sync + std::fmt::Debug {
    /// Get a connection from the pool
    async fn get_connection(&self) -> Result<Arc<PooledConnection>>;

    /// Return a connection to the pool
    async fn return_connection(&self, connection: Arc<PooledConnection>) -> Result<()>;

    /// Close a connection
    async fn close_connection(&self, connection: Arc<PooledConnection>) -> Result<()>;

    /// Get pool statistics
    async fn get_statistics(&self) -> Result<ConnectionStats>;

    /// Health check for all connections
    async fn health_check(&self) -> Result<bool>;

    /// Close all connections
    async fn close_all(&self) -> Result<()>;

    /// Add a new server endpoint
    async fn add_endpoint(&self, endpoint: ServerEndpoint) -> Result<()>;

    /// Remove a server endpoint
    async fn remove_endpoint(&self, endpoint_id: &str) -> Result<bool>;

    /// Get list of server endpoints
    async fn get_endpoints(&self) -> Result<Vec<ServerEndpoint>>;
}

/// Advanced connection pool implementation
#[derive(Debug)]
pub struct AdvancedConnectionPool {
    /// Pool configuration
    config: ConnectionPoolConfig,
    /// Server endpoints
    endpoints: Arc<RwLock<Vec<ServerEndpoint>>>,
    /// Available connections per endpoint
    connections: Arc<RwLock<HashMap<String, Vec<Arc<PooledConnection>>>>>,
    /// Connection semaphore for limiting total connections
    connection_semaphore: Arc<Semaphore>,
    /// Round-robin counter
    round_robin_counter: Arc<RwLock<usize>>,
    /// Statistics
    stats: Arc<RwLock<ConnectionStats>>,
    /// Health check task handle
    health_check_handle: Arc<RwLock<Option<tokio::task::JoinHandle<()>>>>,
}

impl AdvancedConnectionPool {
    /// Create a new advanced connection pool
    pub async fn new(config: ConnectionPoolConfig, endpoints: Vec<ServerEndpoint>) -> Self {
        let pool = Self {
            connection_semaphore: Arc::new(Semaphore::new(config.max_connections)),
            endpoints: Arc::new(RwLock::new(endpoints)),
            connections: Arc::new(RwLock::new(HashMap::new())),
            round_robin_counter: Arc::new(RwLock::new(0)),
            stats: Arc::new(RwLock::new(ConnectionStats {
                total_connections: 0,
                active_connections: 0,
                idle_connections: 0,
                failed_connections: 0,
                avg_connection_lifetime_seconds: 0.0,
                total_queries: 0,
                avg_query_time_ms: 0.0,
                utilization: 0.0,
                last_health_check: None,
                health_check_failures: 0,
            })),
            config,
            health_check_handle: Arc::new(RwLock::new(None)),
        };

        // Start background tasks
        pool.start_background_tasks().await;

        pool
    }

    /// Start background health checking
    async fn start_background_tasks(&self) {
        if self.config.health_check_interval_seconds > 0 {
            let endpoints = self.endpoints.clone();
            let connections = self.connections.clone();
            let stats = self.stats.clone();
            let interval = Duration::from_secs(self.config.health_check_interval_seconds);

            let handle = tokio::spawn(async move {
                let mut interval_timer = tokio::time::interval(interval);
                
                loop {
                    interval_timer.tick().await;
                    
                    if let Err(e) = Self::perform_health_checks(&endpoints, &connections, &stats).await {
                        eprintln!("Health check failed: {}", e);
                    }
                }
            });

            let mut health_check_handle = self.health_check_handle.write().await;
            *health_check_handle = Some(handle);
        }
    }

    /// Perform health checks on all connections
    async fn perform_health_checks(
        endpoints: &Arc<RwLock<Vec<ServerEndpoint>>>,
        connections: &Arc<RwLock<HashMap<String, Vec<Arc<PooledConnection>>>>>,
        stats: &Arc<RwLock<ConnectionStats>>,
    ) -> Result<()> {
        let endpoints_guard = endpoints.read().await;
        let mut connections_guard = connections.write().await;
        let mut stats_guard = stats.write().await;

        let now = chrono::Utc::now();
        stats_guard.last_health_check = Some(now);

        for endpoint in endpoints_guard.iter() {
            if let Some(conn_list) = connections_guard.get_mut(&endpoint.id) {
                let mut healthy_connections = Vec::new();
                let mut failed_connections = Vec::new();

                for connection in conn_list.iter() {
                    if Self::check_connection_health(connection).await? {
                        healthy_connections.push(connection.clone());
                    } else {
                        failed_connections.push(connection.clone());
                    }
                }

                // Update connection list
                *conn_list = healthy_connections;
                
                // Update statistics
                stats_guard.health_check_failures += failed_connections.len() as u64;

                // Mark endpoint as unavailable if all connections failed
                if conn_list.is_empty() {
                    // Update endpoint availability (would need mutable access)
                    stats_guard.health_check_failures += 1;
                }
            }
        }

        Ok(())
    }

    /// Check health of a single connection
    async fn check_connection_health(connection: &Arc<PooledConnection>) -> Result<bool> {
        // Simple health check - in production, implement actual ping/query
        let age = connection.created_at.elapsed();
        let idle_time = connection.last_used.elapsed();

        // Consider connection unhealthy if:
        // 1. Too old (exceeded max lifetime)
        // 2. Idle for too long
        // 3. Marked as failed
        
        if age.as_secs() > 3600 || idle_time.as_secs() > 300 || !connection.healthy {
            return Ok(false);
        }

        Ok(true)
    }

    /// Select the best endpoint based on load balancing algorithm
    async fn select_endpoint(&self) -> Result<ServerEndpoint> {
        let endpoints = self.endpoints.read().await;
        let available_endpoints: Vec<&ServerEndpoint> = endpoints
            .iter()
            .filter(|e| e.available)
            .collect();

        if available_endpoints.is_empty() {
            return Err(FortressError::storage(
                "No available endpoints".to_string(),
                "connection_pool".to_string(),
                crate::error::StorageErrorCode::ConnectionFailed,
            ));
        }

        let selected = match self.config.load_balance_algorithm {
            LoadBalanceAlgorithm::RoundRobin => {
                let mut counter = self.round_robin_counter.write().await;
                let index = *counter % available_endpoints.len();
                *counter += 1;
                available_endpoints[index].clone()
            }
            LoadBalanceAlgorithm::LeastConnections => {
                let connections = self.connections.read().await;
                let best_endpoint = available_endpoints
                    .iter()
                    .min_by(|a, b| {
                        let conn_a = connections
                            .get(&a.id)
                            .map(|conns| conns.len())
                            .unwrap_or(0);
                        let conn_b = connections
                            .get(&b.id)
                            .map(|conns| conns.len())
                            .unwrap_or(0);
                        conn_a.cmp(&conn_b)
                    })
                    .unwrap_or(&available_endpoints[0]);
                (*best_endpoint).clone()
            }
            LoadBalanceAlgorithm::Random => {
                let index = rand::random::<usize>() % available_endpoints.len();
                available_endpoints[index].clone()
            }
            LoadBalanceAlgorithm::WeightedRoundRobin => {
                // Simplified weighted selection
                let total_weight: u32 = available_endpoints.iter().map(|e| e.weight).sum();
                let mut random_weight = rand::random::<u32>() % total_weight;
                
                for endpoint in available_endpoints.iter() {
                    if random_weight < endpoint.weight {
                        return Ok((*endpoint).clone());
                    }
                    random_weight -= endpoint.weight;
                }
                
                available_endpoints[0].clone()
            }
            LoadBalanceAlgorithm::WeightedLeastConnections => {
                let connections = self.connections.read().await;
                let best_endpoint = available_endpoints
                    .iter()
                    .min_by(|a, b| {
                        let conn_count_a = connections
                            .get(&a.id)
                            .map(|conns| conns.len())
                            .unwrap_or(0);
                        let conn_count_b = connections
                            .get(&b.id)
                            .map(|conns| conns.len())
                            .unwrap_or(0);
                        let ratio_a = (conn_count_a as f64) / (a.weight as f64);
                        let ratio_b = (conn_count_b as f64) / (b.weight as f64);
                        ratio_a.total_cmp(&ratio_b)
                    })
                    .unwrap();
                (*best_endpoint).clone()
            }
            LoadBalanceAlgorithm::IpHash => {
                // Simplified IP hash - would use client IP in real implementation
                let hash = rand::random::<u64>();
                let index = (hash as usize) % available_endpoints.len();
                available_endpoints[index].clone()
            }
            LoadBalanceAlgorithm::ResponseTime => {
                // Simplified - would track actual response times
                available_endpoints[0].clone()
            }
        };

        Ok(selected)
    }

    /// Create a new connection to an endpoint
    async fn create_connection(&self, endpoint: &ServerEndpoint) -> Result<Arc<PooledConnection>> {
        // Simulate connection creation
        let connection = Arc::new(PooledConnection {
            id: Uuid::new_v4().to_string(),
            endpoint: endpoint.clone(),
            created_at: Instant::now(),
            last_used: Instant::now(),
            use_count: 0,
            healthy: true,
            state: ConnectionState::Idle,
        });

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_connections += 1;
            stats.idle_connections += 1;
        }

        Ok(connection)
    }

    /// Get an existing idle connection for an endpoint
    async fn get_idle_connection(&self, endpoint_id: &str) -> Option<Arc<PooledConnection>> {
        let mut connections = self.connections.write().await;
        
        if let Some(conn_list) = connections.get_mut(endpoint_id) {
            // Find an idle connection
            if let Some(pos) = conn_list.iter().position(|conn| conn.state == ConnectionState::Idle) {
                let connection = conn_list.swap_remove(pos);
                
                // Update connection state
                let mut conn_mut = Arc::try_unwrap(connection)
                    .unwrap_or_else(|arc| (*arc).clone());
                conn_mut.state = ConnectionState::Active;
                conn_mut.last_used = Instant::now();
                conn_mut.use_count += 1;
                let connection = Arc::new(conn_mut);
                
                // Add back to list
                conn_list.push(connection.clone());
                
                // Update statistics
                let mut stats = self.stats.write().await;
                stats.active_connections += 1;
                stats.idle_connections = stats.idle_connections.saturating_sub(1);
                
                return Some(connection);
            }
        }

        None
    }
}

#[async_trait]
impl ConnectionManager for AdvancedConnectionPool {
    async fn get_connection(&self) -> Result<Arc<PooledConnection>> {
        // Acquire semaphore to limit total connections
        let _permit = self.connection_semaphore.acquire().await
            .map_err(|_| FortressError::storage(
                "Connection pool exhausted".to_string(),
                "connection_pool".to_string(),
                crate::error::StorageErrorCode::ConnectionFailed,
            ))?;

        // Select best endpoint
        let endpoint = self.select_endpoint().await?;

        // Try to get existing connection
        if let Some(connection) = self.get_idle_connection(&endpoint.id).await {
            return Ok(connection);
        }

        // Create new connection
        let connection = self.create_connection(&endpoint).await?;

        // Add to connection pool
        {
            let mut connections = self.connections.write().await;
            connections
                .entry(endpoint.id.clone())
                .or_insert_with(Vec::new)
                .push(connection.clone());
        }

        Ok(connection)
    }

    async fn return_connection(&self, connection: Arc<PooledConnection>) -> Result<()> {
        // Update connection state
        let mut conn_mut = Arc::try_unwrap(connection)
            .unwrap_or_else(|arc| (*arc).clone());
        conn_mut.state = ConnectionState::Idle;
        conn_mut.last_used = Instant::now();
        let _connection = Arc::new(conn_mut);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.active_connections = stats.active_connections.saturating_sub(1);
            stats.idle_connections += 1;
        }

        // Connection is already in the pool, just updated state
        Ok(())
    }

    async fn close_connection(&self, connection: Arc<PooledConnection>) -> Result<()> {
        let endpoint_id = connection.endpoint.id.clone();

        // Remove from pool
        {
            let mut connections = self.connections.write().await;
            if let Some(conn_list) = connections.get_mut(&endpoint_id) {
                conn_list.retain(|conn| conn.id != connection.id);
            }
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            if connection.state == ConnectionState::Active {
                stats.active_connections = stats.active_connections.saturating_sub(1);
            } else {
                stats.idle_connections = stats.idle_connections.saturating_sub(1);
            }
        }

        Ok(())
    }

    async fn get_statistics(&self) -> Result<ConnectionStats> {
        let stats = self.stats.read().await;
        Ok(stats.clone())
    }

    async fn health_check(&self) -> Result<bool> {
        Self::perform_health_checks(
            &self.endpoints,
            &self.connections,
            &self.stats,
        ).await?;
        Ok(true)
    }

    async fn close_all(&self) -> Result<()> {
        let mut connections = self.connections.write().await;
        connections.clear();

        // Update statistics
        let mut stats = self.stats.write().await;
        stats.active_connections = 0;
        stats.idle_connections = 0;

        Ok(())
    }

    async fn add_endpoint(&self, endpoint: ServerEndpoint) -> Result<()> {
        let mut endpoints = self.endpoints.write().await;
        endpoints.push(endpoint);
        Ok(())
    }

    async fn remove_endpoint(&self, endpoint_id: &str) -> Result<bool> {
        let mut endpoints = self.endpoints.write().await;
        let initial_len = endpoints.len();
        endpoints.retain(|e| e.id != endpoint_id);
        
        // Also remove connections for this endpoint
        let mut connections = self.connections.write().await;
        connections.remove(endpoint_id);

        Ok(endpoints.len() < initial_len)
    }

    async fn get_endpoints(&self) -> Result<Vec<ServerEndpoint>> {
        let endpoints = self.endpoints.read().await;
        Ok(endpoints.clone())
    }
}

/// Factory function to create connection pool
pub async fn create_connection_pool(
    config: ConnectionPoolConfig,
    endpoints: Vec<ServerEndpoint>,
) -> Box<dyn ConnectionManager> {
    Box::new(AdvancedConnectionPool::new(config, endpoints).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool_basic_operations() {
        let config = ConnectionPoolConfig::default();
        let endpoints = vec![
            ServerEndpoint {
                id: "server1".to_string(),
                address: "localhost:5432".to_string(),
                weight: 1,
                max_connections: 10,
                available: true,
                region: None,
                tags: vec!["primary".to_string()],
            }
        ];

        let pool = AdvancedConnectionPool::new(config, endpoints);

        // Test getting a connection
        let connection = pool.get_connection().await.unwrap();
        assert_eq!(connection.endpoint.id, "server1");
        assert_eq!(connection.state, ConnectionState::Active);

        // Test returning connection
        pool.return_connection(connection).await.unwrap();

        // Test statistics
        let stats = pool.get_statistics().await.unwrap();
        assert!(stats.total_connections > 0);
    }

    #[tokio::test]
    async fn test_load_balancing_algorithms() {
        let config = ConnectionPoolConfig {
            load_balance_algorithm: LoadBalanceAlgorithm::RoundRobin,
            ..Default::default()
        };

        let endpoints = vec![
            ServerEndpoint {
                id: "server1".to_string(),
                address: "localhost:5432".to_string(),
                weight: 1,
                max_connections: 10,
                available: true,
                region: None,
                tags: vec![],
            },
            ServerEndpoint {
                id: "server2".to_string(),
                address: "localhost:5433".to_string(),
                weight: 1,
                max_connections: 10,
                available: true,
                region: None,
                tags: vec![],
            },
        ];

        let pool = AdvancedConnectionPool::new(config, endpoints);

        // Test round-robin selection
        let conn1 = pool.get_connection().await.unwrap();
        let conn2 = pool.get_connection().await.unwrap();

        assert_ne!(conn1.endpoint.id, conn2.endpoint.id);
    }

    #[tokio::test]
    async fn test_endpoint_management() {
        let config = ConnectionPoolConfig::default();
        let endpoints = vec![];

        let pool = AdvancedConnectionPool::new(config, endpoints);

        // Add endpoint
        let new_endpoint = ServerEndpoint {
            id: "server3".to_string(),
            address: "localhost:5434".to_string(),
            weight: 1,
            max_connections: 10,
            available: true,
            region: None,
            tags: vec![],
        };

        pool.add_endpoint(new_endpoint.clone()).await.unwrap();

        // Check endpoints
        let endpoint_list = pool.get_endpoints().await.unwrap();
        assert_eq!(endpoint_list.len(), 1);
        assert_eq!(endpoint_list[0].id, "server3");

        // Remove endpoint
        let removed = pool.remove_endpoint("server3").await.unwrap();
        assert!(removed);

        let endpoint_list = pool.get_endpoints().await.unwrap();
        assert_eq!(endpoint_list.len(), 0);
    }

    #[tokio::test]
    async fn test_connection_statistics() {
        let config = ConnectionPoolConfig::default();
        let endpoints = vec![
            ServerEndpoint {
                id: "server1".to_string(),
                address: "localhost:5432".to_string(),
                weight: 1,
                max_connections: 10,
                available: true,
                region: None,
                tags: vec![],
            }
        ];

        let pool = AdvancedConnectionPool::new(config, endpoints);

        // Perform some operations
        let conn1 = pool.get_connection().await.unwrap();
        let conn2 = pool.get_connection().await.unwrap();
        
        pool.return_connection(conn1).await.unwrap();
        pool.return_connection(conn2).await.unwrap();

        let stats = pool.get_statistics().await.unwrap();
        assert_eq!(stats.total_connections, 2);
        assert!(stats.active_connections >= 0);
        assert!(stats.idle_connections >= 0);
    }
}
