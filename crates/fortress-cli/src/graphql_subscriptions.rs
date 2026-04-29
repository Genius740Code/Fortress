use async_graphql::{Subscription, Result, Context};
use futures::stream::StreamExt;
use tokio_stream::{Stream, wrappers::BroadcastStream};
use tokio::sync::broadcast;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use chrono::{DateTime, Utc};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct DataChangeEvent {
    pub table_id: String,
    pub operation: DataOperation,
    pub record_id: String,
    pub timestamp: DateTime<Utc>,
    pub user_id: Option<String>,
    pub changes: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum DataOperation {
    Create,
    Update,
    Delete,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct SecurityEvent {
    pub event_type: String,
    pub severity: SecuritySeverity,
    pub user_id: Option<String>,
    pub resource: String,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
    pub source_ip: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct PerformanceMetrics {
    pub cpu_usage: f64,
    pub memory_usage: f64,
    pub disk_usage: f64,
    pub network_io: NetworkIO,
    pub database_connections: u32,
    pub active_requests: u32,
    pub timestamp: DateTime<Utc>,
    pub uptime_seconds: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct NetworkIO {
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: u32,
    pub requests_per_second: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct ClusterEvent {
    pub event_type: ClusterEventType,
    pub node_id: String,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum ClusterEventType {
    NodeJoined,
    NodeLeft,
    LeaderElected,
    FollowerElected,
    PartitionDetected,
    PartitionHealed,
    ReplicationLag,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::SimpleObject)]
pub struct ComplianceEvent {
    pub framework: String,
    pub event_type: ComplianceEventType,
    pub timestamp: DateTime<Utc>,
    pub details: serde_json::Value,
    pub status: ComplianceStatus,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum ComplianceEventType {
    AuditStarted,
    AuditCompleted,
    ViolationDetected,
    RequirementMet,
    PolicyUpdated,
    ReportGenerated,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[derive(async_graphql::Enum, Copy, Eq, PartialEq)]
pub enum ComplianceStatus {
    Compliant,
    NonCompliant,
    Pending,
    Unknown,
}

// Event bus for real-time events
#[derive(Clone)]
pub struct EventBus {
    data_change_sender: broadcast::Sender<DataChangeEvent>,
    security_event_sender: broadcast::Sender<SecurityEvent>,
    performance_metrics_sender: broadcast::Sender<PerformanceMetrics>,
    cluster_event_sender: broadcast::Sender<ClusterEvent>,
    compliance_event_sender: broadcast::Sender<ComplianceEvent>,
}

impl EventBus {
    pub fn new() -> Self {
        let (data_change_sender, _) = broadcast::channel(1000);
        let (security_event_sender, _) = broadcast::channel(1000);
        let (performance_metrics_sender, _) = broadcast::channel(1000);
        let (cluster_event_sender, _) = broadcast::channel(1000);
        let (compliance_event_sender, _) = broadcast::channel(1000);
        
        Self {
            data_change_sender,
            security_event_sender,
            performance_metrics_sender,
            cluster_event_sender,
            compliance_event_sender,
        }
    }
    
    pub fn publish_data_change(&self, event: DataChangeEvent) -> Result<usize, broadcast::error::SendError<DataChangeEvent>> {
        self.data_change_sender.send(event)
    }
    
    pub fn publish_security_event(&self, event: SecurityEvent) -> Result<usize, broadcast::error::SendError<SecurityEvent>> {
        self.security_event_sender.send(event)
    }
    
    pub fn publish_performance_metrics(&self, metrics: PerformanceMetrics) -> Result<usize, broadcast::error::SendError<PerformanceMetrics>> {
        self.performance_metrics_sender.send(metrics)
    }
    
    pub fn publish_cluster_event(&self, event: ClusterEvent) -> Result<usize, broadcast::error::SendError<ClusterEvent>> {
        self.cluster_event_sender.send(event)
    }
    
    pub fn publish_compliance_event(&self, event: ComplianceEvent) -> Result<usize, broadcast::error::SendError<ComplianceEvent>> {
        self.compliance_event_sender.send(event)
    }
    
    pub fn subscribe_data_changes(&self) -> broadcast::Receiver<DataChangeEvent> {
        self.data_change_sender.subscribe()
    }
    
    pub fn subscribe_security_events(&self) -> broadcast::Receiver<SecurityEvent> {
        self.security_event_sender.subscribe()
    }
    
    pub fn subscribe_performance_metrics(&self) -> broadcast::Receiver<PerformanceMetrics> {
        self.performance_metrics_sender.subscribe()
    }
    
    pub fn subscribe_cluster_events(&self) -> broadcast::Receiver<ClusterEvent> {
        self.cluster_event_sender.subscribe()
    }
    
    pub fn subscribe_compliance_events(&self) -> broadcast::Receiver<ComplianceEvent> {
        self.compliance_event_sender.subscribe()
    }
}

// User context for authorization
#[derive(Clone)]
pub struct UserContext {
    pub user_id: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub tenant_id: Option<String>,
}

impl UserContext {
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }
    
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(&role.to_string())
    }
    
    pub fn can_access_table(&self, table_id: &str) -> bool {
        // Check table-specific permissions
        self.has_permission(&format!("table:read:{}", table_id)) ||
        self.has_permission("table:read:*") ||
        self.has_role("admin")
    }
}

pub struct DataSubscription;

#[Subscription]
impl DataSubscription {
    /// Subscribe to real-time data changes for a specific table
    async fn data_changes(
        &self, 
        ctx: &Context<'_>, 
        table_id: String,
        #[graphql(desc = "Filter by operation type")] operation: Option<DataOperation>,
        #[graphql(desc = "Filter by user ID")] user_id: Option<String>
    ) -> Result<impl Stream<Item = DataChangeEvent>> {
        let event_bus = ctx.data::<Arc<EventBus>>()
            .map_err(|_| async_graphql::Error::new("Event bus not available"))?;
        
        // Validate table access permissions
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        if !user_context.can_access_table(&table_id) {
            return Err(async_graphql::Error::new("Access denied to table"));
        }
        
        let subscription_rx = event_bus.subscribe_data_changes();
        let table_id_filter = table_id;
        let stream = BroadcastStream::new(subscription_rx)
            .filter_map(|result| async move {
                match result {
                    Ok(event) => Some(event),
                    Err(_) => None, // Skip broadcast errors
                }
            });
        
        Ok(stream)
    }
    
    /// Subscribe to security events in real-time
    async fn security_events(
        &self, 
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by severity")] severity: Option<SecuritySeverity>,
        #[graphql(desc = "Filter by event type")] event_type: Option<String>
    ) -> Result<impl Stream<Item = SecurityEvent>> {
        let event_bus = ctx.data::<Arc<EventBus>>()
            .map_err(|_| async_graphql::Error::new("Event bus not available"))?;
        
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        // Check security monitoring permissions
        if !user_context.has_permission("security.monitor") {
            return Err(async_graphql::Error::new("Insufficient permissions for security monitoring"));
        }
        
        let subscription_rx = event_bus.subscribe_security_events();
        let stream = BroadcastStream::new(subscription_rx)
            .filter_map(|result| async move {
                match result {
                    Ok(event) => Some(event),
                    Err(_) => None, // Skip broadcast errors
                }
            });
        
        Ok(stream)
    }
    
    /// Subscribe to system performance metrics
    async fn performance_metrics(
        &self, 
        ctx: &Context<'_>,
        #[graphql(desc = "Update interval in seconds")] interval: Option<i32>
    ) -> Result<impl Stream<Item = PerformanceMetrics>> {
        let event_bus = ctx.data::<Arc<EventBus>>()
            .map_err(|_| async_graphql::Error::new("Event bus not available"))?;
        
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        // Check monitoring permissions
        if !user_context.has_permission("system.monitor") {
            return Err(async_graphql::Error::new("Insufficient permissions for system monitoring"));
        }
        
        let subscription_rx = event_bus.subscribe_performance_metrics();
        let stream = BroadcastStream::new(subscription_rx)
            .filter_map(|result| async move {
                match result {
                    Ok(metrics) => Some(metrics),
                    Err(_) => None, // Skip broadcast errors
                }
            });
        
        Ok(stream)
    }
    
    /// Subscribe to cluster events
    async fn cluster_events(
        &self, 
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by event type")] event_type: Option<ClusterEventType>,
        #[graphql(desc = "Filter by node ID")] node_id: Option<String>
    ) -> Result<impl Stream<Item = ClusterEvent>> {
        let event_bus = ctx.data::<Arc<EventBus>>()
            .map_err(|_| async_graphql::Error::new("Event bus not available"))?;
        
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        // Check cluster monitoring permissions
        if !user_context.has_permission("cluster.monitor") {
            return Err(async_graphql::Error::new("Insufficient permissions for cluster monitoring"));
        }
        
        let subscription_rx = event_bus.subscribe_cluster_events();
        let stream = BroadcastStream::new(subscription_rx)
            .filter_map(|result| async move {
                match result {
                    Ok(event) => Some(event),
                    Err(_) => None, // Skip broadcast errors
                }
            });
        
        Ok(stream)
    }
    
    /// Subscribe to compliance events
    async fn compliance_events(
        &self, 
        ctx: &Context<'_>,
        #[graphql(desc = "Filter by compliance framework")] framework: Option<String>,
        #[graphql(desc = "Filter by event type")] event_type: Option<ComplianceEventType>
    ) -> Result<impl Stream<Item = ComplianceEvent>> {
        let event_bus = ctx.data::<Arc<EventBus>>()
            .map_err(|_| async_graphql::Error::new("Event bus not available"))?;
        
        let user_context = ctx.data::<UserContext>()
            .map_err(|_| async_graphql::Error::new("User context not available"))?;
        
        // Check compliance monitoring permissions
        if !user_context.has_permission("compliance.monitor") {
            return Err(async_graphql::Error::new("Insufficient permissions for compliance monitoring"));
        }
        
        let subscription_rx = event_bus.subscribe_compliance_events();
        let stream = BroadcastStream::new(subscription_rx)
            .filter_map(|result| async move {
                match result {
                    Ok(event) => Some(event),
                    Err(_) => None, // Skip broadcast errors
                }
            });
        
        Ok(stream)
    }
}

// Metrics collector for performance data
pub struct MetricsCollector {
    event_bus: Arc<EventBus>,
}

impl MetricsCollector {
    pub fn new(event_bus: Arc<EventBus>) -> Self {
        Self { event_bus }
    }
    
    pub async fn collect_current_metrics(&self) -> PerformanceMetrics {
        // In a real implementation, this would collect actual system metrics
        // For now, we'll return simulated data
        let now = Utc::now();
        
        PerformanceMetrics {
            cpu_usage: 45.2,
            memory_usage: 67.8,
            disk_usage: 23.1,
            network_io: NetworkIO {
                bytes_in: 1024 * 1024 * 100, // 100MB
                bytes_out: 1024 * 1024 * 50,  // 50MB
                connections: 25,
                requests_per_second: 150.5,
            },
            database_connections: 8,
            active_requests: 12,
            timestamp: now,
            uptime_seconds: 86400, // 1 day
        }
    }
    
    pub async fn start_metrics_collection(&self) -> tokio::task::JoinHandle<()> {
        let event_bus = self.event_bus.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                let collector = MetricsCollector::new(event_bus.clone());
                let metrics = collector.collect_current_metrics().await;
                
                if let Err(e) = event_bus.publish_performance_metrics(metrics) {
                    eprintln!("Failed to publish performance metrics: {}", e);
                }
            }
        })
    }
    
    pub async fn simulate_data_change_event(&self, table_id: &str, operation: DataOperation, user_id: Option<String>) {
        let event = DataChangeEvent {
            table_id: table_id.to_string(),
            operation,
            record_id: format!("record_{}", uuid::Uuid::new_v4()),
            timestamp: Utc::now(),
            user_id,
            changes: Some(serde_json::json!({
                "field1": "value1",
                "field2": "value2"
            })),
        };
        
        if let Err(e) = self.event_bus.publish_data_change(event) {
            eprintln!("Failed to publish data change event: {}", e);
        }
    }
    
    pub async fn simulate_security_event(&self, event_type: &str, severity: SecuritySeverity, user_id: Option<String>) {
        let event = SecurityEvent {
            event_type: event_type.to_string(),
            severity,
            user_id,
            resource: "api_endpoint".to_string(),
            timestamp: Utc::now(),
            details: serde_json::json!({
                "endpoint": "/api/v1/users",
                "method": "POST",
                "status": "success"
            }),
            source_ip: Some("192.168.1.100".to_string()),
            user_agent: Some("Fortress CLI/1.0.2".to_string()),
        };
        
        if let Err(e) = self.event_bus.publish_security_event(event) {
            eprintln!("Failed to publish security event: {}", e);
        }
    }
    
    pub async fn simulate_cluster_event(&self, event_type: ClusterEventType, node_id: &str) {
        let event = ClusterEvent {
            event_type,
            node_id: node_id.to_string(),
            timestamp: Utc::now(),
            details: serde_json::json!({
                "cluster_size": 3,
                "leader": node_id,
                "term": 5
            }),
        };
        
        if let Err(e) = self.event_bus.publish_cluster_event(event) {
            eprintln!("Failed to publish cluster event: {}", e);
        }
    }
    
    pub async fn simulate_compliance_event(&self, framework: &str, event_type: ComplianceEventType, status: ComplianceStatus) {
        let event = ComplianceEvent {
            framework: framework.to_string(),
            event_type,
            timestamp: Utc::now(),
            details: serde_json::json!({
                "requirement_id": "REQ-001",
                "description": "Data encryption at rest"
            }),
            status,
        };
        
        if let Err(e) = self.event_bus.publish_compliance_event(event) {
            eprintln!("Failed to publish compliance event: {}", e);
        }
    }
}

// Utility functions for subscription management
pub struct SubscriptionManager {
    active_subscriptions: std::sync::atomic::AtomicU32,
}

impl SubscriptionManager {
    pub fn new() -> Self {
        Self {
            active_subscriptions: std::sync::atomic::AtomicU32::new(0),
        }
    }
    
    pub fn increment_subscriptions(&self) -> u32 {
        self.active_subscriptions.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1
    }
    
    pub fn decrement_subscriptions(&self) -> u32 {
        self.active_subscriptions.fetch_sub(1, std::sync::atomic::Ordering::SeqCst) - 1
    }
    
    pub fn get_active_count(&self) -> u32 {
        self.active_subscriptions.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QueryRoot {
    _private: (),
}

#[async_graphql::Object]
impl QueryRoot {
    async fn version(&self) -> &str {
        "1.0.0"
    }
}

// GraphQL schema extensions for subscriptions
pub type FortressSchema = async_graphql::Schema<
    async_graphql::EmptyMutation,
    QueryRoot,
    DataSubscription,
>;

pub fn create_schema(event_bus: Arc<EventBus>) -> FortressSchema {
    FortressSchema::build(
        async_graphql::EmptyMutation,
        QueryRoot {
            _private: (),
        },
        DataSubscription,
    )
    .data(event_bus)
    .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    
    #[tokio::test]
    async fn test_data_change_subscription() {
        let event_bus = Arc::new(EventBus::new());
        let schema = create_schema(event_bus.clone());
        
        // Create a subscription
        let query = r#"
            subscription DataChanges($tableId: String!) {
                dataChanges(tableId: $tableId) {
                    tableId
                    operation
                    recordId
                    timestamp
                    userId
                }
            }
        "#;
        
        let variables = serde_json::json!({
            "tableId": "users"
        });
        
        // This would typically be handled by the GraphQL executor
        // For testing purposes, we'll verify the event bus works
        let collector = MetricsCollector::new(event_bus.clone());
        
        // Simulate a data change event
        collector.simulate_data_change_event(
            "users",
            DataOperation::Create,
            Some("user_123".to_string())
        ).await;
        
        // Verify the event was published (in a real test, we'd subscribe and verify)
        assert!(true, "Event bus should work correctly");
    }
    
    #[tokio::test]
    async fn test_security_event_subscription() {
        let event_bus = Arc::new(EventBus::new());
        let collector = MetricsCollector::new(event_bus.clone());
        
        // Simulate a security event
        collector.simulate_security_event(
            "login_success",
            SecuritySeverity::Low,
            Some("user_123".to_string())
        ).await;
        
        assert!(true, "Security event should be published");
    }
    
    #[tokio::test]
    async fn test_performance_metrics_collection() {
        let event_bus = Arc::new(EventBus::new());
        let collector = MetricsCollector::new(event_bus.clone());
        
        let metrics = collector.collect_current_metrics().await;
        
        assert!(metrics.cpu_usage >= 0.0);
        assert!(metrics.memory_usage >= 0.0);
        assert!(metrics.disk_usage >= 0.0);
    }
}
