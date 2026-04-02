//! WebSocket subscription system for real-time data updates

use crate::error::{FortressError, Result};
use crate::websocket::message::{WebSocketMessage, MessageType, MessagePayload, DataUpdatePayload, SubscriptionFilter, FilterOperator};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;
use serde::{Serialize, Deserialize};

/// Subscription manager
#[derive(Debug)]
pub struct SubscriptionManager {
    /// Active subscriptions
    subscriptions: Arc<RwLock<HashMap<String, Subscription>>>,
    /// Topic to subscription mapping
    topic_subscriptions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Connection to subscription mapping
    connection_subscriptions: Arc<RwLock<HashMap<String, Vec<String>>>>,
    /// Message sender for subscription events
    event_sender: mpsc::UnboundedSender<SubscriptionEvent>,
    /// Subscription statistics
    stats: Arc<RwLock<SubscriptionStats>>,
}

/// Subscription information
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Unique subscription ID
    pub id: String,
    /// Connection ID
    pub connection_id: String,
    /// Subscription topic
    pub topic: String,
    /// Subscription filters
    pub filters: Vec<SubscriptionFilter>,
    /// Subscription options
    pub options: SubscriptionOptions,
    /// Created at timestamp
    pub created_at: Instant,
    /// Last activity timestamp
    pub last_activity: Instant,
    /// Subscription status
    pub status: SubscriptionStatus,
    /// Message count
    pub message_count: u64,
    /// Last message timestamp
    pub last_message_at: Option<Instant>,
}

/// Subscription options
#[derive(Debug, Clone)]
pub struct SubscriptionOptions {
    /// Enable compression
    pub compression: bool,
    /// Batch updates
    pub batch_updates: bool,
    /// Batch size
    pub batch_size: Option<usize>,
    /// Batch interval in milliseconds
    pub batch_interval_ms: Option<u64>,
    /// Enable history
    pub enable_history: bool,
    /// History limit
    pub history_limit: Option<usize>,
}

/// Subscription status
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SubscriptionStatus {
    /// Active
    Active,
    /// Paused
    Paused,
    /// Error
    Error,
    /// Closed
    Closed,
}

/// Subscription event
#[derive(Debug, Clone)]
pub enum SubscriptionEvent {
    /// New subscription created
    Created { subscription: Subscription },
    /// Subscription updated
    Updated { subscription_id: String, changes: HashMap<String, String> },
    /// Subscription cancelled
    Cancelled { subscription_id: String, reason: String },
    /// Message to be sent to subscribers
    Message { topic: String, message: WebSocketMessage, exclude_connections: Vec<String> },
}

/// Subscription statistics
#[derive(Debug, Default, Clone)]
pub struct SubscriptionStats {
    /// Total subscriptions created
    pub total_subscriptions: u64,
    /// Active subscriptions
    pub active_subscriptions: usize,
    /// Peak concurrent subscriptions
    pub peak_subscriptions: usize,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total topics
    pub total_topics: usize,
    /// Messages per topic
    pub messages_per_topic: HashMap<String, u64>,
}

impl SubscriptionManager {
    /// Create new subscription manager
    pub fn new() -> Self {
        let (event_sender, _) = mpsc::unbounded_channel();
        
        Self {
            subscriptions: Arc::new(RwLock::new(HashMap::new())),
            topic_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            connection_subscriptions: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            stats: Arc::new(RwLock::new(SubscriptionStats::default())),
        }
    }

    /// Create new subscription
    pub async fn subscribe(
        &self,
        connection_id: String,
        topic: String,
        filters: Vec<SubscriptionFilter>,
        options: SubscriptionOptions,
    ) -> Result<String> {
        let subscription_id = Uuid::new_v4().to_string();
        
        // Create subscription
        let subscription = Subscription {
            id: subscription_id.clone(),
            connection_id: connection_id.clone(),
            topic: topic.clone(),
            filters,
            options,
            created_at: Instant::now(),
            last_activity: Instant::now(),
            status: SubscriptionStatus::Active,
            message_count: 0,
            last_message_at: None,
        };

        // Add to subscriptions
        {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.insert(subscription_id.clone(), subscription.clone());
        }

        // Update topic mapping
        {
            let mut topic_subscriptions = self.topic_subscriptions.write().await;
            topic_subscriptions.entry(topic.clone()).or_insert_with(Vec::new).push(subscription_id.clone());
        }

        // Update connection mapping
        {
            let mut connection_subscriptions = self.connection_subscriptions.write().await;
            connection_subscriptions.entry(connection_id.clone()).or_insert_with(Vec::new).push(subscription_id.clone());
        }

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.total_subscriptions += 1;
            stats.active_subscriptions += 1;
            if stats.active_subscriptions > stats.peak_subscriptions {
                stats.peak_subscriptions = stats.active_subscriptions;
            }
            
            if !stats.messages_per_topic.contains_key(&topic) {
                stats.total_topics += 1;
            }
        }

        // Send event
        tracing::info!("Created subscription {} for topic {} on connection {}", subscription_id, topic, connection_id);
        let event = SubscriptionEvent::Created { subscription };
        let _ = self.event_sender.send(event);
        Ok(subscription_id)
    }

    /// Cancel subscription
    pub async fn unsubscribe(&self, subscription_id: &str) -> Result<()> {
        let subscription = {
            let mut subscriptions = self.subscriptions.write().await;
            subscriptions.remove(subscription_id)
        };

        if let Some(sub) = subscription {
            // Remove from topic mapping
            {
                let mut topic_subscriptions = self.topic_subscriptions.write().await;
                if let Some(subscriptions) = topic_subscriptions.get_mut(&sub.topic) {
                    subscriptions.retain(|id| id != subscription_id);
                    if subscriptions.is_empty() {
                        topic_subscriptions.remove(&sub.topic);
                    }
                }
            }

            // Remove from connection mapping
            {
                let mut connection_subscriptions = self.connection_subscriptions.write().await;
                if let Some(subscriptions) = connection_subscriptions.get_mut(&sub.connection_id) {
                    subscriptions.retain(|id| id != subscription_id);
                    if subscriptions.is_empty() {
                        connection_subscriptions.remove(&sub.connection_id);
                    }
                }
            }

            // Update statistics
            {
                let mut stats = self.stats.write().await;
                if stats.active_subscriptions > 0 {
                    stats.active_subscriptions -= 1;
                }
            }

            // Send event
            let event = SubscriptionEvent::Cancelled {
                subscription_id: subscription_id.to_string(),
                reason: "Client requested unsubscribe".to_string(),
            };
            let _ = self.event_sender.send(event);

            tracing::info!("Cancelled subscription {} for topic {}", subscription_id, sub.topic);
        } else {
            return Err(FortressError::websocket(format!("Subscription {} not found", subscription_id)));
        }

        Ok(())
    }

    /// Cancel all subscriptions for a connection
    pub async fn unsubscribe_all(&self, connection_id: &str) -> Result<()> {
        let subscription_ids: Vec<String> = {
            let connection_subscriptions = self.connection_subscriptions.read().await;
            connection_subscriptions.get(connection_id).cloned().unwrap_or_default()
        };

        for subscription_id in subscription_ids {
            let _ = self.unsubscribe(&subscription_id).await;
        }

        Ok(())
    }

    /// Publish message to topic subscribers
    pub async fn publish(&self, topic: &str, data: serde_json::Value, metadata: HashMap<String, String>) -> Result<()> {
        let message = WebSocketMessage::new(
            MessageType::DataUpdate,
            MessagePayload::DataUpdate(DataUpdatePayload {
                topic: topic.to_string(),
                data,
                metadata,
                version: None,
            }),
        );

        // Get subscriptions for topic
        let subscription_ids: Vec<String> = {
            let topic_subscriptions = self.topic_subscriptions.read().await;
            topic_subscriptions.get(topic).cloned().unwrap_or_default()
        };

        // Filter active subscriptions and apply filters
        let matching_subscriptions: Vec<String> = {
            let subscriptions = self.subscriptions.read().await;
            subscription_ids.clone().into_iter().filter(|sub_id| {
                if let Some(subscription) = subscriptions.get(sub_id) {
                    subscription.status == SubscriptionStatus::Active && self.matches_filters(&subscription, &message)
                } else {
                    false
                }
            }).collect()
        };

        // Get connections to exclude (those not matching)
        let exclude_connections: Vec<String> = {
            let subscriptions = self.subscriptions.read().await;
            subscription_ids.clone().into_iter().filter(|sub_id| {
                if let Some(subscription) = subscriptions.get(sub_id) {
                    subscription.status != SubscriptionStatus::Active || !self.matches_filters(&subscription, &message)
                } else {
                    false
                }
            }).map(|sub_id| {
                if let Some(subscription) = subscriptions.get(&sub_id) {
                    subscription.connection_id.clone()
                } else {
                    String::new()
                }
            }).collect()
        };

        // Send event
        let event = SubscriptionEvent::Message {
            topic: topic.to_string(),
            message,
            exclude_connections,
        };
        let _ = self.event_sender.send(event);

        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.messages_sent += matching_subscriptions.len() as u64;
            *stats.messages_per_topic.entry(topic.to_string()).or_insert(0) += matching_subscriptions.len() as u64;
        }

        // Update subscription activity
        {
            let mut subscriptions = self.subscriptions.write().await;
            for subscription_id in &matching_subscriptions {
                if let Some(subscription) = subscriptions.get_mut(subscription_id) {
                    subscription.last_activity = Instant::now();
                    subscription.message_count += 1;
                    subscription.last_message_at = Some(Instant::now());
                }
            }
        }

        Ok(())
    }

    /// Check if message matches subscription filters
    fn matches_filters(&self, subscription: &Subscription, message: &WebSocketMessage) -> bool {
        if subscription.filters.is_empty() {
            return true;
        }

        if let MessagePayload::DataUpdate(data_update) = &message.payload {
            for filter in &subscription.filters {
                if !self.matches_filter(filter, data_update) {
                    return false;
                }
            }
        }

        true
    }

    /// Check if data update matches a single filter
    fn matches_filter(&self, filter: &SubscriptionFilter, data_update: &DataUpdatePayload) -> bool {
        let field_value = self.extract_field_value(&filter.field, data_update);
        
        match filter.operator {
            FilterOperator::Equals => field_value == filter.value,
            FilterOperator::NotEquals => field_value != filter.value,
            FilterOperator::GreaterThan => self.compare_values(&field_value, &filter.value, std::cmp::Ordering::Greater),
            FilterOperator::LessThan => self.compare_values(&field_value, &filter.value, std::cmp::Ordering::Less),
            FilterOperator::Contains => self.contains_value(&field_value, &filter.value),
            FilterOperator::In => self.is_in_array(&field_value, &filter.value),
            FilterOperator::NotIn => !self.is_in_array(&field_value, &filter.value),
        }
    }

    /// Extract field value from data update
    fn extract_field_value(&self, field: &str, data_update: &DataUpdatePayload) -> serde_json::Value {
        // Check metadata first
        if let Some(value) = data_update.metadata.get(field) {
            return serde_json::Value::String(value.clone());
        }

        // Check data fields
        if let serde_json::Value::Object(map) = &data_update.data {
            if let Some(value) = map.get(field) {
                return value.clone();
            }
        }

        serde_json::Value::Null
    }

    /// Compare two values for greater/less than
    fn compare_values(&self, a: &serde_json::Value, b: &serde_json::Value, ordering: std::cmp::Ordering) -> bool {
        match (a, b) {
            (serde_json::Value::Number(a_num), serde_json::Value::Number(b_num)) => {
                match (a_num.as_f64(), b_num.as_f64()) {
                    (Some(a_val), Some(b_val)) => a_val.partial_cmp(&b_val) == Some(ordering),
                    _ => false,
                }
            }
            (serde_json::Value::String(a_str), serde_json::Value::String(b_str)) => {
                a_str.cmp(b_str) == ordering
            }
            _ => false,
        }
    }

    /// Check if field contains value
    fn contains_value(&self, field_value: &serde_json::Value, filter_value: &serde_json::Value) -> bool {
        match (field_value, filter_value) {
            (serde_json::Value::String(field_str), serde_json::Value::String(filter_str)) => {
                field_str.contains(filter_str)
            }
            _ => false,
        }
    }

    /// Check if value is in array
    fn is_in_array(&self, field_value: &serde_json::Value, filter_value: &serde_json::Value) -> bool {
        if let serde_json::Value::Array(array) = filter_value {
            array.contains(field_value)
        } else {
            false
        }
    }

    /// Get subscription by ID
    pub async fn get_subscription(&self, subscription_id: &str) -> Option<Subscription> {
        self.subscriptions.read().await.get(subscription_id).cloned()
    }

    /// Get subscriptions for connection
    pub async fn get_connection_subscriptions(&self, connection_id: &str) -> Vec<Subscription> {
        let subscription_ids: Vec<String> = {
            let connection_subscriptions = self.connection_subscriptions.read().await;
            connection_subscriptions.get(connection_id).cloned().unwrap_or_default()
        };

        let subscriptions = self.subscriptions.read().await;
        subscription_ids.into_iter().filter_map(|id| subscriptions.get(&id).cloned()).collect()
    }

    /// Get subscriptions for topic
    pub async fn get_topic_subscriptions(&self, topic: &str) -> Vec<Subscription> {
        let subscription_ids: Vec<String> = {
            let topic_subscriptions = self.topic_subscriptions.read().await;
            topic_subscriptions.get(topic).cloned().unwrap_or_default()
        };

        let subscriptions = self.subscriptions.read().await;
        subscription_ids.into_iter().filter_map(|id| subscriptions.get(&id).cloned()).collect()
    }

    /// Get all subscriptions
    pub async fn get_all_subscriptions(&self) -> Vec<Subscription> {
        self.subscriptions.read().await.values().cloned().collect()
    }

    /// Get subscription statistics
    pub async fn get_stats(&self) -> SubscriptionStats {
        self.stats.read().await.clone()
    }

    /// Start event processor
    pub async fn start_event_processor(&self) -> mpsc::UnboundedReceiver<SubscriptionEvent> {
        let (sender, receiver) = mpsc::unbounded_channel();
        
        // Note: In a real implementation, we'd replace the internal sender
        // For now, we'll return a new receiver
        
        receiver
    }

    /// Clean up expired subscriptions
    pub async fn cleanup_expired_subscriptions(&self, timeout: Duration) {
        let now = Instant::now();
        let expired_subscriptions: Vec<String> = {
            let subscriptions = self.subscriptions.read().await;
            subscriptions
                .iter()
                .filter(|(_, sub)| now.duration_since(sub.last_activity) > timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for subscription_id in expired_subscriptions {
            let _ = self.unsubscribe(&subscription_id).await;
        }
    }
}

impl Default for SubscriptionOptions {
    fn default() -> Self {
        Self {
            compression: true,
            batch_updates: false,
            batch_size: None,
            batch_interval_ms: None,
            enable_history: false,
            history_limit: None,
        }
    }
}
