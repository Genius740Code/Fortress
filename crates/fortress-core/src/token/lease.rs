//! Lease management for dynamic secrets
//!
//! This module provides lease management functionality for dynamic secrets
//! and other time-limited resources.

use chrono::{DateTime, Utc, Duration, Timelike};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{FortressError, Result, TokenErrorCode};

/// Lease status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum LeaseStatus {
    /// Lease is active
    Active,
    /// Lease has expired
    Expired,
    /// Lease has been revoked
    Revoked,
    /// Lease is in renewal process
    Renewing,
    /// Lease is pending creation
    Pending,
}

/// Lease information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseInfo {
    /// Unique lease identifier
    pub lease_id: String,
    /// Lease status
    pub status: LeaseStatus,
    /// Whether lease is renewable
    pub renewable: bool,
    /// Lease time-to-live
    pub ttl: Duration,
    /// Maximum TTL for this lease
    pub max_ttl: Option<Duration>,
    /// Lease creation timestamp
    pub created_time: DateTime<Utc>,
    /// Lease expiration timestamp
    pub expires_time: DateTime<Utc>,
    /// Last renewal timestamp
    pub last_renewal: Option<DateTime<Utc>>,
    /// Number of times this lease has been renewed
    pub renewal_count: u32,
    /// Maximum number of renewals allowed
    pub max_renewals: Option<u32>,
    /// Resource this lease is for
    pub resource: String,
    /// Entity that owns this lease
    pub entity_id: String,
    /// Token that created this lease
    pub token_id: String,
    /// Lease metadata
    pub metadata: HashMap<String, String>,
    /// Lease capabilities
    pub capabilities: Vec<String>,
}

impl LeaseInfo {
    /// Create a new lease
    pub fn new(
        resource: String,
        entity_id: String,
        token_id: String,
        ttl: Duration,
    ) -> Self {
        let now = Utc::now();
        let lease_id = Uuid::new_v4().to_string();

        Self {
            lease_id,
            status: LeaseStatus::Active,
            renewable: true,
            ttl,
            max_ttl: None,
            created_time: now,
            expires_time: now + ttl,
            last_renewal: None,
            renewal_count: 0,
            max_renewals: Some(10),
            resource,
            entity_id,
            token_id,
            metadata: HashMap::new(),
            capabilities: Vec::new(),
        }
    }

    /// Check if lease is expired
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.expires_time
    }

    /// Check if lease is active
    pub fn is_active(&self) -> bool {
        self.status == LeaseStatus::Active && !self.is_expired()
    }

    /// Check if lease is renewable
    pub fn is_renewable(&self) -> bool {
        if !self.renewable || self.status != LeaseStatus::Active {
            return false;
        }

        if let Some(max_renewals) = self.max_renewals {
            self.renewal_count < max_renewals
        } else {
            true
        }
    }

    /// Get remaining TTL
    pub fn remaining_ttl(&self) -> Duration {
        let now = Utc::now();
        if now > self.expires_time {
            Duration::zero()
        } else {
            self.expires_time - now
        }
    }

    /// Add metadata to lease
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }

    /// Add capability to lease
    pub fn add_capability(&mut self, capability: String) {
        if !self.capabilities.contains(&capability) {
            self.capabilities.push(capability);
        }
    }

    /// Check if lease has capability
    pub fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.contains(&capability.to_string())
    }

    /// Renew the lease
    pub fn renew(&mut self, increment: Duration) -> Result<()> {
        if !self.is_renewable() {
            return Err(FortressError::token_with_id(
                "Lease is not renewable",
                Some(self.lease_id.clone()),
                TokenErrorCode::LeaseRenewalFailed,
            ));
        }

        // Check max TTL constraint
        let new_expires_time = Utc::now() + increment;
        if let Some(max_ttl) = self.max_ttl {
            let max_expires_time = self.created_time + max_ttl;
            if new_expires_time > max_expires_time {
                return Err(FortressError::token_with_id(
                    "Renewal would exceed maximum TTL",
                    Some(self.lease_id.clone()),
                    TokenErrorCode::LeaseRenewalFailed,
                ));
            }
        }

        self.status = LeaseStatus::Active;
        self.expires_time = new_expires_time;
        self.last_renewal = Some(Utc::now());
        self.renewal_count += 1;

        Ok(())
    }

    /// Revoke the lease
    pub fn revoke(&mut self) {
        self.status = LeaseStatus::Revoked;
    }

    /// Mark lease as expired
    pub fn mark_expired(&mut self) {
        self.status = LeaseStatus::Expired;
    }
}

/// Lease manager for handling lease lifecycle
pub struct LeaseManager {
    leases: Arc<RwLock<HashMap<String, LeaseInfo>>>,
    cleanup_interval: Duration,
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseManager {
    /// Create a new lease manager
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            leases: Arc::new(RwLock::new(HashMap::new())),
            cleanup_interval,
            cleanup_task: None,
        }
    }

    /// Create a new lease
    pub async fn create_lease(&mut self, lease_info: LeaseInfo) -> Result<String> {
        let lease_id = lease_info.lease_id.clone();
        
        {
            let mut leases = self.leases.write().await;
            leases.insert(lease_id.clone(), lease_info);
        }

        // Start cleanup task if not already running
        if self.cleanup_task.is_none() {
            self.start_cleanup_task().await;
        }

        Ok(lease_id)
    }

    /// Get lease information
    pub async fn get_lease(&self, lease_id: &str) -> Result<LeaseInfo> {
        let leases = self.leases.read().await;
        leases.get(lease_id)
            .cloned()
            .ok_or_else(|| FortressError::token_with_id(
                "Lease not found",
                Some(lease_id.to_string()),
                TokenErrorCode::LeaseNotFound,
            ))
    }

    /// Renew a lease
    pub async fn renew_lease(&self, lease_id: &str, increment: Duration) -> Result<Duration> {
        let mut leases = self.leases.write().await;
        let lease = leases.get_mut(lease_id)
            .ok_or_else(|| FortressError::token_with_id(
                "Lease not found",
                Some(lease_id.to_string()),
                TokenErrorCode::LeaseNotFound,
            ))?;

        lease.renew(increment)?;
        Ok(lease.ttl)
    }

    /// Revoke a lease
    pub async fn revoke_lease(&self, lease_id: &str) -> Result<()> {
        let mut leases = self.leases.write().await;
        let lease = leases.get_mut(lease_id)
            .ok_or_else(|| FortressError::token_with_id(
                "Lease not found",
                Some(lease_id.to_string()),
                TokenErrorCode::LeaseNotFound,
            ))?;

        lease.revoke();
        Ok(())
    }

    /// List all leases for an entity
    pub async fn list_entity_leases(&self, entity_id: &str) -> Result<Vec<LeaseInfo>> {
        let leases = self.leases.read().await;
        let entity_leases: Vec<LeaseInfo> = leases
            .values()
            .filter(|lease| lease.entity_id == entity_id)
            .cloned()
            .collect();

        Ok(entity_leases)
    }

    /// List all leases for a resource
    pub async fn list_resource_leases(&self, resource: &str) -> Result<Vec<LeaseInfo>> {
        let leases = self.leases.read().await;
        let resource_leases: Vec<LeaseInfo> = leases
            .values()
            .filter(|lease| lease.resource == resource)
            .cloned()
            .collect();

        Ok(resource_leases)
    }

    /// List all active leases
    pub async fn list_active_leases(&self) -> Result<Vec<LeaseInfo>> {
        let leases = self.leases.read().await;
        let active_leases: Vec<LeaseInfo> = leases
            .values()
            .filter(|lease| lease.is_active())
            .cloned()
            .collect();

        Ok(active_leases)
    }

    /// List all expired leases
    pub async fn list_expired_leases(&self) -> Result<Vec<LeaseInfo>> {
        let leases = self.leases.read().await;
        let expired_leases: Vec<LeaseInfo> = leases
            .values()
            .filter(|lease| lease.is_expired())
            .cloned()
            .collect();

        Ok(expired_leases)
    }

    /// Cleanup expired leases
    pub async fn cleanup_expired_leases(&self) -> Result<u64> {
        let mut leases = self.leases.write().await;
        let now = Utc::now();
        
        let mut expired_count = 0;
        let mut expired_lease_ids = Vec::new();

        // Find expired leases
        for (lease_id, lease) in leases.iter() {
            if lease.expires_time < now && lease.status != LeaseStatus::Revoked {
                expired_lease_ids.push(lease_id.clone());
            }
        }

        // Remove expired leases
        for lease_id in expired_lease_ids {
            if let Some(mut lease) = leases.remove(&lease_id) {
                lease.mark_expired();
                expired_count += 1;
            }
        }

        Ok(expired_count)
    }

    /// Get lease statistics
    pub async fn get_lease_statistics(&self) -> Result<LeaseStatistics> {
        let leases = self.leases.read().await;
        
        let mut stats = LeaseStatistics::default();
        
        for lease in leases.values() {
            stats.total_leases += 1;
            
            match lease.status {
                LeaseStatus::Active => {
                    stats.active_leases += 1;
                    if lease.is_expired() {
                        stats.expired_leases += 1;
                    }
                }
                LeaseStatus::Expired => stats.expired_leases += 1,
                LeaseStatus::Revoked => stats.revoked_leases += 1,
                LeaseStatus::Renewing => stats.renewing_leases += 1,
                LeaseStatus::Pending => stats.pending_leases += 1,
            }
            
            if lease.renewable {
                stats.renewable_leases += 1;
            }
        }

        Ok(stats)
    }

    /// Start the cleanup task
    async fn start_cleanup_task(&mut self) {
        let leases = self.leases.clone();
        let interval = self.cleanup_interval;

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(std::time::Duration::from_secs(interval.num_seconds() as u64));
            
            loop {
                interval_timer.tick().await;
                
                // Clean up expired leases
                {
                    let mut leases_guard = leases.write().await;
                    let now = Utc::now();
                    
                    let expired_lease_ids: Vec<String> = leases_guard
                        .iter()
                        .filter(|(_, lease)| lease.expires_time < now && lease.status != LeaseStatus::Revoked)
                        .map(|(id, _)| id.clone())
                        .collect();

                    for lease_id in expired_lease_ids {
                        if let Some(mut lease) = leases_guard.remove(&lease_id) {
                            lease.mark_expired();
                        }
                    }
                }
            }
        });

        self.cleanup_task = Some(task);
    }

    /// Stop the cleanup task
    pub async fn stop_cleanup_task(&mut self) {
        if let Some(task) = self.cleanup_task.take() {
            task.abort();
        }
    }
}

impl Drop for LeaseManager {
    fn drop(&mut self) {
        // The cleanup task will be automatically aborted when dropped
    }
}

/// Lease statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LeaseStatistics {
    /// Total number of leases
    pub total_leases: u64,
    /// Number of active leases
    pub active_leases: u64,
    /// Number of expired leases
    pub expired_leases: u64,
    /// Number of revoked leases
    pub revoked_leases: u64,
    /// Number of renewable leases
    pub renewable_leases: u64,
    /// Number of leases being renewed
    pub renewing_leases: u64,
    /// Number of pending leases
    pub pending_leases: u64,
}

impl LeaseStatistics {
    /// Get percentage of active leases
    pub fn active_percentage(&self) -> f64 {
        if self.total_leases == 0 {
            0.0
        } else {
            (self.active_leases as f64 / self.total_leases as f64) * 100.0
        }
    }

    /// Get percentage of expired leases
    pub fn expired_percentage(&self) -> f64 {
        if self.total_leases == 0 {
            0.0
        } else {
            (self.expired_leases as f64 / self.total_leases as f64) * 100.0
        }
    }
}

/// Lease renewal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewalRequest {
    /// Lease ID to renew
    pub lease_id: String,
    /// TTL increment
    pub increment: Duration,
    /// Requester token ID
    pub requester_token: String,
    /// Request reason
    pub reason: Option<String>,
}

/// Lease renewal response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRenewalResponse {
    /// Whether renewal was successful
    pub success: bool,
    /// New lease information if successful
    pub lease_info: Option<LeaseInfo>,
    /// Error message if failed
    pub error: Option<String>,
    /// Renewal timestamp
    pub renewed_at: DateTime<Utc>,
}

/// Lease revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRevocationRequest {
    /// Lease ID to revoke
    pub lease_id: String,
    /// Requester token ID
    pub requester_token: String,
    /// Revocation reason
    pub reason: String,
    /// Force revocation
    pub force: bool,
}

/// Lease revocation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaseRevocationResponse {
    /// Whether revocation was successful
    pub success: bool,
    /// Revoked lease information
    pub lease_info: Option<LeaseInfo>,
    /// Error message if failed
    pub error: Option<String>,
    /// Revocation timestamp
    pub revoked_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_lease_creation() {
        let lease = LeaseInfo::new(
            "database/creds/mydb".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        assert_eq!(lease.status, LeaseStatus::Active);
        assert!(lease.is_renewable());
        assert!(!lease.is_expired());
        assert_eq!(lease.renewal_count, 0);
    }

    #[tokio::test]
    async fn test_lease_expiration() {
        let mut lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::seconds(1),
        );

        assert!(!lease.is_expired());
        
        // Manually set expiration to past
        lease.expires_time = Utc::now() - Duration::seconds(1);
        assert!(lease.is_expired());
        assert!(!lease.is_active());
    }

    #[tokio::test]
    async fn test_lease_renewal() {
        let mut lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        lease.max_renewals = Some(2);
        
        assert!(lease.is_renewable());
        
        // First renewal
        lease.renew(Duration::minutes(30)).unwrap();
        assert_eq!(lease.renewal_count, 1);
        assert!(lease.last_renewal.is_some());
        
        // Second renewal
        lease.renew(Duration::minutes(30)).unwrap();
        assert_eq!(lease.renewal_count, 2);
        
        // Third renewal should fail
        assert!(lease.renew(Duration::minutes(30)).is_err());
    }

    #[tokio::test]
    async fn test_lease_revocation() {
        let mut lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        assert_eq!(lease.status, LeaseStatus::Active);
        
        lease.revoke();
        assert_eq!(lease.status, LeaseStatus::Revoked);
        assert!(!lease.is_active());
        assert!(!lease.is_renewable());
    }

    #[tokio::test]
    async fn test_lease_metadata() {
        let mut lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        lease.add_metadata("environment".to_string(), "production".to_string());
        lease.add_metadata("region".to_string(), "us-west-2".to_string());

        assert_eq!(lease.get_metadata("environment"), Some(&"production".to_string()));
        assert_eq!(lease.get_metadata("region"), Some(&"us-west-2".to_string()));
        assert_eq!(lease.get_metadata("nonexistent"), None);
    }

    #[tokio::test]
    async fn test_lease_capabilities() {
        let mut lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        lease.add_capability("read".to_string());
        lease.add_capability("write".to_string());
        lease.add_capability("read".to_string()); // Duplicate

        assert!(lease.has_capability("read"));
        assert!(lease.has_capability("write"));
        assert!(!lease.has_capability("delete"));
        assert_eq!(lease.capabilities.len(), 2); // No duplicate
    }

    #[tokio::test]
    async fn test_lease_manager() {
        let lease_manager = LeaseManager::new(Duration::minutes(5));
        
        let lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        let lease_id = lease_manager.create_lease(lease.clone()).await.unwrap();
        
        // Retrieve lease
        let retrieved = lease_manager.get_lease(&lease_id).await.unwrap();
        assert_eq!(retrieved.lease_id, lease.lease_id);
        assert_eq!(retrieved.resource, lease.resource);
        
        // List entity leases
        let entity_leases = lease_manager.list_entity_leases("user123").await.unwrap();
        assert_eq!(entity_leases.len(), 1);
        
        // List resource leases
        let resource_leases = lease_manager.list_resource_leases("resource1").await.unwrap();
        assert_eq!(resource_leases.len(), 1);
        
        // List active leases
        let active_leases = lease_manager.list_active_leases().await.unwrap();
        assert_eq!(active_leases.len(), 1);
    }

    #[tokio::test]
    async fn test_lease_renewal_through_manager() {
        let lease_manager = LeaseManager::new(Duration::minutes(5));
        
        let lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        let lease_id = lease_manager.create_lease(lease).await.unwrap();
        
        // Renew lease
        let new_ttl = lease_manager.renew_lease(&lease_id, Duration::minutes(30)).await.unwrap();
        assert_eq!(new_ttl, Duration::hours(1)); // TTL stays the same
        
        // Verify renewal
        let renewed_lease = lease_manager.get_lease(&lease_id).await.unwrap();
        assert_eq!(renewed_lease.renewal_count, 1);
        assert!(renewed_lease.last_renewal.is_some());
    }

    #[tokio::test]
    async fn test_lease_revocation_through_manager() {
        let lease_manager = LeaseManager::new(Duration::minutes(5));
        
        let lease = LeaseInfo::new(
            "resource1".to_string(),
            "user123".to_string(),
            "token456".to_string(),
            Duration::hours(1),
        );

        let lease_id = lease_manager.create_lease(lease).await.unwrap();
        
        // Revoke lease
        lease_manager.revoke_lease(&lease_id).await.unwrap();
        
        // Verify revocation
        let revoked_lease = lease_manager.get_lease(&lease_id).await.unwrap();
        assert_eq!(revoked_lease.status, LeaseStatus::Revoked);
    }

    #[tokio::test]
    async fn test_lease_statistics() {
        let lease_manager = LeaseManager::new(Duration::minutes(5));
        
        // Create multiple leases
        for i in 0..5 {
            let lease = LeaseInfo::new(
                format!("resource{}", i),
                format!("user{}", i),
                format!("token{}", i),
                Duration::hours(1),
            );
            lease_manager.create_lease(lease).await.unwrap();
        }
        
        // Revoke one lease
        lease_manager.revoke_lease("resource1").await.ok();
        
        // Get statistics
        let stats = lease_manager.get_lease_statistics().await.unwrap();
        assert_eq!(stats.total_leases, 5);
        assert_eq!(stats.active_leases, 4);
        assert_eq!(stats.revoked_leases, 1);
        assert_eq!(stats.renewable_leases, 5);
    }

    #[test]
    fn test_lease_statistics_percentages() {
        let mut stats = LeaseStatistics::default();
        stats.total_leases = 100;
        stats.active_leases = 75;
        stats.expired_leases = 25;
        
        assert_eq!(stats.active_percentage(), 75.0);
        assert_eq!(stats.expired_percentage(), 25.0);
        
        // Edge case: zero total leases
        let empty_stats = LeaseStatistics::default();
        assert_eq!(empty_stats.active_percentage(), 0.0);
        assert_eq!(empty_stats.expired_percentage(), 0.0);
    }
}
