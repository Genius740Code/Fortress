//! Token revocation management
//!
//! This module provides token revocation functionality including revocation lists,
//! revocation reasons, and revocation propagation.

use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::error::{FortressError, Result, TokenErrorCode};

/// Revocation reason enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// Token expired
    Expired,
    /// Token compromised
    Compromised,
    /// User requested revocation
    UserRequest,
    /// Administrative action
    Administrative,
    /// Security policy violation
    SecurityViolation,
    /// Entity disabled/deleted
    EntityDisabled,
    /// Token limit exceeded
    LimitExceeded,
    /// System maintenance
    Maintenance,
    /// Custom reason
    Custom(String),
}

impl RevocationReason {
    /// Get the display name for the reason
    pub fn display_name(&self) -> &str {
        match self {
            RevocationReason::Expired => "Expired",
            RevocationReason::Compromised => "Compromised",
            RevocationReason::UserRequest => "User Request",
            RevocationReason::Administrative => "Administrative",
            RevocationReason::SecurityViolation => "Security Violation",
            RevocationReason::EntityDisabled => "Entity Disabled",
            RevocationReason::LimitExceeded => "Limit Exceeded",
            RevocationReason::Maintenance => "Maintenance",
            RevocationReason::Custom(reason) => reason,
        }
    }

    /// Check if this is a security-related revocation
    pub fn is_security_related(&self) -> bool {
        matches!(
            self,
            RevocationReason::Compromised
                | RevocationReason::SecurityViolation
                | RevocationReason::EntityDisabled
        )
    }
}

/// Revocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// Unique revocation ID
    pub revocation_id: String,
    /// Token ID that was revoked
    pub token_id: String,
    /// Revocation reason
    pub reason: RevocationReason,
    /// When the revocation occurred
    pub revoked_at: DateTime<Utc>,
    /// Who performed the revocation
    pub revoked_by: String,
    /// Additional notes
    pub notes: Option<String>,
    /// Whether this was an emergency revocation
    pub emergency: bool,
    /// IP address from which revocation was performed
    pub source_ip: Option<String>,
    /// User agent used for revocation
    pub user_agent: Option<String>,
}

impl RevocationEntry {
    /// Create a new revocation entry
    pub fn new(token_id: String, reason: RevocationReason, revoked_by: String) -> Self {
        Self {
            revocation_id: Uuid::new_v4().to_string(),
            token_id,
            reason: reason.clone(),
            revoked_at: Utc::now(),
            revoked_by,
            notes: None,
            emergency: reason.is_security_related(),
            source_ip: None,
            user_agent: None,
        }
    }

    /// Add notes to the revocation entry
    pub fn with_notes(mut self, notes: String) -> Self {
        self.notes = Some(notes);
        self
    }

    /// Set source IP
    pub fn with_source_ip(mut self, ip: String) -> Self {
        self.source_ip = Some(ip);
        self
    }

    /// Set user agent
    pub fn with_user_agent(mut self, user_agent: String) -> Self {
        self.user_agent = Some(user_agent);
        self
    }

    /// Mark as emergency revocation
    pub fn as_emergency(mut self) -> Self {
        self.emergency = true;
        self
    }
}

/// Revocation list for tracking revoked tokens
pub struct RevocationList {
    /// Set of revoked token IDs
    revoked_tokens: Arc<RwLock<HashSet<String>>>,
    /// Revocation entries with metadata
    revocation_entries: Arc<RwLock<HashMap<String, RevocationEntry>>>,
    /// Reason-based index
    reason_index: Arc<RwLock<HashMap<RevocationReason, HashSet<String>>>>,
    /// Time-based index (revoked after timestamp)
    time_index: Arc<RwLock<HashMap<DateTime<Utc>, HashSet<String>>>>,
    /// Entity-based index
    entity_index: Arc<RwLock<HashMap<String, HashSet<String>>>>,
}

impl RevocationList {
    /// Create a new revocation list
    pub fn new() -> Self {
        Self {
            revoked_tokens: Arc::new(RwLock::new(HashSet::new())),
            revocation_entries: Arc::new(RwLock::new(HashMap::new())),
            reason_index: Arc::new(RwLock::new(HashMap::new())),
            time_index: Arc::new(RwLock::new(HashMap::new())),
            entity_index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a token to the revocation list
    pub async fn revoke_token(&self, entry: RevocationEntry) -> Result<()> {
        let token_id = entry.token_id.clone();
        let reason = entry.reason.clone();
        let revoked_at = entry.revoked_at;
        let revoked_by = entry.revoked_by.clone();

        // Add to main revocation set
        {
            let mut revoked_tokens = self.revoked_tokens.write().await;
            revoked_tokens.insert(token_id.clone());
        }

        // Add to entries
        {
            let mut entries = self.revocation_entries.write().await;
            entries.insert(token_id.clone(), entry.clone());
        }

        // Update reason index
        {
            let mut reason_index = self.reason_index.write().await;
            reason_index
                .entry(reason.clone())
                .or_insert_with(HashSet::new)
                .insert(token_id.clone());
        }

        // Update time index (group by hour for efficiency)
        {
            let hour_key = revoked_at
                .with_minute(0)
                .and_then(|dt| dt.with_second(0))
                .and_then(|dt| dt.with_nanosecond(0))
                .unwrap();
            let mut time_index = self.time_index.write().await;
            time_index
                .entry(hour_key)
                .or_insert_with(HashSet::new)
                .insert(token_id.clone());
        }

        // Update entity index
        {
            let mut entity_index = self.entity_index.write().await;
            entity_index
                .entry(revoked_by)
                .or_insert_with(HashSet::new)
                .insert(token_id.clone());
        }

        Ok(())
    }

    /// Check if a token is revoked
    pub async fn is_revoked(&self, token_id: &str) -> bool {
        let revoked_tokens = self.revoked_tokens.read().await;
        revoked_tokens.contains(token_id)
    }

    /// Get revocation entry for a token
    pub async fn get_revocation_entry(&self, token_id: &str) -> Option<RevocationEntry> {
        let entries = self.revocation_entries.read().await;
        entries.get(token_id).cloned()
    }

    /// Get all revoked tokens
    pub async fn get_all_revoked_tokens(&self) -> Vec<String> {
        let revoked_tokens = self.revoked_tokens.read().await;
        revoked_tokens.iter().cloned().collect()
    }

    /// Get tokens revoked by reason
    pub async fn get_tokens_by_reason(&self, reason: &RevocationReason) -> Vec<String> {
        let reason_index = self.reason_index.read().await;
        reason_index
            .get(reason)
            .map(|tokens| tokens.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get tokens revoked after a specific time
    pub async fn get_tokens_revoked_after(&self, after: DateTime<Utc>) -> Vec<String> {
        let entries = self.revocation_entries.read().await;
        entries
            .values()
            .filter(|entry| entry.revoked_at > after)
            .map(|entry| entry.token_id.clone())
            .collect()
    }

    /// Get tokens revoked by a specific entity
    pub async fn get_tokens_revoked_by(&self, revoked_by: &str) -> Vec<String> {
        let entity_index = self.entity_index.read().await;
        entity_index
            .get(revoked_by)
            .map(|tokens| tokens.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get emergency revocations
    pub async fn get_emergency_revocations(&self) -> Vec<RevocationEntry> {
        let entries = self.revocation_entries.read().await;
        entries
            .values()
            .filter(|entry| entry.emergency)
            .cloned()
            .collect()
    }

    /// Get security-related revocations
    pub async fn get_security_revocations(&self) -> Vec<RevocationEntry> {
        let entries = self.revocation_entries.read().await;
        entries
            .values()
            .filter(|entry| entry.reason.is_security_related())
            .cloned()
            .collect()
    }

    /// Remove a token from the revocation list (undo revocation)
    pub async fn undo_revocation(&self, token_id: &str) -> Result<RevocationEntry> {
        // Get the entry before removing
        let entry = {
            let entries = self.revocation_entries.read().await;
            entries.get(token_id).cloned()
        };

        if let Some(entry) = entry {
            let reason = entry.reason.clone();
            let revoked_at = entry.revoked_at;
            let revoked_by = entry.revoked_by.clone();

            // Remove from main set
            {
                let mut revoked_tokens = self.revoked_tokens.write().await;
                revoked_tokens.remove(token_id);
            }

            // Remove from entries
            {
                let mut entries = self.revocation_entries.write().await;
                entries.remove(token_id);
            }

            // Update reason index
            {
                let mut reason_index = self.reason_index.write().await;
                if let Some(tokens) = reason_index.get_mut(&reason) {
                    tokens.remove(token_id);
                    if tokens.is_empty() {
                        reason_index.remove(&reason);
                    }
                }
            }

            // Update time index
            {
                let hour_key = revoked_at
                    .with_minute(0)
                    .and_then(|dt| dt.with_second(0))
                    .and_then(|dt| dt.with_nanosecond(0))
                    .unwrap();
                let mut time_index = self.time_index.write().await;
                if let Some(tokens) = time_index.get_mut(&hour_key) {
                    tokens.remove(token_id);
                    if tokens.is_empty() {
                        time_index.remove(&hour_key);
                    }
                }
            }

            // Update entity index
            {
                let mut entity_index = self.entity_index.write().await;
                if let Some(tokens) = entity_index.get_mut(&revoked_by) {
                    tokens.remove(token_id);
                    if tokens.is_empty() {
                        entity_index.remove(&revoked_by);
                    }
                }
            }

            Ok(entry)
        } else {
            Err(FortressError::token_with_id(
                "Token not found in revocation list",
                Some(token_id.to_string()),
                TokenErrorCode::TokenNotFound,
            ))
        }
    }

    /// Clear old revocations (cleanup)
    pub async fn cleanup_old_revocations(&self, older_than: DateTime<Utc>) -> Result<u64> {
        let entries = self.revocation_entries.read().await;
        let old_token_ids: Vec<String> = entries
            .values()
            .filter(|entry| entry.revoked_at < older_than)
            .map(|entry| entry.token_id.clone())
            .collect();

        let mut removed_count = 0;
        for token_id in old_token_ids {
            self.undo_revocation(&token_id).await?;
            removed_count += 1;
        }

        Ok(removed_count)
    }

    /// Get revocation statistics
    pub async fn get_statistics(&self) -> RevocationStatistics {
        let entries = self.revocation_entries.read().await;
        let mut stats = RevocationStatistics::default();

        for entry in entries.values() {
            stats.total_revocations += 1;

            match entry.reason {
                RevocationReason::Expired => stats.expired_revocations += 1,
                RevocationReason::Compromised => stats.compromised_revocations += 1,
                RevocationReason::UserRequest => stats.user_request_revocations += 1,
                RevocationReason::Administrative => stats.administrative_revocations += 1,
                RevocationReason::SecurityViolation => stats.security_violation_revocations += 1,
                RevocationReason::EntityDisabled => stats.entity_disabled_revocations += 1,
                RevocationReason::LimitExceeded => stats.limit_exceeded_revocations += 1,
                RevocationReason::Maintenance => stats.maintenance_revocations += 1,
                RevocationReason::Custom(_) => stats.custom_revocations += 1,
            }

            if entry.emergency {
                stats.emergency_revocations += 1;
            }

            if entry.reason.is_security_related() {
                stats.security_related_revocations += 1;
            }
        }

        stats
    }

    /// Export revocation list
    pub async fn export(&self) -> RevocationExport {
        let entries = self.revocation_entries.read().await;
        let revoked_tokens = self.revoked_tokens.read().await;

        RevocationExport {
            entries: entries.values().cloned().collect(),
            revoked_tokens: revoked_tokens.iter().cloned().collect(),
            exported_at: Utc::now(),
        }
    }

    /// Import revocation list
    pub async fn import(&self, export: RevocationExport) -> Result<u64> {
        let mut imported_count = 0;

        for entry in export.entries {
            self.revoke_token(entry).await?;
            imported_count += 1;
        }

        Ok(imported_count)
    }
}

impl Default for RevocationList {
    fn default() -> Self {
        Self::new()
    }
}

/// Revocation statistics
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RevocationStatistics {
    /// Total number of revocations
    pub total_revocations: u64,
    /// Revocations due to expiration
    pub expired_revocations: u64,
    /// Revocations due to compromise
    pub compromised_revocations: u64,
    /// Revocations due to user request
    pub user_request_revocations: u64,
    /// Revocations due to administrative action
    pub administrative_revocations: u64,
    /// Revocations due to security violations
    pub security_violation_revocations: u64,
    /// Revocations due to entity being disabled
    pub entity_disabled_revocations: u64,
    /// Revocations due to limit exceeded
    pub limit_exceeded_revocations: u64,
    /// Revocations due to maintenance
    pub maintenance_revocations: u64,
    /// Revocations with custom reasons
    pub custom_revocations: u64,
    /// Emergency revocations
    pub emergency_revocations: u64,
    /// Security-related revocations
    pub security_related_revocations: u64,
}

impl RevocationStatistics {
    /// Get percentage of emergency revocations
    pub fn emergency_percentage(&self) -> f64 {
        if self.total_revocations == 0 {
            0.0
        } else {
            (self.emergency_revocations as f64 / self.total_revocations as f64) * 100.0
        }
    }

    /// Get percentage of security-related revocations
    pub fn security_related_percentage(&self) -> f64 {
        if self.total_revocations == 0 {
            0.0
        } else {
            (self.security_related_revocations as f64 / self.total_revocations as f64) * 100.0
        }
    }
}

/// Revocation list export format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationExport {
    /// All revocation entries
    pub entries: Vec<RevocationEntry>,
    /// Set of revoked token IDs for quick lookup
    pub revoked_tokens: HashSet<String>,
    /// Export timestamp
    pub exported_at: DateTime<Utc>,
}

/// Bulk revocation request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRevocationRequest {
    /// List of token IDs to revoke
    pub token_ids: Vec<String>,
    /// Revocation reason
    pub reason: RevocationReason,
    /// Who is performing the revocation
    pub revoked_by: String,
    /// Common notes for all revocations
    pub notes: Option<String>,
    /// Whether this is an emergency bulk revocation
    pub emergency: bool,
    /// Source IP
    pub source_ip: Option<String>,
    /// User agent
    pub user_agent: Option<String>,
}

/// Bulk revocation response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkRevocationResponse {
    /// Number of successfully revoked tokens
    pub successful_count: u64,
    /// Number of failed revocations
    pub failed_count: u64,
    /// List of failed token IDs with reasons
    pub failures: Vec<RevocationFailure>,
    /// Bulk revocation timestamp
    pub revoked_at: DateTime<Utc>,
}

/// Revocation failure information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationFailure {
    /// Token ID that failed to revoke
    pub token_id: String,
    /// Failure reason
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_test;

    #[tokio::test]
    async fn test_revocation_entry_creation() {
        let entry = RevocationEntry::new(
            "token123".to_string(),
            RevocationReason::Compromised,
            "admin".to_string(),
        )
        .with_notes("Suspicious activity detected".to_string())
        .with_source_ip("192.168.1.1".to_string())
        .as_emergency();

        assert_eq!(entry.token_id, "token123");
        assert_eq!(entry.reason, RevocationReason::Compromised);
        assert_eq!(entry.revoked_by, "admin");
        assert_eq!(
            entry.notes,
            Some("Suspicious activity detected".to_string())
        );
        assert_eq!(entry.source_ip, Some("192.168.1.1".to_string()));
        assert!(entry.emergency);
    }

    #[tokio::test]
    async fn test_revocation_reasons() {
        assert_eq!(RevocationReason::Expired.display_name(), "Expired");
        assert_eq!(RevocationReason::Compromised.display_name(), "Compromised");
        assert_eq!(
            RevocationReason::Custom("Other".to_string()).display_name(),
            "Other"
        );

        assert!(RevocationReason::Compromised.is_security_related());
        assert!(RevocationReason::SecurityViolation.is_security_related());
        assert!(RevocationReason::EntityDisabled.is_security_related());
        assert!(!RevocationReason::Expired.is_security_related());
        assert!(!RevocationReason::UserRequest.is_security_related());
    }

    #[tokio::test]
    async fn test_revocation_list_basic_operations() {
        let revocation_list = RevocationList::new();

        // Initially empty
        assert!(!revocation_list.is_revoked("token1").await);
        assert_eq!(revocation_list.get_all_revoked_tokens().await.len(), 0);

        // Add revocation
        let entry = RevocationEntry::new(
            "token1".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        revocation_list.revoke_token(entry).await.unwrap();

        // Check revocation
        assert!(revocation_list.is_revoked("token1").await);
        assert_eq!(revocation_list.get_all_revoked_tokens().await.len(), 1);

        // Get entry
        let retrieved_entry = revocation_list.get_revocation_entry("token1").await;
        assert!(retrieved_entry.is_some());
        assert_eq!(retrieved_entry.unwrap().token_id, "token1");
    }

    #[tokio::test]
    async fn test_revocation_list_indexing() {
        let revocation_list = RevocationList::new();

        // Add multiple revocations with different reasons
        let entry1 = RevocationEntry::new(
            "token1".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        let entry2 = RevocationEntry::new(
            "token2".to_string(),
            RevocationReason::Compromised,
            "admin".to_string(),
        );
        let entry3 = RevocationEntry::new(
            "token3".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );

        revocation_list.revoke_token(entry1).await.unwrap();
        revocation_list.revoke_token(entry2).await.unwrap();
        revocation_list.revoke_token(entry3).await.unwrap();

        // Test reason index
        let expired_tokens = revocation_list
            .get_tokens_by_reason(&RevocationReason::Expired)
            .await;
        assert_eq!(expired_tokens.len(), 2);
        assert!(expired_tokens.contains(&"token1".to_string()));
        assert!(expired_tokens.contains(&"token3".to_string()));

        let compromised_tokens = revocation_list
            .get_tokens_by_reason(&RevocationReason::Compromised)
            .await;
        assert_eq!(compromised_tokens.len(), 1);
        assert!(compromised_tokens.contains(&"token2".to_string()));

        // Test entity index
        let system_revoked = revocation_list.get_tokens_revoked_by("system").await;
        assert_eq!(system_revoked.len(), 2);

        let admin_revoked = revocation_list.get_tokens_revoked_by("admin").await;
        assert_eq!(admin_revoked.len(), 1);
    }

    #[tokio::test]
    async fn test_emergency_and_security_revocations() {
        let revocation_list = RevocationList::new();

        // Add various revocations
        let expired_entry = RevocationEntry::new(
            "token1".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        let compromised_entry = RevocationEntry::new(
            "token2".to_string(),
            RevocationReason::Compromised,
            "admin".to_string(),
        );
        let security_violation_entry = RevocationEntry::new(
            "token3".to_string(),
            RevocationReason::SecurityViolation,
            "admin".to_string(),
        );

        revocation_list.revoke_token(expired_entry).await.unwrap();
        revocation_list
            .revoke_token(compromised_entry)
            .await
            .unwrap();
        revocation_list
            .revoke_token(security_violation_entry)
            .await
            .unwrap();

        // Test emergency revocations
        let emergency_revocations = revocation_list.get_emergency_revocations().await;
        assert_eq!(emergency_revocations.len(), 2); // Compromised and SecurityViolation

        // Test security-related revocations
        let security_revocations = revocation_list.get_security_revocations().await;
        assert_eq!(security_revocations.len(), 2); // Compromised and SecurityViolation
    }

    #[tokio::test]
    async fn test_undo_revocation() {
        let revocation_list = RevocationList::new();

        // Add revocation
        let entry = RevocationEntry::new(
            "token1".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        revocation_list.revoke_token(entry.clone()).await.unwrap();

        // Verify it's revoked
        assert!(revocation_list.is_revoked("token1").await);

        // Undo revocation
        let undone_entry = revocation_list.undo_revocation("token1").await.unwrap();
        assert_eq!(undone_entry.token_id, "token1");

        // Verify it's no longer revoked
        assert!(!revocation_list.is_revoked("token1").await);

        // Try to undo again (should fail)
        assert!(revocation_list.undo_revocation("token1").await.is_err());
    }

    #[tokio::test]
    async fn test_revocation_statistics() {
        let revocation_list = RevocationList::new();

        // Add various revocations
        let reasons = vec![
            RevocationReason::Expired,
            RevocationReason::Compromised,
            RevocationReason::UserRequest,
            RevocationReason::Administrative,
            RevocationReason::SecurityViolation,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let entry = RevocationEntry::new(
                format!("token{}", i + 1),
                reason.clone(),
                "admin".to_string(),
            );
            revocation_list.revoke_token(entry).await.unwrap();
        }

        // Get statistics
        let stats = revocation_list.get_statistics().await;
        assert_eq!(stats.total_revocations, 5);
        assert_eq!(stats.expired_revocations, 1);
        assert_eq!(stats.compromised_revocations, 1);
        assert_eq!(stats.user_request_revocations, 1);
        assert_eq!(stats.administrative_revocations, 1);
        assert_eq!(stats.security_violation_revocations, 1);
        assert_eq!(stats.emergency_revocations, 2); // Compromised + SecurityViolation
        assert_eq!(stats.security_related_revocations, 2); // Compromised + SecurityViolation
    }

    #[tokio::test]
    async fn test_revocation_export_import() {
        let revocation_list1 = RevocationList::new();
        let revocation_list2 = RevocationList::new();

        // Add revocations to first list
        let entry = RevocationEntry::new(
            "token1".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        revocation_list1.revoke_token(entry).await.unwrap();

        // Export from first list
        let export = revocation_list1.export().await;
        assert_eq!(export.entries.len(), 1);
        assert_eq!(export.revoked_tokens.len(), 1);

        // Import to second list
        let imported_count = revocation_list2.import(export).await.unwrap();
        assert_eq!(imported_count, 1);

        // Verify import
        assert!(revocation_list2.is_revoked("token1").await);
        let imported_entry = revocation_list2.get_revocation_entry("token1").await;
        assert!(imported_entry.is_some());
    }

    #[tokio::test]
    async fn test_cleanup_old_revocations() {
        let revocation_list = RevocationList::new();

        // Add an old revocation
        let old_entry = RevocationEntry::new(
            "old_token".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );

        // Manually set old timestamp
        let mut old_entry = old_entry;
        old_entry.revoked_at = Utc::now() - chrono::Duration::days(30);

        revocation_list.revoke_token(old_entry).await.unwrap();

        // Add a recent revocation
        let recent_entry = RevocationEntry::new(
            "recent_token".to_string(),
            RevocationReason::Expired,
            "system".to_string(),
        );
        revocation_list.revoke_token(recent_entry).await.unwrap();

        // Should have 2 revocations
        assert_eq!(revocation_list.get_all_revoked_tokens().await.len(), 2);

        // Cleanup old revocations (older than 1 day)
        let cutoff = Utc::now() - chrono::Duration::days(1);
        let removed_count = revocation_list
            .cleanup_old_revocations(cutoff)
            .await
            .unwrap();
        assert_eq!(removed_count, 1);

        // Should have 1 revocation left
        assert_eq!(revocation_list.get_all_revoked_tokens().await.len(), 1);
        assert!(revocation_list.is_revoked("recent_token").await);
        assert!(!revocation_list.is_revoked("old_token").await);
    }

    #[test]
    fn test_revocation_statistics_percentages() {
        let mut stats = RevocationStatistics::default();
        stats.total_revocations = 100;
        stats.emergency_revocations = 25;
        stats.security_related_revocations = 30;

        assert_eq!(stats.emergency_percentage(), 25.0);
        assert_eq!(stats.security_related_percentage(), 30.0);

        // Edge case: zero total revocations
        let empty_stats = RevocationStatistics::default();
        assert_eq!(empty_stats.emergency_percentage(), 0.0);
        assert_eq!(empty_stats.security_related_percentage(), 0.0);
    }
}
