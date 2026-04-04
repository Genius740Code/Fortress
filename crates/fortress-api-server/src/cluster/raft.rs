//! # Raft Consensus Implementation
//!
//! This module implements the Raft consensus algorithm for leader election,
//! log replication, and consistency guarantees across the cluster.

use crate::cluster::{ClusterError, ClusterResult};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use tokio::time::interval;
use tracing::{error, info};
use uuid::Uuid;

/// Raft node role
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RaftRole {
    /// Follower node (default state)
    Follower,
    /// Candidate node (participating in election)
    Candidate,
    /// Leader node (handling client requests)
    Leader,
}

/// Raft log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Unique identifier for this entry
    pub entry_id: Uuid,
    /// Term number when entry was created
    pub term: u64,
    /// Command to be executed
    pub command: Vec<u8>,
    /// Index in the log
    pub index: u64,
    /// Timestamp when entry was created
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// Raft node state
#[derive(Debug)]
pub struct RaftState {
    /// Current role of this node
    pub role: RaftRole,
    /// Current term number
    pub current_term: u64,
    /// Node voted for in current term (if any)
    pub voted_for: Option<Uuid>,
    /// Log entries
    pub log: Vec<LogEntry>,
    /// Index of highest log entry known to be committed
    pub commit_index: u64,
    /// Index of highest log entry applied to state machine
    pub last_applied: u64,
    /// For each server, index of next log entry to send
    pub next_index: HashMap<Uuid, u64>,
    /// For each server, index of highest log entry known to be replicated
    pub match_index: HashMap<Uuid, u64>,
    /// Last time we heard from leader
    pub last_heartbeat: Option<Instant>,
    /// Election timeout
    pub election_timeout: Duration,
}

/// Raft configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftConfig {
    /// Minimum election timeout in milliseconds
    pub min_election_timeout_ms: u64,
    /// Maximum election timeout in milliseconds
    pub max_election_timeout_ms: u64,
    /// Heartbeat interval in milliseconds
    pub heartbeat_interval_ms: u64,
    /// Log compaction threshold
    pub log_compaction_threshold: usize,
    /// Maximum log size before compaction
    pub max_log_size: usize,
    /// Snapshot interval in terms
    pub snapshot_interval_terms: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            min_election_timeout_ms: 3000,
            max_election_timeout_ms: 5000,
            heartbeat_interval_ms: 1000,
            log_compaction_threshold: 1000,
            max_log_size: 10000,
            snapshot_interval_terms: 10,
        }
    }
}

/// Raft message types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RaftMessage {
    /// Request vote message
    RequestVote {
        /// Current election term
        term: u64,
        /// ID of the candidate requesting vote
        candidate_id: Uuid,
        /// Index of candidate's last log entry
        last_log_index: u64,
        /// Term of candidate's last log entry
        last_log_term: u64,
    },
    
    /// Response to vote request
    RequestVoteResponse {
        /// Current election term
        term: u64,
        /// Whether the vote was granted
        vote_granted: bool,
    },
    
    /// Append entries message (heartbeat or log replication)
    AppendEntries {
        /// Current election term
        term: u64,
        /// ID of the leader sending entries
        leader_id: Uuid,
        /// Index of log entry before new ones
        prev_log_index: u64,
        /// Term of log entry before new ones
        prev_log_term: u64,
        /// New log entries to append
        entries: Vec<LogEntry>,
        /// Leader's commit index
        leader_commit: u64,
    },
    
    /// Response to append entries
    AppendEntriesResponse {
        /// Current election term
        term: u64,
        /// Whether the vote was granted
        success: bool,
        /// Index of highest log entry known to be replicated
        match_index: u64,
    },
    
    /// Install snapshot message
    InstallSnapshot {
        /// Current election term
        term: u64,
        /// ID of the leader sending snapshot
        leader_id: Uuid,
        /// Index of last included entry
        last_included_index: u64,
        /// Term of last included entry
        last_included_term: u64,
        /// Snapshot data bytes
        data: Vec<u8>,
    },
    
    /// Response to install snapshot
    InstallSnapshotResponse {
        /// Current election term
        term: u64,
    },
}

/// Raft-specific errors
#[derive(Debug, thiserror::Error)]
pub enum RaftError {
    /// Invalid election term
    #[error("Invalid term: {0}")]
    InvalidTerm(u64),
    
    /// Log inconsistency detected
    #[error("Log inconsistency at index {0}")]
    LogInconsistency(u64),
    
    /// Node is not the leader
    #[error("Not a leader")]
    NotLeader,
    
    /// Leadership transfer failed
    #[error("Leadership transfer failed: {0}")]
    LeadershipTransferFailed(String),
    
    /// Snapshot installation failed
    #[error("Snapshot installation failed: {0}")]
    SnapshotInstallationFailed(String),
    
    /// Log compaction failed
    #[error("Log compaction failed: {0}")]
    LogCompactionFailed(String),
}

/// Raft node implementation
pub struct RaftNode {
    /// Unique identifier for this node
    node_id: Uuid,
    /// Current raft state
    state: Arc<RwLock<RaftState>>,
    /// Configuration
    config: RaftConfig,
    /// Cluster members
    cluster_members: Arc<RwLock<HashSet<Uuid>>>,
    /// Message sender
    message_sender: Arc<Mutex<dyn MessageSender + Send + Sync>>,
}

/// Trait for sending messages to other nodes
#[async_trait::async_trait]
pub trait MessageSender {
    /// Send a message to a specific node
    async fn send_message(&self, target: Uuid, message: RaftMessage) -> ClusterResult<()>;
    
    /// Broadcast a message to all nodes
    async fn broadcast_message(&self, message: RaftMessage) -> ClusterResult<()>;
}

impl RaftNode {
    /// Create a new Raft node
    pub fn new(
        node_id: Uuid,
        config: RaftConfig,
        message_sender: Arc<Mutex<dyn MessageSender + Send + Sync>>,
    ) -> Self {
        let election_timeout = Duration::from_millis(
            rand::random::<u64>() % (config.max_election_timeout_ms - config.min_election_timeout_ms)
                + config.min_election_timeout_ms,
        );

        let state = RaftState {
            role: RaftRole::Follower,
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
            commit_index: 0,
            last_applied: 0,
            next_index: HashMap::new(),
            match_index: HashMap::new(),
            last_heartbeat: None,
            election_timeout,
        };

        Self {
            node_id,
            state: Arc::new(RwLock::new(state)),
            config,
            cluster_members: Arc::new(RwLock::new(HashSet::new())),
            message_sender,
        }
    }

    /// Start the Raft node
    pub async fn start(&self) -> ClusterResult<()> {
        info!("Starting Raft node {}", self.node_id);
        
        // Start the main Raft loop
        let raft_node = self.clone();
        tokio::spawn(async move {
            raft_node.raft_loop().await;
        });

        Ok(())
    }

    /// Main Raft event loop
    async fn raft_loop(&self) {
        let mut heartbeat_interval = interval(Duration::from_millis(self.config.heartbeat_interval_ms));
        
        loop {
            let state = self.state.read().await;
            let role = state.role.clone();
            drop(state);

            match role {
                RaftRole::Follower => {
                    self.handle_follower_role().await;
                }
                RaftRole::Candidate => {
                    self.handle_candidate_role().await;
                }
                RaftRole::Leader => {
                    self.handle_leader_role(&mut heartbeat_interval).await;
                }
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Handle follower role responsibilities
    async fn handle_follower_role(&self) {
        let state = self.state.read().await;
        
        // Check if election timeout has expired
        if let Some(last_heartbeat) = state.last_heartbeat {
            if last_heartbeat.elapsed() > state.election_timeout {
                drop(state);
                self.start_election().await;
            }
        } else {
            // No heartbeat received yet, start election
            drop(state);
            self.start_election().await;
        }
    }

    /// Handle candidate role responsibilities
    async fn handle_candidate_role(&self) {
        let state = self.state.read().await;
        
        // Check if election timeout has expired
        if let Some(last_heartbeat) = state.last_heartbeat {
            if last_heartbeat.elapsed() > state.election_timeout {
                drop(state);
                self.start_election().await;
            }
        }
    }

    /// Handle leader role responsibilities
    async fn handle_leader_role(&self, heartbeat_interval: &mut tokio::time::Interval) {
        heartbeat_interval.tick().await;
        
        // Send heartbeats to all followers
        if let Err(e) = self.send_heartbeats().await {
            error!("Failed to send heartbeats: {}", e);
        }
        
        // Check for committed entries
        self.check_commit_index().await;
    }

    /// Start a new election
    async fn start_election(&self) {
        info!("Starting election for node {}", self.node_id);
        
        // Update state to candidate
        {
            let mut state = self.state.write().await;
            state.role = RaftRole::Candidate;
            state.current_term += 1;
            state.voted_for = Some(self.node_id);
            state.last_heartbeat = Some(Instant::now());
        }

        // Request votes from other nodes
        let state = self.state.read().await;
        let term = state.current_term;
        let last_log_index = state.log.len() as u64;
        let last_log_term = state.log.last().map(|e| e.term).unwrap_or(0);
        drop(state);

        let vote_request = RaftMessage::RequestVote {
            term,
            candidate_id: self.node_id,
            last_log_index,
            last_log_term,
        };

        if let Err(e) = self.broadcast_message(vote_request).await {
            error!("Failed to broadcast vote request: {}", e);
        }
    }

    /// Send heartbeats to all followers
    async fn send_heartbeats(&self) -> ClusterResult<()> {
        let state = self.state.read().await;
        let term = state.current_term;
        let commit_index = state.commit_index;
        drop(state);

        let heartbeat = RaftMessage::AppendEntries {
            term,
            leader_id: self.node_id,
            prev_log_index: 0,
            prev_log_term: 0,
            entries: Vec::new(),
            leader_commit: commit_index,
        };

        self.broadcast_message(heartbeat).await
    }

    /// Check and update commit index
    async fn check_commit_index(&self) {
        let state = self.state.read().await;
        let mut match_indices: Vec<u64> = state.match_index.values().cloned().collect();
        match_indices.push(state.log.len() as u64); // Include leader's last index
        drop(state);

        match_indices.sort_unstable_by(|a, b| b.cmp(a));
        
        // Find majority index
        let majority = (self.cluster_members.read().await.len() + 1) / 2 + 1;
        if match_indices.len() >= majority {
            let majority_commit_index = match_indices[majority - 1];
            
            let mut state = self.state.write().await;
            if majority_commit_index > state.commit_index {
                state.commit_index = majority_commit_index;
                info!("Updated commit index to {}", state.commit_index);
            }
        }
    }

    /// Handle incoming Raft message
    pub async fn handle_message(&self, message: RaftMessage) -> ClusterResult<RaftMessage> {
        match message {
            RaftMessage::RequestVote { term, candidate_id, last_log_index, last_log_term } => {
                self.handle_request_vote(term, candidate_id, last_log_index, last_log_term).await
            }
            RaftMessage::AppendEntries { term, leader_id, prev_log_index, prev_log_term, entries, leader_commit } => {
                self.handle_append_entries(term, leader_id, prev_log_index, prev_log_term, entries, leader_commit).await
            }
            RaftMessage::InstallSnapshot { term, leader_id, last_included_index, last_included_term, data } => {
                self.handle_install_snapshot(term, leader_id, last_included_index, last_included_term, data).await
            }
            _ => Err(ClusterError::Raft(RaftError::InvalidTerm(0))),
        }
    }

    /// Handle vote request
    async fn handle_request_vote(&self, term: u64, candidate_id: Uuid, last_log_index: u64, last_log_term: u64) -> ClusterResult<RaftMessage> {
        let mut state = self.state.write().await;
        
        // Update term if necessary
        if term > state.current_term {
            state.current_term = term;
            state.role = RaftRole::Follower;
            state.voted_for = None;
        }

        // Check if we can vote for this candidate
        let vote_granted = if state.voted_for.is_none() || state.voted_for == Some(candidate_id) {
            // Check if candidate's log is at least as up-to-date as ours
            let our_last_log_index = state.log.len() as u64;
            let our_last_log_term = state.log.last().map(|e| e.term).unwrap_or(0);
            
            (last_log_term > our_last_log_term) || 
            (last_log_term == our_last_log_term && last_log_index >= our_last_log_index)
        } else {
            false
        };

        if vote_granted {
            state.voted_for = Some(candidate_id);
            state.last_heartbeat = Some(Instant::now());
        }

        Ok(RaftMessage::RequestVoteResponse {
            term: state.current_term,
            vote_granted,
        })
    }

    /// Handle append entries request
    async fn handle_append_entries(&self, term: u64, _leader_id: Uuid, prev_log_index: u64, prev_log_term: u64, entries: Vec<LogEntry>, leader_commit: u64) -> ClusterResult<RaftMessage> {
        let mut state = self.state.write().await;
        
        // Update term if necessary
        if term > state.current_term {
            state.current_term = term;
            state.role = RaftRole::Follower;
            state.voted_for = None;
        }

        // If we're not the leader, accept the heartbeat
        if state.role != RaftRole::Leader {
            state.last_heartbeat = Some(Instant::now());
        }

        // Check log consistency
        if prev_log_index > 0 {
            if state.log.len() < prev_log_index as usize {
                return Ok(RaftMessage::AppendEntriesResponse {
                    term: state.current_term,
                    success: false,
                    match_index: 0,
                });
            }

            if state.log[prev_log_index as usize - 1].term != prev_log_term {
                return Ok(RaftMessage::AppendEntriesResponse {
                    term: state.current_term,
                    success: false,
                    match_index: 0,
                });
            }
        }

        // Append new entries
        let mut match_index = prev_log_index;
        for (i, entry) in entries.iter().enumerate() {
            let log_index = prev_log_index + 1 + i as u64;
            
            if state.log.len() >= log_index as usize {
                if state.log[log_index as usize - 1].term != entry.term {
                    // Remove conflicting entries
                    state.log.truncate(log_index as usize - 1);
                    state.log.push(entry.clone());
                }
            } else {
                state.log.push(entry.clone());
            }
            match_index = log_index;
        }

        // Update commit index
        if leader_commit > state.commit_index {
            state.commit_index = std::cmp::min(leader_commit, state.log.len() as u64);
        }

        Ok(RaftMessage::AppendEntriesResponse {
            term: state.current_term,
            success: true,
            match_index,
        })
    }

    /// Handle install snapshot request
    async fn handle_install_snapshot(&self, term: u64, _leader_id: Uuid, _last_included_index: u64, _last_included_term: u64, _data: Vec<u8>) -> ClusterResult<RaftMessage> {
        let mut state = self.state.write().await;
        
        // Update term if necessary
        if term > state.current_term {
            state.current_term = term;
            state.role = RaftRole::Follower;
            state.voted_for = None;
        }

        // Install snapshot logic would go here
        // For now, just acknowledge receipt
        
        Ok(RaftMessage::InstallSnapshotResponse {
            term: state.current_term,
        })
    }

    /// Add cluster member
    pub async fn add_member(&self, node_id: Uuid) {
        let mut members = self.cluster_members.write().await;
        members.insert(node_id);
        
        // Initialize next_index for new member
        let mut state = self.state.write().await;
        // Update next index for this node
        let next_index = state.log.len() as u64 + 1;
        state.next_index.insert(node_id, next_index);
        state.match_index.insert(node_id, 0);
    }

    /// Remove cluster member
    pub async fn remove_member(&self, node_id: Uuid) {
        let mut members = self.cluster_members.write().await;
        members.remove(&node_id);
        
        // Clean up tracking for removed member
        let mut state = self.state.write().await;
        state.next_index.remove(&node_id);
        state.match_index.remove(&node_id);
    }

    /// Get current role
    pub async fn get_role(&self) -> RaftRole {
        self.state.read().await.role.clone()
    }

    /// Get current term
    pub async fn get_term(&self) -> u64 {
        self.state.read().await.current_term
    }

    /// Check if this node is the leader
    pub async fn is_leader(&self) -> bool {
        self.state.read().await.role == RaftRole::Leader
    }

    /// Broadcast message to all cluster members
    async fn broadcast_message(&self, message: RaftMessage) -> ClusterResult<()> {
        let sender = self.message_sender.lock().await;
        sender.broadcast_message(message).await
    }
}

impl Clone for RaftNode {
    fn clone(&self) -> Self {
        Self {
            node_id: self.node_id,
            state: Arc::clone(&self.state),
            config: self.config.clone(),
            cluster_members: Arc::clone(&self.cluster_members),
            message_sender: Arc::clone(&self.message_sender),
        }
    }
}
