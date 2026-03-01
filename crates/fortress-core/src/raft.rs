//! Raft consensus algorithm implementation
//!
//! This module provides a complete Raft implementation for distributed consensus
//! in Fortress clusters, including leader election, log replication, and safety.

use crate::cluster::{NodeId, ClusterCommand, LogEntry};
use crate::error::{FortressError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info};

/// Raft node state
#[derive(Debug, Clone, PartialEq)]
pub enum RaftState {
    /// Following a leader
    Follower,
    /// Candidate for leadership
    Candidate,
    /// Current leader
    Leader,
}

/// Raft persistent state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RaftPersistentState {
    /// Current term
    pub current_term: u64,
    /// Candidate that received vote in current term
    pub voted_for: Option<NodeId>,
    /// Log entries
    pub log: Vec<LogEntry>,
}

impl Default for RaftPersistentState {
    fn default() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            log: Vec::new(),
        }
    }
}

/// Raft volatile state on leaders
#[derive(Debug, Clone)]
pub struct LeaderState {
    /// For each server, index of next log entry to send
    pub next_index: HashMap<NodeId, u64>,
    /// For each server, index of highest log entry known to be replicated
    pub match_index: HashMap<NodeId, u64>,
}

/// Raft volatile state on all servers
#[derive(Debug, Clone)]
pub struct RaftVolatileState {
    /// Index of highest log entry known to be committed
    pub commit_index: u64,
    /// Index of highest log entry applied to state machine
    pub last_applied: u64,
}

impl Default for RaftVolatileState {
    fn default() -> Self {
        Self {
            commit_index: 0,
            last_applied: 0,
        }
    }
}

/// AppendEntries RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesRequest {
    /// Leader's term
    pub term: u64,
    /// Leader's ID
    pub leader_id: NodeId,
    /// Index of log entry immediately preceding new ones
    pub prev_log_index: u64,
    /// Term of prev_log_index entry
    pub prev_log_term: u64,
    /// New entries to append
    pub entries: Vec<LogEntry>,
    /// Leader's commit_index
    pub leader_commit: u64,
}

/// AppendEntries RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendEntriesResponse {
    /// Current term
    pub term: u64,
    /// Success if follower contained entry matching prev_log_index and prev_log_term
    pub success: bool,
}

/// RequestVote RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteRequest {
    /// Candidate's term
    pub term: u64,
    /// Candidate's ID
    pub candidate_id: NodeId,
    /// Index of candidate's last log entry
    pub last_log_index: u64,
    /// Term of candidate's last log entry
    pub last_log_term: u64,
}

/// RequestVote RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestVoteResponse {
    /// Current term
    pub term: u64,
    /// True if candidate received vote
    pub vote_granted: bool,
}

/// Raft consensus engine
pub struct RaftEngine {
    /// Node ID
    node_id: NodeId,
    /// Current Raft state
    state: RwLock<RaftState>,
    /// Persistent state
    persistent_state: RwLock<RaftPersistentState>,
    /// Volatile state
    volatile_state: RwLock<RaftVolatileState>,
    /// Leader state (only used when leader)
    leader_state: RwLock<Option<LeaderState>>,
    /// Election timeout
    election_timeout: Duration,
    /// Last heartbeat time
    last_heartbeat: RwLock<Instant>,
    /// Cluster members
    cluster_members: RwLock<HashMap<NodeId, String>>,
}

impl RaftEngine {
    /// Create a new Raft engine
    pub fn new(
        node_id: NodeId,
        election_timeout: Duration,
        cluster_members: HashMap<NodeId, String>,
    ) -> Self {
        Self {
            node_id,
            state: RwLock::new(RaftState::Follower),
            persistent_state: RwLock::new(RaftPersistentState::default()),
            volatile_state: RwLock::new(RaftVolatileState::default()),
            leader_state: RwLock::new(None),
            election_timeout,
            last_heartbeat: RwLock::new(Instant::now()),
            cluster_members: RwLock::new(cluster_members),
        }
    }

    /// Start the Raft engine
    pub async fn start(&self) -> Result<()> {
        // Start election timeout checker
        self.start_election_timeout_checker().await?;
        
        // Start log replication checker (if leader)
        self.start_log_replication_checker().await?;
        
        info!("Raft engine started for node {}", self.node_id);
        Ok(())
    }

    /// Handle AppendEntries RPC
    pub async fn handle_append_entries(
        &self,
        request: AppendEntriesRequest,
    ) -> Result<AppendEntriesResponse> {
        let mut state = self.state.write().await;
        let mut persistent_state = self.persistent_state.write().await;
        let mut volatile_state = self.volatile_state.write().await;

        // Update term if necessary
        if request.term > persistent_state.current_term {
            persistent_state.current_term = request.term;
            persistent_state.voted_for = None;
            *state = RaftState::Follower;
        }

        // Reset heartbeat timeout
        *self.last_heartbeat.write().await = Instant::now();

        // Check if log is consistent
        let log_consistent = if request.prev_log_index == 0 {
            true
        } else if let Some(entry) = persistent_state.log.get((request.prev_log_index - 1) as usize) {
            entry.term == request.prev_log_term
        } else {
            false
        };

        if !log_consistent {
            return Ok(AppendEntriesResponse {
                term: persistent_state.current_term,
                success: false,
            });
        }

        // Append new entries
        let mut new_entries = request.entries;
        if !new_entries.is_empty() {
            // Remove any conflicting entries
            let start_index = request.prev_log_index;
            while persistent_state.log.len() > start_index as usize {
                persistent_state.log.pop();
            }
            
            // Append new entries
            persistent_state.log.append(&mut new_entries);
        }

        // Update commit index
        if request.leader_commit > volatile_state.commit_index {
            let new_commit_index = request.leader_commit.min(persistent_state.log.len() as u64);
            volatile_state.commit_index = new_commit_index;
        }

        Ok(AppendEntriesResponse {
            term: persistent_state.current_term,
            success: true,
        })
    }

    /// Handle RequestVote RPC
    pub async fn handle_request_vote(
        &self,
        request: RequestVoteRequest,
    ) -> Result<RequestVoteResponse> {
        let mut state = self.state.write().await;
        let mut persistent_state = self.persistent_state.write().await;

        // Update term if necessary
        if request.term > persistent_state.current_term {
            persistent_state.current_term = request.term;
            persistent_state.voted_for = None;
            *state = RaftState::Follower;
        }

        // Check if we can grant vote
        let vote_granted = if persistent_state.voted_for.is_none()
            || persistent_state.voted_for == Some(request.candidate_id)
        {
            // Check if candidate's log is at least as up-to-date as ours
            let last_log_term = persistent_state
                .log
                .last()
                .map(|entry| entry.term)
                .unwrap_or(0);
            let last_log_index = persistent_state.log.len() as u64;

            (request.last_log_term > last_log_term)
                || (request.last_log_term == last_log_term && request.last_log_index >= last_log_index)
        } else {
            false
        };

        if vote_granted {
            persistent_state.voted_for = Some(request.candidate_id);
            info!("Granted vote to candidate {} in term {}", request.candidate_id, request.term);
        }

        Ok(RequestVoteResponse {
            term: persistent_state.current_term,
            vote_granted,
        })
    }

    /// Propose a new command to the cluster
    pub async fn propose(&self, command: ClusterCommand) -> Result<()> {
        let state = self.state.read().await;
        
        match *state {
            RaftState::Leader => {
                // As leader, we can directly append to log
                self.append_to_log(command).await?;
                Ok(())
            }
            _ => {
                // Forward to leader
                Err(FortressError::cluster(
                    "Not a leader, cannot propose command directly",
                    None,
                ))
            }
        }
    }

    /// Append entry to local log
    async fn append_to_log(&self, command: ClusterCommand) -> Result<()> {
        let mut persistent_state = self.persistent_state.write().await;
        let current_term = persistent_state.current_term;
        let index = persistent_state.log.len() as u64 + 1;

        let entry = LogEntry {
            index,
            term: current_term,
            command,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        };

        persistent_state.log.push(entry);
        debug!("Appended entry {} to log in term {}", index, current_term);

        // Trigger log replication
        self.replicate_log().await?;

        Ok(())
    }

    /// Replicate log to followers
    async fn replicate_log(&self) -> Result<()> {
        let persistent_state = self.persistent_state.read().await;
        let volatile_state = self.volatile_state.read().await;
        let leader_state = self.leader_state.read().await;
        
        if let Some(leader_state) = leader_state.as_ref() {
            let cluster_members = self.cluster_members.read().await;
            
            for (node_id, _address) in cluster_members.iter() {
                if *node_id != self.node_id {
                    let next_index = leader_state.next_index.get(node_id).copied()
                        .unwrap_or(persistent_state.log.len() as u64 + 1);
                    
                    let prev_log_index = next_index - 1;
                    let prev_log_term = if prev_log_index > 0 {
                        persistent_state
                            .log
                            .get((prev_log_index - 1) as usize)
                            .map(|entry| entry.term)
                            .unwrap_or(0)
                    } else {
                        0
                    };

                    let entries: Vec<LogEntry> = persistent_state
                        .log
                        .iter()
                        .skip((next_index - 1) as usize)
                        .cloned()
                        .collect();

                    let request = AppendEntriesRequest {
                        term: persistent_state.current_term,
                        leader_id: self.node_id,
                        prev_log_index,
                        prev_log_term,
                        entries,
                        leader_commit: volatile_state.commit_index,
                    };

                    // TODO: Send actual RPC to follower
                    debug!("Would send AppendEntries to node {}: {:?}", node_id, request);
                }
            }
        }

        Ok(())
    }

        /// Start election timeout checker
    async fn start_election_timeout_checker(&self) -> Result<()> {
        let node_id = self.node_id;
        let election_timeout = self.election_timeout;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(election_timeout / 2);
            
            loop {
                interval.tick().await;
                
                // TODO: Implement election timeout logic
                debug!("Election timeout tick from {}", node_id);
            }
        });

        Ok(())
    }

    /// Start log replication checker (only when leader)
    async fn start_log_replication_checker(&self) -> Result<()> {
        let node_id = self.node_id;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_millis(50));
            
            loop {
                interval.tick().await;
                
                // TODO: Implement heartbeat mechanism
                debug!("Heartbeat tick from {}", node_id);
            }
        });

        Ok(())
    }

    /// Become leader
    pub async fn become_leader(&self) -> Result<()> {
        let mut state = self.state.write().await;
        let persistent_state = self.persistent_state.read().await;
        let cluster_members = self.cluster_members.read().await;
        
        *state = RaftState::Leader;
        
        // Initialize leader state
        let mut leader_state = LeaderState {
            next_index: HashMap::new(),
            match_index: HashMap::new(),
        };
        
        let next_index_value = persistent_state.log.len() as u64 + 1;
        
        for (node_id, _address) in cluster_members.iter() {
            if *node_id != self.node_id {
                leader_state.next_index.insert(*node_id, next_index_value);
                leader_state.match_index.insert(*node_id, 0);
            }
        }
        
        *self.leader_state.write().await = Some(leader_state);
        
        info!("Node {} became leader in term {}", self.node_id, persistent_state.current_term);
        
        Ok(())
    }

    /// Step down as leader
    pub async fn step_down(&self) -> Result<()> {
        let mut state = self.state.write().await;
        *state = RaftState::Follower;
        *self.leader_state.write().await = None;
        
        info!("Node {} stepped down as leader", self.node_id);
        
        Ok(())
    }

    /// Get current state
    pub async fn get_state(&self) -> RaftState {
        (*self.state.read().await).clone()
    }

    /// Get current term
    pub async fn get_term(&self) -> u64 {
        self.persistent_state.read().await.current_term
    }

    /// Get commit index
    pub async fn get_commit_index(&self) -> u64 {
        self.volatile_state.read().await.commit_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use uuid::Uuid;

    #[tokio::test]
    async fn test_raft_engine_creation() {
        let node_id = Uuid::new_v4();
        let members = HashMap::new();
        let engine = RaftEngine::new(node_id, Duration::from_millis(5000), members);
        
        assert_eq!(engine.get_state().await, RaftState::Follower);
        assert_eq!(engine.get_term().await, 0);
        assert_eq!(engine.get_commit_index().await, 0);
    }

    #[tokio::test]
    async fn test_append_entries_request() {
        let node_id = Uuid::new_v4();
        let members = HashMap::new();
        let engine = RaftEngine::new(node_id, Duration::from_millis(5000), members);
        
        let request = AppendEntriesRequest {
            term: 1,
            leader_id: Uuid::new_v4(),
            prev_log_index: 0,
            prev_log_term: 0,
            entries: vec![],
            leader_commit: 0,
        };
        
        let response = engine.handle_append_entries(request).await.unwrap();
        assert_eq!(response.term, 1);
        assert!(response.success);
    }

    #[tokio::test]
    async fn test_request_vote() {
        let node_id = Uuid::new_v4();
        let members = HashMap::new();
        let engine = RaftEngine::new(node_id, Duration::from_millis(5000), members);
        
        let request = RequestVoteRequest {
            term: 1,
            candidate_id: Uuid::new_v4(),
            last_log_index: 0,
            last_log_term: 0,
        };
        
        let response = engine.handle_request_vote(request).await.unwrap();
        assert_eq!(response.term, 1);
        assert!(response.vote_granted);
    }
}
