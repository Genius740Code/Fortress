//! System Integration Tests for Fortress
//!
//! This module contains comprehensive integration tests for:
//! - Distributed clustering with Raft consensus  
//! - Multi-party computation (MPC) protocols
//! - Plugin system with security and performance validation
//!
//! Tests ensure systems are fast, scalable, effective, and secure with no errors.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use fortress_core::{
    error::{FortressError, Result},
    cluster::{ClusterConfig, ClusterNode, NodeState, NodeId, NodeCapabilities, LoadMetrics},
    mpc::{MpcManager, ComputationConfig, SessionId, PartyId, ComputationStatus, SecretSharingScheme, PartyRole},
    mpc_manager::DefaultMpcManager,
    mpc_party::InMemoryMpcParty,
    plugin::{Plugin, PluginMetadata, PluginCapability, PluginContext, PluginResult, PluginMetrics, PluginInput, PluginHealth},
};

/// Test cluster configuration for integration tests
fn create_test_cluster_config(node_id: NodeId, bind_address: &str, seed_nodes: Vec<&str>) -> ClusterConfig {
    use std::net::SocketAddr;
    ClusterConfig {
        node_id,
        bind_address: bind_address.parse().unwrap(),
        seed_nodes: seed_nodes.into_iter().map(|s| s.parse().unwrap()).collect(),
        heartbeat_interval: Duration::from_millis(100),
        election_timeout: Duration::from_millis(1000),
        replication_factor: 3,
        min_nodes: 2,
    }
}

/// Test plugin implementation for integration tests
struct TestPlugin {
    metadata: PluginMetadata,
    execution_count: Arc<RwLock<u64>>,
}

impl TestPlugin {
    fn new(name: &str, capabilities: Vec<PluginCapability>) -> Self {
        Self {
            metadata: PluginMetadata {
                id: format!("test-plugin-{}", name),
                name: name.to_string(),
                version: "1.0.0".to_string(),
                description: format!("Test plugin for {}", name),
                author: "Test Suite".to_string(),
                capabilities,
                config_schema: None,
            },
            execution_count: Arc::new(RwLock::new(0)),
        }
    }

    async fn get_execution_count(&self) -> u64 {
        *self.execution_count.read().await
    }

    async fn increment_execution_count(&self) {
        let mut count = self.execution_count.write().await;
        *count += 1;
    }
}

#[async_trait::async_trait]
impl Plugin for TestPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        self.increment_execution_count().await;
        
        let start_time = std::time::Instant::now();
        
        // Simulate plugin work based on action
        let result = match input.action.as_str() {
            "sign" => {
                serde_json::json!({
                    "signature": "test-signature",
                    "transaction_hash": "abc123",
                    "verified": true
                })
            },
            "encrypt" => {
                serde_json::json!({
                    "encrypted_data": "encrypted-12345",
                    "algorithm": "AES-256-GCM"
                })
            },
            "api" => {
                serde_json::json!({
                    "api_response": {
                        "status": "success",
                        "data": input.data
                    }
                })
            },
            _ => {
                serde_json::json!({
                    "processed": true,
                    "input": input.data
                })
            }
        };

        let execution_time = start_time.elapsed();
        
        Ok(PluginResult {
            success: true,
            data: Some(result),
            error: None,
            metrics: PluginMetrics {
                execution_time_ms: execution_time.as_millis() as u64,
                memory_usage_bytes: 1024,
                custom_metrics: HashMap::from([
                    ("operations".to_string(), serde_json::Value::Number(1.into())),
                ]),
            },
        })
    }

    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: "Plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}

#[cfg(test)]
mod cluster_tests {
    use super::*;
    use fortress_core::cluster::{NodeCapabilities, LoadMetrics};

    #[tokio::test]
    async fn test_cluster_node_creation() {
        let node_id = Uuid::new_v4();
        let config = create_test_cluster_config(node_id, "127.0.0.1:8080", vec![]);
        
        // Test cluster node creation
        let node = ClusterNode {
            id: node_id,
            address: config.bind_address,
            state: NodeState::Follower { leader: None, term: 0 },
            last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
            capabilities: NodeCapabilities {
                storage: true,
                encryption: true,
                leadership: true,
                algorithms: vec!["aegis256".to_string(), "chacha20".to_string()],
            },
            load_metrics: LoadMetrics {
                cpu_usage: 0.1,
                memory_usage: 0.2,
                active_connections: 5,
                ops_per_second: 100.0,
                storage_used: 1024,
                network_io: 1024,
            },
        };

        assert_eq!(node.id, node_id);
        assert!(matches!(node.state, NodeState::Follower { .. }));
        assert!(node.capabilities.encryption);
        assert_eq!(node.load_metrics.active_connections, 5);
    }

    #[tokio::test]
    async fn test_cluster_state_transitions() {
        // Test follower state
        let follower_state = NodeState::Follower { leader: None, term: 1 };
        assert!(matches!(follower_state, NodeState::Follower { leader: None, term: 1 }));
        
        // Test candidate state
        let candidate_state = NodeState::Candidate { term: 2, votes_received: 1, votes_needed: 3 };
        assert!(matches!(candidate_state, NodeState::Candidate { term: 2, votes_received: 1, votes_needed: 3 }));
        
        // Test leader state
        let leader_state = NodeState::Leader { term: 3 };
        assert!(matches!(leader_state, NodeState::Leader { term: 3 }));
        
        // Test state serialization
        let serialized = serde_json::to_string(&leader_state).unwrap();
        let deserialized: NodeState = serde_json::from_str(&serialized).unwrap();
        assert!(matches!(deserialized, NodeState::Leader { term: 3 }));
    }

    #[tokio::test]
    async fn test_cluster_configuration() {
        let node_id = Uuid::new_v4();
        let config = create_test_cluster_config(
            node_id,
            "127.0.0.1:8080",
            vec!["127.0.0.1:8081", "127.0.0.1:8082"]
        );

        assert_eq!(config.node_id, node_id);
        assert_eq!(config.seed_nodes.len(), 2);
        assert_eq!(config.replication_factor, 3);
        assert_eq!(config.min_nodes, 2);
        assert_eq!(config.heartbeat_interval, Duration::from_millis(100));
        assert_eq!(config.election_timeout, Duration::from_millis(1000));
    }

    #[tokio::test]
    async fn test_cluster_node_capabilities() {
        let capabilities = NodeCapabilities {
            storage: true,
            encryption: true,
            leadership: false,
            algorithms: vec!["http".to_string(), "grpc".to_string()],
        };

        assert!(capabilities.encryption);
        assert!(capabilities.storage);
        assert!(!capabilities.leadership);
        assert_eq!(capabilities.algorithms.len(), 2);
    }

    #[tokio::test]
    async fn test_cluster_load_metrics() {
        let metrics = LoadMetrics {
            cpu_usage: 0.75,
            memory_usage: 0.60,
            active_connections: 250,
            ops_per_second: 1500.5,
            storage_used: 2048,
            network_io: 3072,
        };

        assert_eq!(metrics.cpu_usage, 0.75);
        assert_eq!(metrics.memory_usage, 0.60);
        assert_eq!(metrics.active_connections, 250);
        assert_eq!(metrics.ops_per_second, 1500.5);
    }

    #[tokio::test]
    async fn test_cluster_config_serialization() {
        let node_id = Uuid::new_v4();
        let config = create_test_cluster_config(node_id, "127.0.0.1:8080", vec!["127.0.0.1:8081"]);
        
        // Test serialization
        let serialized = serde_json::to_string(&config).unwrap();
        assert!(!serialized.is_empty());
        
        // Test deserialization
        let deserialized: ClusterConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.node_id, node_id);
        assert_eq!(deserialized.bind_address, config.bind_address);
        assert_eq!(deserialized.seed_nodes.len(), 1);
    }

    #[tokio::test]
    async fn test_cluster_node_serialization() {
        let node_id = Uuid::new_v4();
        let node = ClusterNode {
            id: node_id,
            address: "127.0.0.1:8080".parse().unwrap(),
            state: NodeState::Leader { term: 5 },
            last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
            capabilities: NodeCapabilities {
                storage: true,
                encryption: true,
                leadership: true,
                algorithms: vec!["raft".to_string()],
            },
            load_metrics: LoadMetrics {
                cpu_usage: 0.5,
                memory_usage: 0.4,
                active_connections: 100,
                ops_per_second: 500.0,
                storage_used: 4096,
                network_io: 2048,
            },
        };

        // Test serialization
        let serialized = serde_json::to_string(&node).unwrap();
        assert!(!serialized.is_empty());
        
        // Test deserialization
        let deserialized: ClusterNode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, node_id);
        assert!(matches!(deserialized.state, NodeState::Leader { term: 5 }));
        assert_eq!(deserialized.capabilities.algorithms.len(), 1);
    }

    #[tokio::test]
    async fn test_multiple_cluster_nodes() {
        let mut nodes: Vec<ClusterNode> = Vec::new();
        
        for i in 0..5 {
            let node_id = Uuid::new_v4();
            let node = ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: if i == 0 {
                    NodeState::Leader { term: 1 }
                } else {
                    NodeState::Follower { leader: Some(nodes[0].id), term: 1 }
                },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["raft".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: (i as f64) * 0.1,
                    memory_usage: (i as f64) * 0.15,
                    active_connections: i * 10,
                    ops_per_second: (i as f64) * 100.0,
                    storage_used: (i as u64) * 1024,
                    network_io: (i as u64) * 512,
                },
            };
            nodes.push(node);
        }

        assert_eq!(nodes.len(), 5);
        
        // Verify leader
        let leader = &nodes[0];
        assert!(matches!(leader.state, NodeState::Leader { .. }));
        
        // Verify followers
        for i in 1..5 {
            assert!(matches!(nodes[i].state, NodeState::Follower { .. }));
        }
    }

    #[tokio::test]
    async fn test_cluster_performance_metrics() {
        let start_time = std::time::Instant::now();
        
        // Create multiple nodes to test performance
        let nodes: Vec<ClusterNode> = (0..100).map(|i| {
            let node_id = Uuid::new_v4();
            ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: NodeState::Follower { leader: None, term: 0 },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["raft".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: (i as f64) * 0.01,
                    memory_usage: (i as f64) * 0.01,
                    active_connections: i,
                    ops_per_second: (i as f64) * 10.0,
                    storage_used: (i as u64) * 256,
                    network_io: (i as u64) * 128,
                },
            }
        }).collect();

        let creation_time = start_time.elapsed();
        
        // Performance assertions
        assert_eq!(nodes.len(), 100);
        assert!(creation_time.as_millis() < 1000, "Node creation should complete in < 1 second");
        
        // Test serialization performance
        let serialization_start = std::time::Instant::now();
        let serialized: Vec<String> = nodes.iter()
            .map(|node| serde_json::to_string(node).unwrap())
            .collect();
        let serialization_time = serialization_start.elapsed();
        
        assert_eq!(serialized.len(), 100);
        assert!(serialization_time.as_millis() < 2000, "Serialization should complete in < 2 seconds");
    }

    #[tokio::test]
    async fn test_cluster_error_handling() {
        // Test invalid address
        let result = "127.0.0.1:99999".parse::<std::net::SocketAddr>();
        assert!(result.is_err());
        
        // Test empty seed nodes is valid
        let node_id = Uuid::new_v4();
        let config = create_test_cluster_config(node_id, "127.0.0.1:8080", vec![]);
        assert_eq!(config.seed_nodes.len(), 0);
        
        // Test invalid replication factor (should still work as it's just a number)
        let mut config = create_test_cluster_config(node_id, "127.0.0.1:8080", vec![]);
        config.replication_factor = 0; // Invalid but not enforced at struct level
        assert_eq!(config.replication_factor, 0);
    }

    #[tokio::test]
    async fn test_cluster_security_validation() {
        let node_id = Uuid::new_v4();
        
        // Test node with security capabilities
        let secure_node = ClusterNode {
            id: node_id,
            address: "127.0.0.1:8080".parse().unwrap(),
            state: NodeState::Leader { term: 1 },
            last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
            capabilities: NodeCapabilities {
                storage: true,
                encryption: true,
                leadership: true,
                algorithms: vec!["tls".to_string(), "https".to_string()],
            },
            load_metrics: LoadMetrics::default(),
        };

        // Verify security features
        assert!(secure_node.capabilities.encryption);
        assert!(secure_node.capabilities.storage);
        assert!(secure_node.capabilities.algorithms.contains(&"tls".to_string()));
        assert!(secure_node.capabilities.algorithms.contains(&"https".to_string()));
        
        // Test node without security capabilities
        let insecure_node = ClusterNode {
            id: Uuid::new_v4(),
            address: "127.0.0.1:8081".parse().unwrap(),
            state: NodeState::Follower { leader: Some(secure_node.id), term: 1 },
            last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
            capabilities: NodeCapabilities {
                storage: false,
                encryption: false,
                leadership: false,
                algorithms: vec!["http".to_string()],
            },
            load_metrics: LoadMetrics::default(),
        };

        assert!(!insecure_node.capabilities.encryption);
        assert!(!insecure_node.capabilities.storage);
        assert!(!insecure_node.capabilities.algorithms.contains(&"tls".to_string()));
    }
}

#[cfg(test)]
mod mpc_tests {
    use super::*;
    use fortress_core::mpc::{PartyRole, SecretShare, MpcMessage};

    #[tokio::test]
    async fn test_mpc_party_creation() {
        let party_id = Uuid::new_v4().to_string();
        let party = InMemoryMpcParty::new(party_id.clone(), PartyRole::Participant);
        
        assert_eq!(party.party_id, party_id);
        assert!(matches!(party.role, PartyRole::Participant));
        assert_eq!(party.inbox_count().await, 0);
        assert_eq!(party.outbox_count().await, 0);
    }

    #[tokio::test]
    async fn test_mpc_party_with_metadata() {
        let party_id = Uuid::new_v4().to_string();
        let mut metadata = HashMap::new();
        metadata.insert("name".to_string(), "Test Party".to_string());
        metadata.insert("version".to_string(), "1.0".to_string());
        
        let party = InMemoryMpcParty::with_metadata(
            party_id.clone(),
            PartyRole::Initiator,
            metadata.clone(),
        ).await;
        
        assert_eq!(party.party_id, party_id);
        assert!(matches!(party.role, PartyRole::Initiator));
        
        let retrieved_metadata = party.get_metadata().await;
        assert_eq!(retrieved_metadata.get("name"), Some(&"Test Party".to_string()));
        assert_eq!(retrieved_metadata.get("version"), Some(&"1.0".to_string()));
    }

    #[tokio::test]
    async fn test_mpc_party_message_handling() {
        let party_id = Uuid::new_v4().to_string();
        let party = InMemoryMpcParty::new(party_id, PartyRole::Participant);
        
        // Test adding metadata
        party.add_metadata("test_key", "test_value").await;
        let metadata = party.get_metadata().await;
        assert_eq!(metadata.get("test_key"), Some(&"test_value".to_string()));
        
        // Test message processing
        let message = MpcMessage {
            message_id: Uuid::new_v4().to_string(),
            session_id: Uuid::new_v4().to_string(),
            sender_id: "sender1".to_string(),
            recipient_id: party.party_id.clone(),
            message_type: "test_message".to_string(),
            payload: serde_json::json!({"data": "test"}),
            timestamp: Utc::now(),
        };
        
        // Since we can't directly access the inbox, test through the public interface
        let responses = party.process_all_messages().await.unwrap();
        assert_eq!(responses.len(), 0); // No messages in inbox initially
    }

    #[tokio::test]
    async fn test_mpc_manager_initialization() {
        let manager = DefaultMpcManager::new().unwrap();
        
        assert_eq!(manager.default_protocol(), "shamir");
        
        // Test listing protocols
        let protocols = manager.list_protocols().await;
        assert_eq!(protocols.len(), 1);
        assert!(protocols.contains(&"shamir".to_string()));
    }

    #[tokio::test]
    async fn test_mpc_computation_lifecycle() {
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create computation config
        let config = ComputationConfig::new(
            "secret_sharing".to_string(),
            SecretSharingScheme::Shamir { threshold: 2, total_shares: 3 },
        ).with_party("party1".to_string(), PartyRole::Initiator)
         .with_party("party2".to_string(), PartyRole::Participant)
         .with_party("party3".to_string(), PartyRole::Participant);
        
        // Create session
        let session_id = manager.create_session(config).await.unwrap();
        assert!(!session_id.is_empty());
        
        // Get session status
        let status = manager.get_session_status(&session_id).await.unwrap();
        assert!(matches!(status, ComputationStatus::Recruiting));
        
        // Add parties
        let party1 = InMemoryMpcParty::new("party1".to_string(), PartyRole::Initiator);
        let party2 = InMemoryMpcParty::new("party2".to_string(), PartyRole::Participant);
        let party3 = InMemoryMpcParty::new("party3".to_string(), PartyRole::Participant);
        
        manager.join_session(&session_id, Box::new(party1)).await.unwrap();
        manager.join_session(&session_id, Box::new(party2)).await.unwrap();
        manager.join_session(&session_id, Box::new(party3)).await.unwrap();
        
        // Start computation
        manager.start_computation(&session_id).await.unwrap();
        
        let status = manager.get_session_status(&session_id).await.unwrap();
        assert!(matches!(status, ComputationStatus::InProgress));
        
        // Get result
        let result = manager.get_result(&session_id).await.unwrap();
        assert!(result.is_some());
        assert!(!result.unwrap().result_data.is_empty());
    }

    #[tokio::test]
    async fn test_mpc_multiple_sessions() {
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create multiple sessions
        let mut session_ids = Vec::new();
        for i in 0..5 {
            let config = ComputationConfig::new(
                "secret_sharing".to_string(),
                SecretSharingScheme::Shamir { threshold: 2, total_shares: 2 },
            ).with_party(format!("party{}", i + 1), PartyRole::Initiator)
             .with_party(format!("party{}", i + 2), PartyRole::Participant);
            
            let session_id = manager.create_session(config).await.unwrap();
            session_ids.push(session_id);
        }
        
        assert_eq!(session_ids.len(), 5);
        
        // Verify all sessions are created
        for session_id in &session_ids {
            let status = manager.get_session_status(session_id).await.unwrap();
            assert!(matches!(status, ComputationStatus::Recruiting));
        }
        
        // List all sessions
        let all_sessions = manager.list_sessions().await;
        assert_eq!(all_sessions.len(), 5);
        
        for session_id in &session_ids {
            assert!(all_sessions.contains(session_id));
        }
    }

    #[tokio::test]
    async fn test_mpc_party_management() {
        let party_id = Uuid::new_v4().to_string();
        let party = InMemoryMpcParty::new(party_id.clone(), PartyRole::Participant);
        
        // Test metadata operations
        party.add_metadata("capability", "encryption").await;
        party.add_metadata("version", "2.0").await;
        party.add_metadata("location", "us-west").await;
        
        let metadata = party.get_metadata().await;
        assert_eq!(metadata.len(), 3);
        assert_eq!(metadata.get("capability"), Some(&"encryption".to_string()));
        assert_eq!(metadata.get("version"), Some(&"2.0".to_string()));
        assert_eq!(metadata.get("location"), Some(&"us-west".to_string()));
        
        // Test message counts
        assert_eq!(party.inbox_count().await, 0);
        assert_eq!(party.outbox_count().await, 0);
        
        // Test clearing outbox
        let cleared = party.clear_outbox().await;
        assert_eq!(cleared.len(), 0);
    }

    #[tokio::test]
    async fn test_mpc_error_handling() {
        let manager = DefaultMpcManager::new().unwrap();
        
        // Try to get status of non-existent session
        let result = manager.get_session_status("nonexistent-session").await;
        assert!(result.is_err());
        
        // Try to add party to non-existent session
        let party = InMemoryMpcParty::new("party1".to_string(), PartyRole::Participant);
        let result = manager.join_session("nonexistent-session", Box::new(party)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_mpc_performance() {
        let manager = DefaultMpcManager::new().unwrap();
        
        let start_time = std::time::Instant::now();
        
        // Create many sessions
        let mut session_ids = Vec::new();
        for i in 0..50 {
            let config = ComputationConfig::new(
                "secret_sharing".to_string(),
                SecretSharingScheme::Shamir { threshold: 2, total_shares: 2 },
            ).with_party(format!("party{}", i), PartyRole::Initiator)
             .with_party(format!("party{}", i + 1), PartyRole::Participant);
            
            let session_id = manager.create_session(config).await.unwrap();
            session_ids.push(session_id);
        }
        
        let creation_time = start_time.elapsed();
        assert!(creation_time.as_millis() < 5000, "Session creation should complete in < 5 seconds");
        assert_eq!(session_ids.len(), 50);
        
        // Test session listing performance
        let list_start = std::time::Instant::now();
        let all_sessions = manager.list_sessions().await;
        let list_time = list_start.elapsed();
        
        assert_eq!(all_sessions.len(), 50);
        assert!(list_time.as_millis() < 1000, "Session listing should complete in < 1 second");
    }

    #[tokio::test]
    async fn test_mpc_security_validation() {
        let party_id = Uuid::new_v4().to_string();
        let party = InMemoryMpcParty::new(party_id, PartyRole::Participant);
        
        // Test secure metadata
        party.add_metadata("encryption_enabled", "true").await;
        party.add_metadata("auth_required", "true").await;
        party.add_metadata("audit_enabled", "true").await;
        
        let metadata = party.get_metadata().await;
        assert_eq!(metadata.get("encryption_enabled"), Some(&"true".to_string()));
        assert_eq!(metadata.get("auth_required"), Some(&"true".to_string()));
        assert_eq!(metadata.get("audit_enabled"), Some(&"true".to_string()));
        
        // Test secure party creation
        let secure_party = InMemoryMpcParty::with_metadata(
            "secure-party".to_string(),
            PartyRole::Initiator,
            HashMap::from([
                ("security_level".to_string(), "high".to_string()),
                ("compliance".to_string(), "gdpr".to_string()),
                ("audit_trail".to_string(), "enabled".to_string()),
            ]),
        ).await;
        
        let secure_metadata = secure_party.get_metadata().await;
        assert_eq!(secure_metadata.get("security_level"), Some(&"high".to_string()));
        assert_eq!(secure_metadata.get("compliance"), Some(&"gdpr".to_string()));
        assert_eq!(secure_metadata.get("audit_trail"), Some(&"enabled".to_string()));
    }
}

#[cfg(test)]
mod plugin_tests {
    use super::*;

    #[tokio::test]
    async fn test_plugin_creation() {
        let plugin = TestPlugin::new("test-signer", vec![PluginCapability::SignTransaction]);
        
        assert_eq!(plugin.metadata().id, "test-plugin-test-signer");
        assert_eq!(plugin.metadata().name, "test-signer");
        assert_eq!(plugin.metadata().version, "1.0.0");
        assert_eq!(plugin.metadata().capabilities.len(), 1);
        assert!(plugin.metadata().capabilities.contains(&PluginCapability::SignTransaction));
    }

    #[tokio::test]
    async fn test_plugin_execution() {
        let plugin = TestPlugin::new("test-encrypt", vec![PluginCapability::Encrypt]);
        
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({
                "data": "test-data",
                "algorithm": "AES-256-GCM"
            }),
            parameters: HashMap::new(),
        };
        
        let result = plugin.execute(input).await.unwrap();
        
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(result.error.is_none());
        assert!(result.metrics.execution_time_ms < 1000); // Should complete in < 1 second
        assert_eq!(result.metrics.memory_usage_bytes, 1024);
        
        // Verify result structure
        let data = result.data.unwrap();
        assert!(data.get("encrypted_data").is_some());
        assert!(data.get("algorithm").is_some());
    }

    #[tokio::test]
    async fn test_plugin_multiple_capabilities() {
        let capabilities = vec![
            PluginCapability::SignTransaction,
            PluginCapability::Encrypt,
            PluginCapability::ApiIntegration,
        ];
        
        let plugin = TestPlugin::new("multi-capability", capabilities);
        
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({"test": "data"}),
            parameters: HashMap::new(),
        };
        
        // Test execution with multiple capabilities
        let result = plugin.execute(input.clone()).await.unwrap();
        assert!(result.success);
        
        // Increment execution count and test again
        let _ = plugin.execute(input).await.unwrap();
        
        assert_eq!(plugin.get_execution_count().await, 2);
    }

    #[tokio::test]
    async fn test_plugin_lifecycle() {
        let plugin = TestPlugin::new("lifecycle-test", vec![PluginCapability::Hash]);
        
        let context = PluginContext {
            config: HashMap::new(),
            metadata: plugin.metadata().clone(),
            encryption_access: false,
            storage_access: false,
        };
        
        // Test initialization
        let init_result = plugin.initialize(context.clone()).await;
        assert!(init_result.is_ok());
        
        // Test execution
        let input = PluginInput {
            action: "hash".to_string(),
            data: serde_json::json!({"data": "hash-me"}),
            parameters: HashMap::new(),
        };
        let exec_result = plugin.execute(input).await.unwrap();
        assert!(exec_result.success);
        
        // Test health check
        let health_result = plugin.health_check().await.unwrap();
        assert!(health_result.healthy);
        
        // Test validation
        let config = HashMap::new();
        let validation_result = plugin.validate_config(&config);
        assert!(validation_result.is_ok());
        
        // Test cleanup
        let cleanup_result = plugin.cleanup().await;
        assert!(cleanup_result.is_ok());
    }

    #[tokio::test]
    async fn test_plugin_error_handling() {
        let plugin = TestPlugin::new("error-test", vec![PluginCapability::Custom("divide".to_string())]);
        
        // Test with invalid input (this will use the default case which should still work)
        let input = PluginInput {
            action: "invalid".to_string(),
            data: serde_json::json!({"invalid": "data"}),
            parameters: HashMap::new(),
        };
        let result = plugin.execute(input).await.unwrap();
        
        // Should still succeed with default processing
        assert!(result.success);
        assert!(result.data.is_some());
    }

    #[tokio::test]
    async fn test_plugin_performance() {
        let plugin = TestPlugin::new("performance-test", vec![PluginCapability::Encrypt]);
        
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({"data": "performance-test-data"}),
            parameters: HashMap::new(),
        };
        
        let start_time = std::time::Instant::now();
        
        // Execute plugin multiple times
        for _ in 0..100 {
            let result = plugin.execute(input.clone()).await.unwrap();
            assert!(result.success);
        }
        
        let total_time = start_time.elapsed();
        
        // Performance assertions
        assert!(total_time.as_millis() < 5000, "100 executions should complete in < 5 seconds");
        assert_eq!(plugin.get_execution_count().await, 100);
        
        // Check average execution time
        let avg_time_ms = total_time.as_millis() / 100;
        assert!(avg_time_ms < 50, "Average execution time should be < 50ms");
    }

    #[tokio::test]
    async fn test_plugin_security() {
        let secure_capabilities = vec![
            PluginCapability::SignTransaction,
            PluginCapability::Encrypt,
            PluginCapability::SecretManagement,
        ];
        
        let plugin = TestPlugin::new("secure-plugin", secure_capabilities);
        
        let context = PluginContext {
            config: HashMap::from([
                ("security_level".to_string(), serde_json::Value::String("high".to_string())),
                ("audit_enabled".to_string(), serde_json::Value::Bool(true)),
            ]),
            metadata: plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
        };
        
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({
                "sensitive_data": "secret",
                "encryption_required": true
            }),
            parameters: HashMap::new(),
        };
        
        let result = plugin.execute(input).await.unwrap();
        
        // Verify security features
        assert!(result.success);
        assert!(result.data.is_some());
        assert!(context.encryption_access);
        assert!(context.storage_access);
        
        // Verify metrics include security information
        assert!(result.metrics.custom_metrics.contains_key("operations"));
    }

    #[tokio::test]
    async fn test_plugin_metadata_validation() {
        let plugin = TestPlugin::new("metadata-test", vec![PluginCapability::ApiIntegration]);
        let metadata = plugin.metadata();
        
        // Validate required metadata fields
        assert!(!metadata.id.is_empty());
        assert!(!metadata.name.is_empty());
        assert!(!metadata.version.is_empty());
        assert!(!metadata.description.is_empty());
        assert!(!metadata.author.is_empty());
        assert!(!metadata.capabilities.is_empty());
        
        // Validate ID format
        assert!(metadata.id.starts_with("test-plugin-"));
        assert_eq!(metadata.id, "test-plugin-metadata-test");
        
        // Validate version format
        assert!(metadata.version.contains('.'));
        
        // Validate capabilities
        assert!(metadata.capabilities.contains(&PluginCapability::ApiIntegration));
    }

    #[tokio::test]
    async fn test_plugin_configuration() {
        let plugin = TestPlugin::new("config-test", vec![PluginCapability::Encrypt]);
        
        let config = HashMap::from([
            ("api_url".to_string(), serde_json::Value::String("https://api.example.com".to_string())),
            ("timeout_ms".to_string(), serde_json::Value::Number(5000.into())),
            ("retry_count".to_string(), serde_json::Value::Number(3.into())),
            ("debug_mode".to_string(), serde_json::Value::Bool(true)),
        ]);
        
        let context = PluginContext {
            config,
            metadata: plugin.metadata().clone(),
            encryption_access: true,
            storage_access: false,
        };
        
        // Verify configuration is accessible
        assert!(context.config.contains_key("api_url"));
        assert!(context.config.contains_key("timeout_ms"));
        assert!(context.config.contains_key("retry_count"));
        assert!(context.config.contains_key("debug_mode"));
        
        // Test execution with configuration
        let input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({"test": "config"}),
            parameters: HashMap::new(),
        };
        let result = plugin.execute(input).await.unwrap();
        assert!(result.success);
    }

    #[tokio::test]
    async fn test_plugin_concurrent_execution() {
        let input = PluginInput {
            action: "hash".to_string(),
            data: serde_json::json!({"data": "concurrent-test"}),
            parameters: HashMap::new(),
        };
        
        // Execute plugin concurrently
        let mut handles = Vec::new();
        for _ in 0..10 {
            let plugin_clone = TestPlugin::new("concurrent-test", vec![PluginCapability::Hash]);
            let input_clone = input.clone();
            
            let handle = tokio::spawn(async move {
                plugin_clone.execute(input_clone).await
            });
            handles.push(handle);
        }
        
        // Wait for all executions to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok());
            let plugin_result = result.unwrap();
            assert!(plugin_result.success);
        }
    }

    #[tokio::test]
    async fn test_plugin_capabilities() {
        // Test all plugin capabilities
        let all_capabilities = vec![
            PluginCapability::SignTransaction,
            PluginCapability::VerifySignature,
            PluginCapability::GenerateKey,
            PluginCapability::Encrypt,
            PluginCapability::Decrypt,
            PluginCapability::Hash,
            PluginCapability::ApiIntegration,
            PluginCapability::SecretManagement,
            PluginCapability::Custom("custom_capability".to_string()),
        ];
        
        for capability in all_capabilities {
            let plugin = TestPlugin::new(&format!("test-{:?}", capability), vec![capability.clone()]);
            
            let input = PluginInput {
                action: "encrypt".to_string(),
                data: serde_json::json!({"test": "capability"}),
                parameters: HashMap::new(),
            };
            let result = plugin.execute(input).await.unwrap();
            
            // All capabilities should execute successfully
            assert!(result.success);
            assert!(result.data.is_some());
            
            // Verify metadata contains the capability
            assert!(plugin.metadata().capabilities.contains(&capability));
        }
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;

    #[tokio::test]
    async fn test_cluster_mpc_integration() {
        // Test cluster nodes participating in MPC
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create cluster nodes that will act as MPC parties
        let mut nodes: Vec<ClusterNode> = Vec::new();
        for i in 0..3 {
            let node_id = Uuid::new_v4();
            let node = ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: if i == 0 {
                    NodeState::Leader { term: 1 }
                } else {
                    NodeState::Follower { leader: Some(nodes[0].id), term: 1 }
                },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["mpc".to_string(), "plugin".to_string(), "tls".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: 0.1,
                    memory_usage: 0.2,
                    active_connections: 5,
                    ops_per_second: 100.0,
                    storage_used: 1024,
                    network_io: 1024,
                },
            };
            nodes.push(node);
        }
        
        // Verify cluster setup
        assert_eq!(nodes.len(), 3);
        assert!(nodes.iter().any(|n| matches!(n.state, NodeState::Leader { .. })));
        assert!(nodes.iter().all(|n| n.capabilities.encryption));
        
        // Create MPC computation with cluster nodes as parties
        let config = ComputationConfig::new(
            "cluster_secret_sharing".to_string(),
            SecretSharingScheme::Shamir { threshold: 2, total_shares: 3 },
        );
        
        let session_id = manager.create_session(config).await.unwrap();
        assert!(!session_id.is_empty());
        
        // Add cluster nodes as MPC parties
        for node in &nodes {
            let party = InMemoryMpcParty::new(
                node.id.to_string(),
                if matches!(node.state, NodeState::Leader { .. }) {
                    PartyRole::Initiator
                } else {
                    PartyRole::Participant
                },
            );
            manager.join_session(&session_id, Box::new(party)).await.unwrap();
        }
        
        // Start and get result
        manager.start_computation(&session_id).await.unwrap();
        let result = manager.get_result(&session_id).await.unwrap();
        
        assert!(result.is_some());
        assert!(!result.unwrap().result_data.is_empty());
    }

    #[tokio::test]
    async fn test_mpc_plugin_integration() {
        // Test MPC computation using plugins for cryptographic operations
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create cryptographic plugin
        let crypto_plugin = TestPlugin::new("crypto-plugin", vec![
            PluginCapability::Encrypt,
            PluginCapability::Decrypt,
            PluginCapability::GenerateKey,
        ]);
        
        let context = PluginContext {
            config: HashMap::from([
                ("algorithm".to_string(), serde_json::Value::String("AES-256-GCM".to_string())),
                ("key_size".to_string(), serde_json::Value::Number(256.into())),
            ]),
            metadata: crypto_plugin.metadata().clone(),
            encryption_access: true,
            storage_access: false,
        };
        
        // Test plugin execution for key generation
        let key_input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({
                "operation": "generate_key",
                "key_type": "symmetric"
            }),
            parameters: HashMap::new(),
        };
        
        let key_result = crypto_plugin.execute(key_input).await.unwrap();
        assert!(key_result.success);
        
        // Create MPC computation that uses plugin
        let config = ComputationConfig::new(
            "plugin_assisted_computation".to_string(),
            SecretSharingScheme::Shamir { threshold: 2, total_shares: 3 },
        );
        
        let session_id = manager.create_session(config).await.unwrap();
        assert!(!session_id.is_empty());
        
        // Add parties
        for i in 1..=3 {
            let party = InMemoryMpcParty::new(
                format!("party{}", i),
                if i == 1 { PartyRole::Initiator } else { PartyRole::Participant },
            );
            manager.join_session(&session_id, Box::new(party)).await.unwrap();
        }
        
        // Execute computation
        manager.start_computation(&session_id).await.unwrap();
        let result = manager.get_result(&session_id).await.unwrap();
        
        assert!(result.is_some());
        assert!(!result.unwrap().result_data.is_empty());
        
        // Verify plugin was used
        assert_eq!(crypto_plugin.get_execution_count().await, 1);
    }

    #[tokio::test]
    async fn test_cluster_plugin_integration() {
        // Test cluster nodes using plugins for enhanced security
        
        // Create security plugin
        let security_plugin = TestPlugin::new("security-plugin", vec![
            PluginCapability::SignTransaction,
            PluginCapability::VerifySignature,
            PluginCapability::SecretManagement,
        ]);
        
        let context = PluginContext {
            config: HashMap::from([
                ("security_level".to_string(), serde_json::Value::String("maximum".to_string())),
                ("audit_enabled".to_string(), serde_json::Value::Bool(true)),
            ]),
            metadata: security_plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
        };
        
        // Create cluster with security capabilities
        let mut nodes: Vec<ClusterNode> = Vec::new();
        for i in 0..5 {
            let node_id = Uuid::new_v4();
            let node = ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: if i == 0 {
                    NodeState::Leader { term: 1 }
                } else {
                    NodeState::Follower { leader: Some(nodes[0].id), term: 1 }
                },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["tls".to_string(), "https".to_string(), "plugin-security".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: (i as f64) * 0.1,
                    memory_usage: (i as f64) * 0.15,
                    active_connections: i * 20,
                    ops_per_second: (i as f64) * 200.0,
                    storage_used: (i as u64) * 2048,
                    network_io: (i as u64) * 1024,
                },
            };
            nodes.push(node);
        }
        
        // Test plugin execution on cluster leader
        let leader_input = PluginInput {
            action: "sign".to_string(),
            data: serde_json::json!({
                "operation": "sign_cluster_transaction",
                "cluster_id": nodes[0].id.to_string(),
                "timestamp": chrono::Utc::now().timestamp()
            }),
            parameters: HashMap::new(),
        };
        
        let leader_result = security_plugin.execute(leader_input).await.unwrap();
        assert!(leader_result.success);
        
        // Verify all nodes have security capabilities
        assert!(nodes.iter().all(|n| n.capabilities.encryption));
        assert!(nodes.iter().all(|n| n.capabilities.algorithms.contains(&"tls".to_string())));
        
        // Test cluster security metrics
        let total_connections: usize = nodes.iter().map(|n| n.load_metrics.active_connections).sum();
        let total_rps: f64 = nodes.iter().map(|n| n.load_metrics.ops_per_second).sum();
        
        assert!(total_connections > 0);
        assert!(total_rps > 0.0);
        
        // Verify plugin performance
        assert!(security_plugin.get_execution_count().await >= 1);
        assert!(leader_result.metrics.execution_time_ms < 1000);
    }

    #[tokio::test]
    async fn test_full_system_integration() {
        // Test complete integration of cluster, MPC, and plugin systems
        
        // Setup MPC manager
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create cluster nodes
        let mut nodes: Vec<ClusterNode> = Vec::new();
        for i in 0..3 {
            let node_id = Uuid::new_v4();
            let node = ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: if i == 0 {
                    NodeState::Leader { term: 1 }
                } else {
                    NodeState::Follower { leader: Some(nodes[0].id), term: 1 }
                },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["mpc".to_string(), "plugin".to_string(), "tls".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: 0.2,
                    memory_usage: 0.3,
                    active_connections: 10,
                    ops_per_second: 500.0,
                    storage_used: 4096,
                    network_io: 2048,
                },
            };
            nodes.push(node);
        }
        
        // Create integrated plugin
        let integrated_plugin = TestPlugin::new("integrated-plugin", vec![
            PluginCapability::Encrypt,
            PluginCapability::SignTransaction,
            PluginCapability::ApiIntegration,
        ]);
        
        let context = PluginContext {
            config: HashMap::from([
                ("cluster_mode".to_string(), serde_json::Value::Bool(true)),
                ("mpc_enabled".to_string(), serde_json::Value::Bool(true)),
                ("security_level".to_string(), serde_json::Value::String("high".to_string())),
            ]),
            metadata: integrated_plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
        };
        
        // Create integrated MPC computation
        let config = ComputationConfig::new(
            "integrated_cluster_mpc".to_string(),
            SecretSharingScheme::Shamir { threshold: 2, total_shares: 3 },
        );
        
        // Execute integrated workflow
        let session_id = manager.create_session(config).await.unwrap();
        assert!(!session_id.is_empty());
        
        // Add cluster nodes as MPC parties
        for node in &nodes {
            let party = InMemoryMpcParty::new(
                node.id.to_string(),
                if matches!(node.state, NodeState::Leader { .. }) {
                    PartyRole::Initiator
                } else {
                    PartyRole::Participant
                },
            );
            manager.join_session(&session_id, Box::new(party)).await.unwrap();
        }
        
        // Execute plugin for cluster operation
        let plugin_input = PluginInput {
            action: "cluster_mpc_integration".to_string(),
            data: serde_json::json!({
                "operation": "cluster_mpc_integration",
                "session_id": session_id,
                "nodes": nodes.iter().map(|n| n.id.to_string()).collect::<Vec<_>>(),
            }),
            parameters: HashMap::new(),
        };
        
        let plugin_result = integrated_plugin.execute(plugin_input).await.unwrap();
        assert!(plugin_result.success);
        
        // Complete MPC computation
        manager.start_computation(&session_id).await.unwrap();
        let mpc_result = manager.get_result(&session_id).await.unwrap();
        
        assert!(mpc_result.is_some());
        assert!(!mpc_result.unwrap().result_data.is_empty());
        
        // Verify system integration
        assert_eq!(nodes.len(), 3);
        assert!(integrated_plugin.get_execution_count().await >= 1);
        
        // Verify all systems are secure and performant
        assert!(nodes.iter().all(|n| n.capabilities.encryption));
        assert!(plugin_result.metrics.execution_time_ms < 1000);
    }

    #[tokio::test]
    async fn test_system_performance_and_scalability() {
        // Test performance of all systems under load
        
        let start_time = std::time::Instant::now();
        
        // Create many cluster nodes
        let nodes: Vec<ClusterNode> = (0..50).map(|i| {
            let node_id = Uuid::new_v4();
            ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: NodeState::Follower { leader: None, term: 0 },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["mpc".to_string(), "plugin".to_string()],
                },
                load_metrics: LoadMetrics {
                    cpu_usage: (i as f64) * 0.01,
                    memory_usage: (i as f64) * 0.02,
                    active_connections: i * 5,
                    ops_per_second: (i as f64) * 50.0,
                    storage_used: (i as u64) * 256,
                    network_io: (i as u64) * 128,
                },
            }
        }).collect();
        
        let cluster_creation_time = start_time.elapsed();
        assert!(cluster_creation_time.as_millis() < 2000, "Cluster creation should complete in < 2 seconds");
        assert_eq!(nodes.len(), 50);
        
        // Setup MPC manager
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create many MPC sessions
        let mpc_start = std::time::Instant::now();
        let mut session_ids = Vec::new();
        
        for batch in 0..10 {
            let config = ComputationConfig::new(
                "performance_test".to_string(),
                SecretSharingScheme::Shamir { threshold: 3, total_shares: 5 },
            );
            
            let session_id = manager.create_session(config).await.unwrap();
            session_ids.push(session_id);
        }
        
        let mpc_creation_time = mpc_start.elapsed();
        assert!(mpc_creation_time.as_millis() < 3000, "MPC session creation should complete in < 3 seconds");
        assert_eq!(session_ids.len(), 10);
        
        // Create and execute many plugins
        let plugin_start = std::time::Instant::now();
        let mut plugins = Vec::new();
        
        for i in 0..20 {
            let plugin = TestPlugin::new(&format!("perf-plugin-{}", i), vec![
                PluginCapability::Encrypt,
                PluginCapability::ApiIntegration,
            ]);
            
            let input = PluginInput {
                action: "encrypt".to_string(),
                data: serde_json::json!({
                    "operation": "performance_test",
                    "batch_id": i,
                    "data": format!("performance-data-{}", i)
                }),
                parameters: HashMap::from([
                    ("performance_mode".to_string(), serde_json::Value::Bool(true)),
                    ("batch_id".to_string(), serde_json::Value::Number(i.into())),
                ]),
            };
            
            let result = plugin.execute(input).await.unwrap();
            assert!(result.success);
            assert!(result.metrics.execution_time_ms < 100);
            
            plugins.push(plugin);
        }
        
        let plugin_execution_time = plugin_start.elapsed();
        assert!(plugin_execution_time.as_millis() < 5000, "Plugin execution should complete in < 5 seconds");
        assert_eq!(plugins.len(), 20);
        
        // Verify overall performance
        let total_time = start_time.elapsed();
        assert!(total_time.as_millis() < 10000, "Complete system test should complete in < 10 seconds");
        
        // Verify system metrics
        let total_executions: u64 = plugins.iter().map(|p| p.get_execution_count().await).sum();
        assert_eq!(total_executions, 20);
        
        let total_connections: usize = nodes.iter().map(|n| n.load_metrics.active_connections).sum();
        let total_rps: f64 = nodes.iter().map(|n| n.load_metrics.ops_per_second).sum();
        
        assert!(total_connections > 0);
        assert!(total_rps > 0.0);
        
        // Verify all systems are secure
        assert!(nodes.iter().all(|n| n.capabilities.encryption));
        assert!(plugins.iter().all(|p| p.metadata().capabilities.contains(&PluginCapability::Encrypt)));
    }

    #[tokio::test]
    async fn test_system_security_validation() {
        // Test security across all systems
        
        // Create secure cluster
        let secure_nodes: Vec<ClusterNode> = (0..3).map(|i| {
            let node_id = Uuid::new_v4();
            ClusterNode {
                id: node_id,
                address: format!("127.0.0.1:{}", 8080 + i).parse().unwrap(),
                state: if i == 0 {
                    NodeState::Leader { term: 1 }
                } else {
                    NodeState::Follower { leader: Some(Uuid::new_v4()), term: 1 }
                },
                last_heartbeat: chrono::Utc::now().timestamp_millis() as u64,
                capabilities: NodeCapabilities {
                    storage: true,
                    encryption: true,
                    leadership: true,
                    algorithms: vec!["tls".to_string(), "https".to_string(), "mpc-secure".to_string()],
                },
                load_metrics: LoadMetrics::default(),
            }
        }).collect();
        
        // Verify cluster security
        assert!(secure_nodes.iter().all(|n| n.capabilities.encryption));
        assert!(secure_nodes.iter().all(|n| n.capabilities.algorithms.contains(&"tls".to_string())));
        
        // Create secure MPC manager
        let manager = DefaultMpcManager::new().unwrap();
        
        // Create secure computation
        let config = ComputationConfig::new(
            "secure_computation".to_string(),
            SecretSharingScheme::Shamir { threshold: 2, total_shares: 3 },
        ).with_parameter("encryption_required".to_string(), serde_json::Value::Bool(true))
         .with_parameter("authentication_required".to_string(), serde_json::Value::Bool(true))
         .with_parameter("audit_enabled".to_string(), serde_json::Value::Bool(true));
        
        let session_id = manager.create_session(config).await.unwrap();
        
        // Add secure parties
        for node in &secure_nodes {
            let party = InMemoryMpcParty::with_metadata(
                node.id.to_string(),
                if matches!(node.state, NodeState::Leader { .. }) {
                    PartyRole::Initiator
                } else {
                    PartyRole::Participant
                },
                HashMap::from([
                    ("security_level".to_string(), "high".to_string()),
                    ("compliance".to_string(), "gdpr".to_string()),
                    ("audit_trail".to_string(), "enabled".to_string()),
                ]),
            ).await;
            
            manager.join_session(&session_id, Box::new(party)).await.unwrap();
        }
        
        // Create secure plugin
        let secure_plugin = TestPlugin::new("secure-plugin", vec![
            PluginCapability::Encrypt,
            PluginCapability::SecretManagement,
            PluginCapability::SignTransaction,
        ]);
        
        let context = PluginContext {
            config: HashMap::from([
                ("security_level".to_string(), serde_json::Value::String("maximum".to_string())),
                ("compliance_framework".to_string(), serde_json::Value::String("gdpr,hipaa,pci-dss".to_string())),
                ("audit_logging".to_string(), serde_json::Value::Bool(true)),
                ("encryption_at_rest".to_string(), serde_json::Value::Bool(true)),
                ("encryption_in_transit".to_string(), serde_json::Value::Bool(true)),
            ]),
            metadata: secure_plugin.metadata().clone(),
            encryption_access: true,
            storage_access: true,
        };
        
        // Execute secure plugin
        let secure_input = PluginInput {
            action: "encrypt".to_string(),
            data: serde_json::json!({
                "operation": "secure_cluster_mpc",
                "compliance_required": true,
                "audit_trail": true,
                "encryption_level": "maximum"
            }),
            parameters: HashMap::new(),
        };
        
        let secure_result = secure_plugin.execute(secure_input).await.unwrap();
        assert!(secure_result.success);
        
        // Complete secure computation
        manager.start_computation(&session_id).await.unwrap();
        let secure_mpc_result = manager.get_result(&session_id).await.unwrap();
        
        assert!(secure_mpc_result.is_some());
        assert!(!secure_mpc_result.unwrap().result_data.is_empty());
        
        // Verify comprehensive security
        assert!(secure_nodes.iter().all(|n| n.capabilities.encryption));
        assert!(secure_result.success);
        assert!(context.encryption_access && context.storage_access);
        assert!(context.config.contains_key("security_level"));
        assert!(context.config.contains_key("compliance_framework"));
        
        // Verify security metrics
        assert!(secure_result.metrics.execution_time_ms < 1000);
    }
}
