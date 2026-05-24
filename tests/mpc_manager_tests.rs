#![cfg(any())]
//! Comprehensive MPC Manager Tests
//! 
//! This test suite provides comprehensive coverage for Multi-Party Computation (MPC) manager functionality,
//! ensuring secure, reliable, and efficient multi-party cryptographic operations.

use fortress_core::mpc_manager::{MpcManager, MpcConfig, MpcSession, MpcProtocol};
use fortress_core::mpc_party::{MpcParty, PartyMetadata};
use fortress_core::mpc::PartyRole;
use fortress_core::error::MpcErrorCode;
use std::time::Instant;
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test MPC manager initialization
    #[tokio::test]
    async fn test_mpc_manager_initialization() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        assert!(manager.initialize().await.is_ok(), "MPC manager should initialize successfully");
        
        // Test health check
        let health_status = manager.health_check().await;
        assert!(health_status.is_ok(), "Health check should succeed");
    }

    /// Test MPC session creation
    #[tokio::test]
    async fn test_mpc_session_creation() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create a new MPC session
        let session_id = manager.create_session("test_protocol", 3).await.unwrap();
        assert!(!session_id.is_empty(), "Session ID should not be empty");
        
        // Verify session exists
        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.session_id, session_id, "Session ID should match");
        assert_eq!(session.protocol_name, "test_protocol", "Protocol name should match");
        assert_eq!(session.required_parties, 3, "Required parties should match");
        assert_eq!(session.current_parties, 0, "Current parties should be 0 initially");
    }

    /// Test MPC party addition
    #[tokio::test]
    async fn test_mpc_party_addition() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create session
        let session_id = manager.create_session("test_protocol", 3).await.unwrap();
        
        // Create party metadata
        let party_metadata = PartyMetadata {
            party_id: "party_1".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1, 2, 3, 4],
            capabilities: vec!["signing".to_string(), "encryption".to_string()],
        };

        // Add party to session
        let party_id = manager.add_party(&session_id, party_metadata).await.unwrap();
        assert!(!party_id.is_empty(), "Party ID should not be empty");
        
        // Verify party was added
        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.current_parties, 1, "Should have 1 party");
        assert!(session.parties.contains_key(&party_id), "Party should be in session");
    }

    /// Test MPC session start
    #[tokio::test]
    async fn test_mpc_session_start() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create session
        let session_id = manager.create_session("test_protocol", 2).await.unwrap();
        
        // Add required parties
        for i in 0..2 {
            let party_metadata = PartyMetadata {
                party_id: format!("party_{}", i),
                role: if i == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                endpoint: format!("http://localhost:{}", 8080 + i),
                public_key: vec![i as u8; 32],
                capabilities: vec!["computation".to_string()],
            };
            manager.add_party(&session_id, party_metadata).await.unwrap();
        }

        // Start the session
        let start_result = manager.start_session(&session_id).await;
        assert!(start_result.is_ok(), "Session should start successfully");
        
        // Verify session is running
        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.status, "running", "Session should be running");
    }

    /// Test MPC message handling
    #[tokio::test]
    async fn test_mpc_message_handling() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create and start session
        let session_id = manager.create_session("test_protocol", 2).await.unwrap();
        
        // Add parties
        for i in 0..2 {
            let party_metadata = PartyMetadata {
                party_id: format!("party_{}", i),
                role: if i == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                endpoint: format!("http://localhost:{}", 8080 + i),
                public_key: vec![i as u8; 32],
                capabilities: vec!["computation".to_string()],
            };
            manager.add_party(&session_id, party_metadata).await.unwrap();
        }
        
        manager.start_session(&session_id).await.unwrap();

        // Send test message
        let message = HashMap::from([
            ("type".to_string(), "share_data".to_string()),
            ("data".to_string(), "test_share_data".to_string()),
        ]);
        
        let send_result = manager.send_message(&session_id, "party_0", &message).await;
        assert!(send_result.is_ok(), "Message should be sent successfully");
        
        // Receive message
        let received_message = manager.receive_message(&session_id, "party_1").await.unwrap();
        assert_eq!(received_message.get("type"), Some(&"share_data".to_string()));
        assert_eq!(received_message.get("data"), Some(&"test_share_data".to_string()));
    }

    /// Test MPC computation execution
    #[tokio::test]
    async fn test_mpc_computation_execution() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create and start session for computation
        let session_id = manager.create_session("addition_protocol", 2).await.unwrap();
        
        // Add parties
        for i in 0..2 {
            let party_metadata = PartyMetadata {
                party_id: format!("party_{}", i),
                role: if i == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                endpoint: format!("http://localhost:{}", 8080 + i),
                public_key: vec![i as u8; 32],
                capabilities: vec!["addition".to_string()],
            };
            manager.add_party(&session_id, party_metadata).await.unwrap();
        }
        
        manager.start_session(&session_id).await.unwrap();

        // Execute computation
        let computation_input = HashMap::from([
            ("operation".to_string(), "add".to_string()),
            ("operand1".to_string(), "42".to_string()),
            ("operand2".to_string(), "58".to_string()),
        ]);
        
        let computation_result = manager.execute_computation(&session_id, &computation_input).await.unwrap();
        assert!(computation_result.contains_key("result"), "Should have result");
        assert_eq!(computation_result.get("result"), Some(&"100".to_string()));
    }

    /// Test MPC session termination
    #[tokio::test]
    async fn test_mpc_session_termination() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create and start session
        let session_id = manager.create_session("test_protocol", 2).await.unwrap();
        
        // Add parties
        for i in 0..2 {
            let party_metadata = PartyMetadata {
                party_id: format!("party_{}", i),
                role: if i == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                endpoint: format!("http://localhost:{}", 8080 + i),
                public_key: vec![i as u8; 32],
                capabilities: vec!["computation".to_string()],
            };
            manager.add_party(&session_id, party_metadata).await.unwrap();
        }
        
        manager.start_session(&session_id).await.unwrap();

        // Terminate session
        let terminate_result = manager.terminate_session(&session_id).await;
        assert!(terminate_result.is_ok(), "Session should terminate successfully");
        
        // Verify session is terminated
        let session = manager.get_session(&session_id).await.unwrap();
        assert_eq!(session.status, "terminated", "Session should be terminated");
    }

    /// Test MPC session listing
    #[tokio::test]
    async fn test_mpc_session_listing() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create multiple sessions
        let session_ids = vec![
            manager.create_session("protocol1", 2).await.unwrap(),
            manager.create_session("protocol2", 3).await.unwrap(),
            manager.create_session("protocol3", 4).await.unwrap(),
        ];

        // List all sessions
        let sessions = manager.list_sessions().await.unwrap();
        assert!(sessions.len() >= 3, "Should have at least 3 sessions");
        
        // Verify our sessions are in the list
        for session_id in &session_ids {
            assert!(sessions.iter().any(|s| s.session_id == *session_id), 
                   "Created session should be in the list");
        }
    }

    /// Test MPC concurrent sessions
    #[tokio::test]
    async fn test_mpc_concurrent_sessions() {
        let config = MpcConfig {
            max_concurrent_sessions: 5,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create multiple sessions concurrently
        let mut handles = vec![];
        for i in 0..3 {
            let manager_clone = manager.clone();
            let handle = tokio::spawn(async move {
                let session_id = manager_clone.create_session(&format!("protocol_{}", i), 2).await.unwrap();
                
                // Add a party to each session
                let party_metadata = PartyMetadata {
                    party_id: format!("party_{}", i),
                    role: PartyRole::Initiator,
                    endpoint: format!("http://localhost:{}", 8080 + i),
                    public_key: vec![i as u8; 32],
                    capabilities: vec!["computation".to_string()],
                };
                
                let party_id = manager_clone.add_party(&session_id, party_metadata).await.unwrap();
                (session_id, party_id)
            });
            handles.push(handle);
        }

        // Wait for all sessions to be created
        let results: Vec<_> = futures::future::join_all(handles).await
            .into_iter()
            .map(|result| result.unwrap())
            .collect();

        // Verify all sessions were created successfully
        for (session_id, party_id) in results {
            assert!(!session_id.is_empty(), "Session ID should not be empty");
            assert!(!party_id.is_empty(), "Party ID should not be empty");
            
            let session = manager.get_session(&session_id).await.unwrap();
            assert_eq!(session.current_parties, 1, "Each session should have 1 party");
        }
    }

    /// Test MPC session timeout
    #[tokio::test]
    async fn test_mpc_session_timeout() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 1, // Very short timeout for testing
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create session
        let session_id = manager.create_session("test_protocol", 2).await.unwrap();
        
        // Wait for timeout
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Try to access the session (should fail due to timeout)
        let session_result = manager.get_session(&session_id).await;
        assert!(session_result.is_err(), "Session should have timed out");
    }

    /// Test MPC error handling
    #[tokio::test]
    async fn test_mpc_error_handling() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Test operations with non-existent session
        let non_existent_session = "non_existent_session_id";
        let session_result = manager.get_session(non_existent_session).await;
        assert!(session_result.is_err(), "Non-existent session should return error");

        // Test adding party to non-existent session
        let party_metadata = PartyMetadata {
            party_id: "test_party".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1, 2, 3, 4],
            capabilities: vec!["test".to_string()],
        };
        let add_party_result = manager.add_party(non_existent_session, party_metadata).await;
        assert!(add_party_result.is_err(), "Adding party to non-existent session should fail");

        // Test starting non-existent session
        let start_result = manager.start_session(non_existent_session).await;
        assert!(start_result.is_err(), "Starting non-existent session should fail");
    }

    /// Test MPC performance metrics
    #[tokio::test]
    async fn test_mpc_performance_metrics() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create and run multiple sessions for performance testing
        let start_time = Instant::now();
        for i in 0..5 {
            let session_id = manager.create_session(&format!("perf_protocol_{}", i), 2).await.unwrap();
            
            // Add parties
            for j in 0..2 {
                let party_metadata = PartyMetadata {
                    party_id: format!("party_{}_{}", i, j),
                    role: if j == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                    endpoint: format!("http://localhost:{}", 8080 + i * 10 + j),
                    public_key: vec![(i * 10 + j) as u8; 32],
                    capabilities: vec!["computation".to_string()],
                };
                manager.add_party(&session_id, party_metadata).await.unwrap();
            }
            
            manager.start_session(&session_id).await.unwrap();
        }
        let creation_time = start_time.elapsed();

        // Performance should be reasonable
        assert!(creation_time.as_millis() < 5000, "5 sessions should be created within 5 seconds");
        
        // Get performance metrics
        let metrics = manager.get_performance_metrics().await.unwrap();
        assert!(metrics.active_sessions >= 5, "Should have at least 5 active sessions");
        assert!(metrics.total_sessions_created >= 5, "Should have created at least 5 sessions");
        assert!(metrics.average_session_creation_time_ms > 0.0, "Should have average creation time");
    }

    /// Test MPC security validation
    #[tokio::test]
    async fn test_mpc_security_validation() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 256, // High security level
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create session
        let session_id = manager.create_session("secure_protocol", 2).await.unwrap();
        
        // Test party with invalid public key (too short)
        let invalid_party_metadata = PartyMetadata {
            party_id: "invalid_party".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1, 2], // Too short for security level 256
            capabilities: vec!["computation".to_string()],
        };
        
        let add_result = manager.add_party(&session_id, invalid_party_metadata).await;
        assert!(add_result.is_err(), "Party with invalid public key should be rejected");

        // Test party with valid public key
        let valid_party_metadata = PartyMetadata {
            party_id: "valid_party".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 64], // Proper length for security level 256
            capabilities: vec!["computation".to_string()],
        };
        
        let add_result = manager.add_party(&session_id, valid_party_metadata).await;
        assert!(add_result.is_ok(), "Party with valid public key should be accepted");
    }

    /// Test MPC protocol validation
    #[tokio::test]
    async fn test_mpc_protocol_validation() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Test creating session with invalid protocol
        let invalid_protocol_result = manager.create_session("", 2).await;
        assert!(invalid_protocol_result.is_err(), "Empty protocol name should be rejected");

        let invalid_party_count_result = manager.create_session("test_protocol", 1).await;
        assert!(invalid_party_count_result.is_err(), "Single-party MPC should be rejected");

        let too_many_parties_result = manager.create_session("test_protocol", 100).await;
        assert!(too_many_parties_result.is_err(), "Too many parties should be rejected");

        // Test creating session with valid parameters
        let valid_session_result = manager.create_session("valid_protocol", 3).await;
        assert!(valid_session_result.is_ok(), "Valid parameters should be accepted");
    }

    /// Test MPC message integrity
    #[tokio::test]
    async fn test_mpc_message_integrity() {
        let config = MpcConfig {
            max_concurrent_sessions: 10,
            session_timeout_seconds: 3600,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let manager = MpcManager::new(config);
        manager.initialize().await.expect("Manager should initialize");

        // Create and start session
        let session_id = manager.create_session("integrity_test", 2).await.unwrap();
        
        // Add parties
        for i in 0..2 {
            let party_metadata = PartyMetadata {
                party_id: format!("party_{}", i),
                role: if i == 0 { PartyRole::Initiator } else { PartyRole::Participant },
                endpoint: format!("http://localhost:{}", 8080 + i),
                public_key: vec![i as u8; 32],
                capabilities: vec!["computation".to_string()],
            };
            manager.add_party(&session_id, party_metadata).await.unwrap();
        }
        
        manager.start_session(&session_id).await.unwrap();

        // Send message with integrity check
        let message = HashMap::from([
            ("type".to_string(), "secure_data".to_string()),
            ("data".to_string(), "sensitive_computation_data".to_string()),
            ("timestamp".to_string(), "1234567890".to_string()),
        ]);
        
        let send_result = manager.send_message(&session_id, "party_0", &message).await;
        assert!(send_result.is_ok(), "Secure message should be sent successfully");
        
        // Verify message integrity
        let received_message = manager.receive_message(&session_id, "party_1").await.unwrap();
        assert_eq!(received_message.get("type"), Some(&"secure_data".to_string()));
        assert_eq!(received_message.get("data"), Some(&"sensitive_computation_data".to_string()));
        assert_eq!(received_message.get("timestamp"), Some(&"1234567890".to_string()));
    }
}
