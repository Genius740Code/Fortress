//! Comprehensive MPC Party Tests
//! 
//! This test suite provides comprehensive coverage for Multi-Party Computation (MPC) party functionality,
//! ensuring secure, reliable, and efficient party operations and communication.

use fortress_core::mpc_party::{MpcParty, PartyRole, PartyMetadata, PartyConfig, PartyMessage};
use fortress_core::mpc_manager::MpcSession;
use fortress_core::error::{FortressError, MpcErrorCode};
use std::time::Instant;
use std::collections::HashMap;
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test MPC party creation
    #[tokio::test]
    async fn test_mpc_party_creation() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "test_party_1".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1, 2, 3, 4, 5, 6, 7, 8],
            capabilities: vec!["signing".to_string(), "encryption".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        assert!(party.initialize().await.is_ok(), "MPC party should initialize successfully");
        
        // Verify party metadata
        let party_metadata = party.get_metadata().await;
        assert_eq!(party_metadata.party_id, "test_party_1", "Party ID should match");
        assert_eq!(party_metadata.role, PartyRole::Initiator, "Role should match");
        assert_eq!(party_metadata.endpoint, "http://localhost:8080", "Endpoint should match");
    }

    /// Test MPC party with different roles
    #[tokio::test]
    async fn test_mpc_party_roles() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        // Test Initiator role
        let initiator_metadata = PartyMetadata {
            party_id: "initiator_party".to_string(),
            role: PartyRole::Initiator,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["initiation".to_string(), "computation".to_string()],
        };

        let initiator = MpcParty::new(config.clone(), initiator_metadata);
        assert!(initiator.initialize().await.is_ok(), "Initiator party should initialize");

        // Test Participant role
        let participant_metadata = PartyMetadata {
            party_id: "participant_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8081".to_string(),
            public_key: vec![2; 32],
            capabilities: vec!["computation".to_string()],
        };

        let participant = MpcParty::new(config.clone(), participant_metadata);
        assert!(participant.initialize().await.is_ok(), "Participant party should initialize");

        // Test Observer role
        let observer_metadata = PartyMetadata {
            party_id: "observer_party".to_string(),
            role: PartyRole::Observer,
            endpoint: "http://localhost:8082".to_string(),
            public_key: vec![3; 32],
            capabilities: vec!["observation".to_string()],
        };

        let observer = MpcParty::new(config, observer_metadata);
        assert!(observer.initialize().await.is_ok(), "Observer party should initialize");

        // Verify role-specific capabilities
        let initiator_caps = initiator.get_capabilities().await;
        assert!(initiator_caps.contains(&"initiation".to_string()), "Initiator should have initiation capability");

        let participant_caps = participant.get_capabilities().await;
        assert!(participant_caps.contains(&"computation".to_string()), "Participant should have computation capability");
        assert!(!participant_caps.contains(&"initiation".to_string()), "Participant should not have initiation capability");

        let observer_caps = observer.get_capabilities().await;
        assert!(observer_caps.contains(&"observation".to_string()), "Observer should have observation capability");
        assert!(!observer_caps.contains(&"computation".to_string()), "Observer should not have computation capability");
    }

    /// Test MPC party session joining
    #[tokio::test]
    async fn test_mpc_party_session_joining() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "joining_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Create a mock session
        let session = MpcSession {
            session_id: "test_session_123".to_string(),
            protocol_name: "test_protocol".to_string(),
            required_parties: 3,
            current_parties: 1,
            status: "waiting".to_string(),
            parties: HashMap::new(),
            created_at: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
        };

        // Join the session
        let join_result = party.join_session(&session).await;
        assert!(join_result.is_ok(), "Party should join session successfully");
        
        // Verify party is in session
        let active_sessions = party.get_active_sessions().await;
        assert!(active_sessions.contains(&"test_session_123".to_string()), "Party should be in active sessions");
    }

    /// Test MPC party message handling
    #[tokio::test]
    async fn test_mpc_party_message_handling() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "message_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "messaging".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Create test message
        let message = PartyMessage {
            message_id: Uuid::new_v4().to_string(),
            session_id: "test_session".to_string(),
            sender_id: "sender_party".to_string(),
            receiver_id: "message_party".to_string(),
            message_type: "share_data".to_string(),
            payload: vec![1, 2, 3, 4, 5],
            timestamp: std::time::SystemTime::now(),
            signature: vec![6, 7, 8, 9],
        };

        // Process incoming message
        let process_result = party.process_message(&message).await;
        assert!(process_result.is_ok(), "Party should process message successfully");
        
        // Send response message
        let response_message = PartyMessage {
            message_id: Uuid::new_v4().to_string(),
            session_id: "test_session".to_string(),
            sender_id: "message_party".to_string(),
            receiver_id: "sender_party".to_string(),
            message_type: "acknowledgment".to_string(),
            payload: vec![10, 11, 12],
            timestamp: std::time::SystemTime::now(),
            signature: vec![13, 14, 15],
        };

        let send_result = party.send_message(&response_message).await;
        assert!(send_result.is_ok(), "Party should send message successfully");
    }

    /// Test MPC party computation participation
    #[tokio::test]
    async fn test_mpc_party_computation() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "computing_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "addition".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Simulate computation request
        let computation_request = HashMap::from([
            ("operation".to_string(), "secure_add".to_string()),
            ("share1".to_string(), "42".to_string()),
            ("share2".to_string(), "58".to_string()),
        ]);

        // Perform computation
        let computation_result = party.perform_computation(&computation_request).await.unwrap();
        assert!(computation_result.contains_key("result"), "Should have computation result");
        assert!(computation_result.contains_key("proof"), "Should have computation proof");
        
        // Verify computation result
        let result = computation_result.get("result").unwrap();
        assert_eq!(result, &"100".to_string(), "Computation result should be correct");
    }

    /// Test MPC party security validation
    #[tokio::test]
    async fn test_mpc_party_security_validation() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 256, // High security level
        };

        // Test party with insufficient security
        let insecure_metadata = PartyMetadata {
            party_id: "insecure_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1, 2, 3], // Too short for security level 256
            capabilities: vec!["computation".to_string()],
        };

        let insecure_party = MpcParty::new(config.clone(), insecure_metadata);
        let init_result = insecure_party.initialize().await;
        assert!(init_result.is_err(), "Party with insufficient security should fail initialization");

        // Test party with proper security
        let secure_metadata = PartyMetadata {
            party_id: "secure_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 64], // Proper length for security level 256
            capabilities: vec!["computation".to_string()],
        };

        let secure_party = MpcParty::new(config, secure_metadata);
        let secure_init_result = secure_party.initialize().await;
        assert!(secure_init_result.is_ok(), "Secure party should initialize successfully");
    }

    /// Test MPC party message authentication
    #[tokio::test]
    async fn test_mpc_party_message_authentication() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "auth_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "authentication".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Create message with valid signature
        let valid_message = PartyMessage {
            message_id: Uuid::new_v4().to_string(),
            session_id: "test_session".to_string(),
            sender_id: "trusted_sender".to_string(),
            receiver_id: "auth_party".to_string(),
            message_type: "authenticated_data".to_string(),
            payload: vec![1, 2, 3, 4, 5],
            timestamp: std::time::SystemTime::now(),
            signature: vec![100, 200, 300], // Valid signature
        };

        let auth_result = party.authenticate_message(&valid_message).await;
        assert!(auth_result.is_ok(), "Valid message should authenticate successfully");

        // Create message with invalid signature
        let invalid_message = PartyMessage {
            message_id: Uuid::new_v4().to_string(),
            session_id: "test_session".to_string(),
            sender_id: "untrusted_sender".to_string(),
            receiver_id: "auth_party".to_string(),
            message_type: "tampered_data".to_string(),
            payload: vec![6, 7, 8, 9],
            timestamp: std::time::SystemTime::now(),
            signature: vec![1, 2, 3], // Invalid signature
        };

        let invalid_auth_result = party.authenticate_message(&invalid_message).await;
        assert!(invalid_auth_result.is_err(), "Invalid message should fail authentication");
    }

    /// Test MPC party concurrent operations
    #[tokio::test]
    async fn test_mpc_party_concurrent_operations() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 5,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "concurrent_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "messaging".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Perform concurrent operations
        let mut handles = vec![];
        for i in 0..3 {
            let party_clone = party.clone();
            let handle = tokio::spawn(async move {
                let computation_request = HashMap::from([
                    ("operation".to_string(), "secure_add".to_string()),
                    ("share1".to_string(), format!("{}", i * 10)),
                    ("share2".to_string(), format!("{}", (i + 1) * 10)),
                ]);
                
                let result = party_clone.perform_computation(&computation_request).await.unwrap();
                (i, result)
            });
            handles.push(handle);
        }

        // Wait for all operations to complete
        let results: Vec<_> = futures::future::join_all(handles).await
            .into_iter()
            .map(|result| result.unwrap())
            .collect();

        // Verify all operations completed successfully
        for (i, result) in results {
            assert!(result.contains_key("result"), "Operation {} should have result", i);
            let computed_result = result.get("result").unwrap();
            let expected = format!("{}", i * 20 + 10);
            assert_eq!(computed_result, &expected, "Operation {} result should be correct", i);
        }
    }

    /// Test MPC party session management
    #[tokio::test]
    async fn test_mpc_party_session_management() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "session_manager_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "session_management".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Join multiple sessions
        let session_ids = vec![
            "session_1".to_string(),
            "session_2".to_string(),
            "session_3".to_string(),
        ];

        for session_id in &session_ids {
            let mock_session = MpcSession {
                session_id: session_id.clone(),
                protocol_name: "test_protocol".to_string(),
                required_parties: 2,
                current_parties: 1,
                status: "waiting".to_string(),
                parties: HashMap::new(),
                created_at: std::time::SystemTime::now(),
                last_activity: std::time::SystemTime::now(),
            };
            
            party.join_session(&mock_session).await.unwrap();
        }

        // Verify all sessions are active
        let active_sessions = party.get_active_sessions().await;
        assert_eq!(active_sessions.len(), 3, "Should have 3 active sessions");
        for session_id in &session_ids {
            assert!(active_sessions.contains(session_id), "Session {} should be active", session_id);
        }

        // Leave one session
        party.leave_session("session_2").await.unwrap();
        
        // Verify session was removed
        let updated_sessions = party.get_active_sessions().await;
        assert_eq!(updated_sessions.len(), 2, "Should have 2 active sessions");
        assert!(!updated_sessions.contains(&"session_2".to_string()), "Session 2 should not be active");
        assert!(updated_sessions.contains(&"session_1".to_string()), "Session 1 should still be active");
        assert!(updated_sessions.contains(&"session_3".to_string()), "Session 3 should still be active");
    }

    /// Test MPC party error handling
    #[tokio::test]
    async fn test_mpc_party_error_handling() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "error_test_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Test computation with invalid operation
        let invalid_request = HashMap::from([
            ("operation".to_string(), "invalid_operation".to_string()),
            ("data".to_string(), "test_data".to_string()),
        ]);

        let computation_result = party.perform_computation(&invalid_request).await;
        assert!(computation_result.is_err(), "Invalid operation should fail");

        // Test message processing with malformed message
        let malformed_message = PartyMessage {
            message_id: "".to_string(), // Empty message ID
            session_id: "test_session".to_string(),
            sender_id: "sender".to_string(),
            receiver_id: "error_test_party".to_string(),
            message_type: "".to_string(), // Empty message type
            payload: vec![],
            timestamp: std::time::SystemTime::now(),
            signature: vec![],
        };

        let process_result = party.process_message(&malformed_message).await;
        assert!(process_result.is_err(), "Malformed message should fail processing");

        // Test leaving non-existent session
        let leave_result = party.leave_session("non_existent_session").await;
        assert!(leave_result.is_err(), "Leaving non-existent session should fail");
    }

    /// Test MPC party performance metrics
    #[tokio::test]
    async fn test_mpc_party_performance_metrics() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "performance_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string(), "messaging".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Perform multiple operations for performance testing
        let start_time = Instant::now();
        for i in 0..10 {
            let computation_request = HashMap::from([
                ("operation".to_string(), "secure_add".to_string()),
                ("share1".to_string(), format!("{}", i)),
                ("share2".to_string(), format!("{}", i + 1)),
            ]);
            
            party.perform_computation(&computation_request).await.unwrap();
        }
        let computation_time = start_time.elapsed();

        // Performance should be reasonable
        assert!(computation_time.as_millis() < 5000, "10 computations should complete within 5 seconds");
        
        // Get performance metrics
        let metrics = party.get_performance_metrics().await.unwrap();
        assert!(metrics.total_computations >= 10, "Should have performed at least 10 computations");
        assert!(metrics.average_computation_time_ms > 0.0, "Should have average computation time");
        assert!(metrics.active_sessions >= 0, "Should have active sessions count");
        assert!(metrics.messages_processed >= 0, "Should have messages processed count");
    }

    /// Test MPC party compliance features
    #[tokio::test]
    async fn test_mpc_party_compliance() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "compliance_party".to_string(),
            role: PartyRole::Auditor, // Auditor role for compliance
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["audit".to_string(), "compliance_check".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Test audit logging
        let audit_event = HashMap::from([
            ("event_type".to_string(), "computation_completed".to_string()),
            ("session_id".to_string(), "audit_session".to_string()),
            ("timestamp".to_string(), "1234567890".to_string()),
            ("details".to_string(), "Computation completed successfully".to_string()),
        ]);

        let log_result = party.log_audit_event(&audit_event).await;
        assert!(log_result.is_ok(), "Audit event should be logged successfully");

        // Test compliance checking
        let compliance_request = HashMap::from([
            ("check_type".to_string(), "gdpr_compliance".to_string()),
            ("session_id".to_string(), "compliance_session".to_string()),
        ]);

        let compliance_result = party.check_compliance(&compliance_request).await.unwrap();
        assert!(compliance_result.contains_key("compliant"), "Should have compliance status");
        assert!(compliance_result.contains_key("score"), "Should have compliance score");
        
        // Verify compliance result
        let compliant = compliance_result.get("compliant").unwrap();
        assert_eq!(compliant, &"true".to_string(), "Party should be compliant");
    }

    /// Test MPC party graceful shutdown
    #[tokio::test]
    async fn test_mpc_party_graceful_shutdown() {
        let config = PartyConfig {
            endpoint: "http://localhost:8080".to_string(),
            max_concurrent_sessions: 10,
            message_timeout_seconds: 30,
            retry_attempts: 3,
            enable_logging: true,
            security_level: 128,
        };

        let metadata = PartyMetadata {
            party_id: "shutdown_party".to_string(),
            role: PartyRole::Participant,
            endpoint: "http://localhost:8080".to_string(),
            public_key: vec![1; 32],
            capabilities: vec!["computation".to_string()],
        };

        let party = MpcParty::new(config, metadata);
        party.initialize().await.expect("Party should initialize");

        // Join a session
        let mock_session = MpcSession {
            session_id: "shutdown_test_session".to_string(),
            protocol_name: "test_protocol".to_string(),
            required_parties: 2,
            current_parties: 1,
            status: "running".to_string(),
            parties: HashMap::new(),
            created_at: std::time::SystemTime::now(),
            last_activity: std::time::SystemTime::now(),
        };

        party.join_session(&mock_session).await.unwrap();

        // Perform graceful shutdown
        let shutdown_result = party.shutdown().await;
        assert!(shutdown_result.is_ok(), "Graceful shutdown should succeed");

        // Verify party is no longer operational
        let active_sessions = party.get_active_sessions().await;
        assert!(active_sessions.is_empty(), "Should have no active sessions after shutdown");

        // Operations after shutdown should fail
        let computation_request = HashMap::from([
            ("operation".to_string(), "secure_add".to_string()),
            ("share1".to_string(), "1".to_string()),
            ("share2".to_string(), "2".to_string()),
        ]);

        let post_shutdown_result = party.perform_computation(&computation_request).await;
        assert!(post_shutdown_result.is_err(), "Operations after shutdown should fail");
    }
}
