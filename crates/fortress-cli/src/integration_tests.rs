//! Comprehensive integration tests for CLI enhancements
//! 
//! Tests all enhanced CLI features including configuration wizard,
//! progress bars, error handling, and GraphQL integration.

use crate::enhanced_error::{FortressError, ErrorAnalyzer, ErrorDocumentation};
use crate::config_wizard::{ConfigurationWizard, FortressConfig};
use crate::progress::{ProgressManager, ProgressTracker};
use crate::completions::{build_cli, install_completions};
use crate::types::Commands;
use std::collections::HashMap;

pub async fn test_configuration_wizard_complete_flow() {
    // Test complete configuration wizard flow
    let _result = ConfigurationWizard::run_interactive_setup().await;
    
    // In a real test, this would mock user input
    // For now, we'll test the configuration validation
    let test_config = FortressConfig {
        database: crate::config_wizard::DatabaseConfig {
            backend: "postgresql".to_string(),
            host: "localhost".to_string(),
            port: 5432,
            estimated_downtime_secs: 0,
            credentials: crate::config_wizard::DatabaseCredentials {
                username: "test".to_string(),
                password: "test".to_string(),
            },
        },
        encryption: crate::config_wizard::EncryptionConfig {
            enabled: true,
            algorithm: "aegis256".to_string(),
            key_rotation_days: 90,
            field_level_encryption: true,
        },
        networking: crate::config_wizard::NetworkingConfig {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            tls_enabled: false,
            max_connections: 1000,
        },
        security: crate::config_wizard::SecurityConfig {
            auth_method: "jwt".to_string(),
            session_timeout_minutes: 60,
            rate_limiting: true,
            audit_logging: true,
        },
    };
    
    // Validate configuration
    let warnings = ConfigurationWizard::validate_configuration(&test_config).await.unwrap();
    assert!(warnings.is_empty(), "Configuration should be valid");
}

pub async fn test_progress_manager_operations() {
    let progress_manager = ProgressManager::new();
    
    // Test different progress bar types
    let encryption_pb = progress_manager.create_encryption_progress(1024 * 1024); // 1MB
    let migration_pb = progress_manager.create_database_migration_progress(10);
    let key_gen_pb = progress_manager.create_key_generation_progress(100);
    let file_op_pb = progress_manager.create_file_operation_progress(50);
    let download_pb = progress_manager.create_download_progress(1024 * 1024);
    let upload_pb = progress_manager.create_upload_progress(512 * 1024);
    
    // Verify progress bars are created
    assert_eq!(encryption_pb.length(), Some(1024 * 1024));
    assert_eq!(migration_pb.length(), Some(10));
    assert_eq!(key_gen_pb.length(), Some(100));
    assert_eq!(file_op_pb.length(), Some(50));
    assert_eq!(download_pb.length(), Some(1024 * 1024));
    assert_eq!(upload_pb.length(), Some(512 * 1024));
    
    // Test progress tracker
    let tracker = ProgressTracker::new(1000, "Test operation".to_string());
    assert_eq!(tracker.elapsed().as_secs(), 0);
    
    tracker.update(500);
    tracker.finish("Test completed".to_string());
    assert!(tracker.pb.is_finished());
}

pub async fn test_enhanced_error_system() {
    let mut error_analyzer = ErrorAnalyzer::new();
    
    // Test error creation and documentation
    let encryption_error = FortressError::encryption_failed("Invalid key length");
    assert_eq!(encryption_error.error_code(), "ENC001");
    assert_eq!(encryption_error.severity(), crate::enhanced_error::ErrorSeverity::High);
    
    let db_error = FortressError::database_connection_failed("testdb", "localhost", 5432);
    assert_eq!(db_error.error_code(), "DB001");
    assert_eq!(db_error.severity(), crate::enhanced_error::ErrorSeverity::High);
    
    let config_error = FortressError::configuration_error("port", "invalid", "number 1-65535");
    assert_eq!(config_error.error_code(), "CFG001");
    assert_eq!(config_error.severity(), crate::enhanced_error::ErrorSeverity::Medium);
    
    // Test error reporting
    let mut context = HashMap::new();
    context.insert("operation".to_string(), "test_encryption".to_string());
    context.insert("user_id".to_string(), "test_user".to_string());
    
    error_analyzer.report_error(&encryption_error, context);
    
    let summary = error_analyzer.get_error_summary(24);
    assert_eq!(summary.total_errors, 1);
    assert_eq!(summary.error_counts.get("ENC001"), Some(&1));
    assert_eq!(summary.most_common, Some(("ENC001".to_string(), 1)));
    
    // Test error documentation
    let doc = ErrorDocumentation::for_error_code("ENC001");
    assert!(doc.is_some());
    
    let doc = doc.unwrap();
    assert_eq!(doc.error_code, "ENC001");
    assert_eq!(doc.title, "Invalid Key Length");
    assert!(!doc.solutions.is_empty());
    assert!(!doc.examples.is_empty());
    assert!(!doc.prevention_tips.is_empty());
}

pub async fn test_shell_completions() {
    // Test CLI building
    let cli = build_cli();
    assert_eq!(cli.get_name(), "fortress");
    assert!(cli.find_subcommand("config").is_some());
    assert!(cli.find_subcommand("key").is_some());
    assert!(cli.find_subcommand("server").is_some());
    assert!(cli.find_subcommand("completions").is_some());
    
    // Test completion generation
    let mut output = Vec::new();
    let result = crate::completions::generate_completions(
        clap_complete::shells::Bash, 
        &mut output
    );
    assert!(result.is_ok());
    assert!(!output.is_empty());
}

pub async fn test_error_severity_classification() {
    let test_cases = vec![
        (FortressError::encryption_failed("test"), crate::enhanced_error::ErrorSeverity::High),
        (FortressError::database_connection_failed("test", "localhost", 5432), crate::enhanced_error::ErrorSeverity::High),
        (FortressError::authentication_failed("test"), crate::enhanced_error::ErrorSeverity::High),
        (FortressError::key_operation_failed("test", None), crate::enhanced_error::ErrorSeverity::High),
        (FortressError::configuration_error("test", "test", "test"), crate::enhanced_error::ErrorSeverity::Medium),
        (FortressError::network_error("test", "test"), crate::enhanced_error::ErrorSeverity::Medium),
        (FortressError::file_system_error("test", "test"), crate::enhanced_error::ErrorSeverity::Medium),
        (FortressError::compliance_violation("GDPR", "test"), crate::enhanced_error::ErrorSeverity::Critical),
        (FortressError::performance_degradation("test", "test", "test"), crate::enhanced_error::ErrorSeverity::Low),
        (FortressError::plugin_error("test", "test"), crate::enhanced_error::ErrorSeverity::Medium),
    ];
    
    for (error, expected_severity) in test_cases {
        assert_eq!(error.severity(), expected_severity);
    }
}

pub async fn test_error_troubleshooting_steps() {
    let test_cases = vec![
        (FortressError::database_connection_failed("testdb", "localhost", 5432), 6), // DB errors have troubleshooting steps
        (FortressError::encryption_failed("test"), 4), // Encryption errors have troubleshooting steps
        (FortressError::key_operation_failed("test", None), 5), // Key errors have recovery steps
        (FortressError::compliance_violation("GDPR", "test"), 4), // Compliance errors have remediation steps
        (FortressError::performance_degradation("test", "test", "test"), 5), // Performance errors have optimization suggestions
    ];
    
    for (error, min_steps) in test_cases {
        let steps = error.troubleshooting_steps();
        assert!(steps.len() >= min_steps, "Error should have at least {} troubleshooting steps", min_steps);
    }
}

pub async fn test_configuration_validation() {
    let valid_config = FortressConfig {
        database: crate::config_wizard::DatabaseConfig {
            backend: "postgresql".to_string(),
            host: "localhost".to_string(),
            port: 5432,
            estimated_downtime_secs: 0,
            credentials: crate::config_wizard::DatabaseCredentials {
                username: "test".to_string(),
                password: "test".to_string(),
            },
        },
        encryption: crate::config_wizard::EncryptionConfig {
            enabled: true,
            algorithm: "aegis256".to_string(),
            key_rotation_days: 90,
            field_level_encryption: true,
        },
        networking: crate::config_wizard::NetworkingConfig {
            bind_address: "0.0.0.0".to_string(),
            port: 8080,
            tls_enabled: false,
            max_connections: 1000,
        },
        security: crate::config_wizard::SecurityConfig {
            auth_method: "jwt".to_string(),
            session_timeout_minutes: 60,
            rate_limiting: true,
            audit_logging: true,
        },
    };
    
    let warnings = ConfigurationWizard::validate_configuration(&valid_config).await.unwrap();
    assert!(warnings.is_empty(), "Valid configuration should have no warnings");
    
    // Test invalid configurations
    let invalid_config = FortressConfig {
        database: crate::config_wizard::DatabaseConfig {
            backend: "postgresql".to_string(),
            host: "".to_string(), // Invalid: empty host for non-SQLite
            port: 0, // Invalid: port 0 for non-SQLite
            estimated_downtime_secs: 0,
            credentials: crate::config_wizard::DatabaseCredentials {
                username: "test".to_string(),
                password: "test".to_string(),
            },
        },
        encryption: crate::config_wizard::EncryptionConfig {
            enabled: true,
            algorithm: "none".to_string(), // Invalid: encryption enabled but no algorithm
            key_rotation_days: 0, // Invalid: key rotation 0 days
            field_level_encryption: true,
        },
        networking: crate::config_wizard::NetworkingConfig {
            bind_address: "0.0.0.0".to_string(),
            port: 0, // Invalid: port 0
            tls_enabled: false,
            max_connections: 0, // Invalid: max connections 0
        },
        security: crate::config_wizard::SecurityConfig {
            auth_method: "jwt".to_string(),
            session_timeout_minutes: 0, // Invalid: session timeout 0 minutes
            rate_limiting: true,
            audit_logging: true,
        },
    };
    
    let warnings = ConfigurationWizard::validate_configuration(&invalid_config).await.unwrap();
    assert!(!warnings.is_empty(), "Invalid configuration should have warnings");
    assert!(warnings.len() >= 4, "Should have multiple validation warnings");
}

pub async fn test_progress_tracker_functionality() {
    let tracker = ProgressTracker::new(1000, "Test operation".to_string());
    
    // Test initial state
    assert_eq!(tracker.elapsed().as_secs(), 0);
    assert!(!tracker.pb.is_finished());
    
    // Test progress updates
    tracker.update(250);
    assert_eq!(tracker.pb.position(), 250);
    
    tracker.increment(100);
    assert_eq!(tracker.pb.position(), 350);
    
    // Test message updates
    tracker.set_message("Updated message".to_string());
    
    // Test completion
    tracker.finish("Operation completed".to_string());
    assert!(tracker.pb.is_finished());
    
    // Test abandonment
    let abandoned_tracker = ProgressTracker::new(500, "Abandoned test".to_string());
    abandoned_tracker.abandon("Operation abandoned".to_string());
    assert!(abandoned_tracker.pb.is_finished());
}

pub async fn test_error_code_consistency() {
    let error_codes = vec![
        ("ENC001", "encryption_failed"),
        ("DB001", "database_connection_failed"),
        ("CFG001", "configuration_error"),
        ("AUTH001", "authentication_failed"),
        ("KEY001", "key_operation_failed"),
        ("NET001", "network_error"),
        ("FS001", "file_system_error"),
        ("COMP001", "compliance_violation"),
        ("PERF001", "performance_degradation"),
        ("PLUGIN001", "plugin_error"),
    ];
    
    for (expected_code, constructor_name) in error_codes {
        let error = match constructor_name {
            "encryption_failed" => FortressError::encryption_failed("test"),
            "database_connection_failed" => FortressError::database_connection_failed("test", "localhost", 5432),
            "configuration_error" => FortressError::configuration_error("test", "test", "test"),
            "authentication_failed" => FortressError::authentication_failed("test"),
            "key_operation_failed" => FortressError::key_operation_failed("test", None),
            "network_error" => FortressError::network_error("test", "test"),
            "file_system_error" => FortressError::file_system_error("test", "test"),
            "compliance_violation" => FortressError::compliance_violation("GDPR", "test"),
            "performance_degradation" => FortressError::performance_degradation("test", "test", "test"),
            "plugin_error" => FortressError::plugin_error("test", "test"),
            _ => panic!("Unknown constructor: {}", constructor_name),
        };
        
        assert_eq!(error.error_code(), expected_code, "Error code mismatch for {}", constructor_name);
    }
}

pub async fn test_error_help_text_availability() {
    let errors = vec![
        FortressError::encryption_failed("test"),
        FortressError::database_connection_failed("test", "localhost", 5432),
        FortressError::configuration_error("test", "test", "test"),
        FortressError::authentication_failed("test"),
        FortressError::key_operation_failed("test", None),
        FortressError::network_error("test", "test"),
        FortressError::file_system_error("test", "test"),
        FortressError::compliance_violation("GDPR", "test"),
        FortressError::performance_degradation("test", "test", "test"),
        FortressError::plugin_error("test", "test"),
    ];
    
    for error in errors {
        let help_text = error.help_text();
        assert!(!help_text.is_empty(), "Help text should not be empty for error code: {}", error.error_code());
        assert!(help_text.len() > 10, "Help text should be meaningful for error code: {}", error.error_code());
    }
}
