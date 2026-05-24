//! Simple test to verify audit logging works

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use fortress_core::audit::{
        AuditConfig, AuditEntry, AuditEventType, SecurityLevel, EventOutcome,
        DefaultAuditLogger,
    };
    use base64::Engine as _;

    #[test]
    fn test_basic_audit_functionality() {
        // Create audit configuration
        let mut config = AuditConfig::default();
        config.hmac_key = Some(base64::engine::general_purpose::STANDARD.encode("test_hmac_key_32_bytes_long_1234"));
        config.log_path = Some("test_audit.log".to_string());

        // Create audit logger
        let mut logger = DefaultAuditLogger::new(config).unwrap();
        
        // Create a test entry
        let mut metadata = HashMap::new();
        metadata.insert("test".to_string(), "value".to_string());
        
        let entry = AuditEntry {
            id: "test-1".to_string(),
            timestamp: 1234567890,
            event_type: AuditEventType::Authentication,
            security_level: SecurityLevel::High,
            principal: Some("test_user".to_string()),
            resource: Some("/test".to_string()),
            action: "test_action".to_string(),
            outcome: EventOutcome::Success,
            metadata,
            previous_hash: None,
            current_hash: String::new(),
            signature: String::new(),
        };

        // This should work even if other parts of the codebase have issues
        let result = logger.create_entry(
            entry.event_type,
            entry.security_level,
            entry.principal,
            entry.resource,
            entry.action,
            entry.outcome,
            entry.metadata,
        );

        assert!(result.is_ok());
        
        let created_entry = result.unwrap();
        assert!(!created_entry.id.is_empty());
        assert!(!created_entry.current_hash.is_empty());
        assert!(!created_entry.signature.is_empty());
        
        // Clean up
        std::fs::remove_file("test_audit.log").ok();
    }
}
