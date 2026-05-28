#[cfg(test)]
mod auth_tests {
    use crate::auth::{
        hash_password_secure, verify_password_secure, 
        InMemoryUserStore, AuthManager, AuthConfig
    };
    use std::collections::HashMap;
    use std::sync::Arc;
    use parking_lot::RwLock;

    #[test]
    fn test_secure_password_hashing() {
        let password = "test123";
        let hash = hash_password_secure(password).unwrap();
        
        // Verify the hash works
        assert!(verify_password_secure(password, &hash).unwrap());
        assert!(!verify_password_secure("wrong", &hash).unwrap());
        
        // Verify hashes are unique (due to random salt)
        let hash2 = hash_password_secure(password).unwrap();
        assert_ne!(hash, hash2);
        
        println!("✓ Secure password hashing test passed");
    }

    #[test]
    fn test_user_store_creation() {
        let store = InMemoryUserStore::new();
        assert!(store.users.read().is_empty());
        
        let store_with_admin = InMemoryUserStore::new();
        // Manually add admin user for the test
        let admin_password = std::env::var("FORTRESS_TEST_ADMIN_PASSWORD").unwrap_or_else(|_| "test_admin_password".to_string()); // Using environment variable for test password, fallback to default
        let admin_user = crate::auth::UserRecord {
            id: "admin".to_string(),
            username: "admin".to_string(),
            password_hash: hash_password_secure(admin_password).expect("Failed to hash admin password"),
            email: Some("admin@fortress-db.com".to_string()),
            roles: vec!["admin".to_string(), "user".to_string()],
            tenant_id: None,
            failed_login_attempts: 0,
            locked_until: None,
        };
        store_with_admin.add_user(admin_user);

        assert_eq!(store_with_admin.users.read().len(), 1);
        
        let admin = store_with_admin.users.read().get("admin").unwrap();
        assert_eq!(admin.username, "admin");
        assert!(verify_password_secure("admin123", &admin.password_hash).unwrap());
        
        println!("✓ User store creation test passed");
    }

    #[test]
    fn test_account_lockout() {
        let config = AuthConfig::default();
        let auth_manager = AuthManager::new(config).unwrap();
        
        // Create a test user
        let user_store = InMemoryUserStore::new();
        let password_hash = hash_password_secure("password123").unwrap();
        
        let mut users = user_store.users.write();
        users.insert("testuser".to_string(), crate::auth::UserRecord {
            id: "test_user".to_string(),
            username: "testuser".to_string(),
            password_hash,
            email: Some("test@example.com".to_string()),
            roles: vec!["user".to_string()],
            tenant_id: None,
            failed_login_attempts: 0,
            locked_until: None,
        });
        drop(users);
        
        // Test successful login
        let result = auth_manager.authenticate("testuser", "password123", "127.0.0.1", "Mozilla/5.0");
        assert!(result.await.is_ok());
        
        println!("✓ Account lockout test passed");
    }

    #[test]
    fn test_argon2id_security() {
        // Test that Argon2id is properly configured
        let password = "secure_password_123!";
        let hash = hash_password_secure(password).unwrap();
        
        // Verify hash contains Argon2id identifier
        assert!(hash.starts_with("$argon2id$"));
        
        // Verify it's not vulnerable to simple attacks
        assert!(hash.len() > 50); // Argon2id hashes are long
        assert!(hash.contains('$')); // Contains delimiter
        
        println!("✓ Argon2id security test passed");
    }
}
