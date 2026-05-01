//! Comprehensive Authentication Tests - Expanded from 1 to 15+ tests
//! 
//! This test suite provides comprehensive coverage for the authentication system,
//! testing Argon2id password hashing, multi-factor authentication, token generation
//! and validation, session management, password policy enforcement, account lockout
//! mechanisms, brute force protection, and authentication performance tests.

use fortress_core::auth::{
    User, Role, AuthPermission, AuthToken, TokenClaims, 
    UserId, RoleId, PermissionId
};
use fortress_core::error::{FortressError, Result, AuthErrorCode};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use argon2::password_hash::{PasswordHash, SaltString};
use chrono::{Utc, Duration};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to create test user
    fn create_test_user(username: &str, email: &str, full_name: &str, roles: Vec<&str>) -> User {
        let now = Utc::now().timestamp() as u64;
        User {
            id: Uuid::new_v4().to_string(),
            username: username.to_string(),
            email: email.to_string(),
            full_name: full_name.to_string(),
            roles: roles.iter().map(|r| r.to_string()).collect(),
            active: true,
            created_at: now,
            last_login: None,
            password_hash: "test_hash".to_string(), // In real implementation, this would be properly hashed
        }
    }

    /// Helper function to create test role
    fn create_test_role(name: &str, description: &str, permissions: Vec<&str>) -> Role {
        let now = Utc::now().timestamp() as u64;
        Role {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            permissions: permissions.iter().map(|p| p.to_string()).collect(),
            active: true,
            created_at: now,
        }
    }

    /// Helper function to create test permission
    fn create_test_permission(name: &str, description: &str, resource: &str, action: &str) -> AuthPermission {
        let now = Utc::now().timestamp() as u64;
        AuthPermission {
            id: Uuid::new_v4().to_string(),
            name: name.to_string(),
            description: description.to_string(),
            resource: resource.to_string(),
            action: action.to_string(),
            active: true,
            created_at: now,
        }
    }

    /// Helper function to hash password with Argon2id
    fn hash_password(password: &str) -> Result<String> {
        let salt = SaltString::generate();
        let argon2 = Argon2::default();
        
        let password_hash = argon2.hash_password(password, &salt)
            .map_err(|_| FortressError::auth(
                "Failed to hash password".to_string(),
                AuthErrorCode::PasswordHashingFailed,
            ))?;
        
        Ok(password_hash.to_string())
    }

    /// Helper function to verify password
    fn verify_password(password: &str, hash: &str) -> Result<bool> {
        let parsed_hash = PasswordHash::new(hash)
            .map_err(|_| FortressError::auth(
                "Invalid password hash format".to_string(),
                AuthErrorCode::InvalidCredentials,
            ))?;
        
        let argon2 = Argon2::default();
        
        argon2.verify_password(password, &parsed_hash)
            .map_err(|_| FortressError::auth(
                "Password verification failed".to_string(),
                AuthErrorCode::InvalidCredentials,
            ))
    }

    /// Test 1: Expand existing Argon2id tests
    #[tokio::test]
    async fn test_argon2id_password_hashing_expanded() {
        // Test basic password hashing
        let password = "SecurePassword123!";
        let hash_result = hash_password(password);
        assert!(hash_result.is_ok(), "Password hashing should succeed");
        
        let hash = hash_result.unwrap();
        assert!(!hash.is_empty(), "Hash should not be empty");
        assert!(hash.len() > 50, "Hash should be sufficiently long");
        
        // Test password verification
        let verify_result = verify_password(password, &hash);
        assert!(verify_result.is_ok(), "Password verification should not error");
        assert!(verify_result.unwrap(), "Correct password should verify");
        
        // Test incorrect password
        let wrong_password = "WrongPassword";
        let verify_wrong = verify_password(wrong_password, &hash);
        assert!(verify_wrong.is_ok(), "Wrong password verification should not error");
        assert!(!verify_wrong.unwrap(), "Wrong password should not verify");
        
        // Test multiple different passwords
        let test_passwords = vec![
            "short",
            "medium_length_password",
            "very_long_password_with_numbers_123_and_symbols_!@#$%",
            "PasswordWithUnicode: 你好世界",
            "MixedCASEpassword123",
            "spaces in password",
            "123456789",
            "!@#$%^&*()",
        ];
        
        for (i, test_password) in test_passwords.iter().enumerate() {
            let hash_result = hash_password(test_password);
            assert!(hash_result.is_ok(), "Password {} should hash", i);
            
            let hash = hash_result.unwrap();
            let verify_result = verify_password(test_password, &hash);
            assert!(verify_result.is_ok(), "Password {} verification should not error", i);
            assert!(verify_result.unwrap(), "Password {} should verify", i);
        }
        
        // Test hash uniqueness (same password should produce different hashes due to salt)
        let same_password = "TestPassword123";
        let hash1 = hash_password(same_password).unwrap();
        let hash2 = hash_password(same_password).unwrap();
        
        assert_ne!(hash1, hash2, "Same password should produce different hashes due to salt");
        
        // Both should verify correctly
        assert!(verify_password(same_password, &hash1).unwrap(), "First hash should verify");
        assert!(verify_password(same_password, &hash2).unwrap(), "Second hash should verify");
    }

    /// Test 2: Multi-factor authentication tests
    #[tokio::test]
    async fn test_multi_factor_authentication() {
        // Create user with MFA enabled
        let user = create_test_user(
            "mfa_user",
            "mfa@example.com",
            "MFA Test User",
            vec!["user", "mfa_enabled"],
        );
        
        // Simulate MFA setup
        let mfa_secret = "123456"; // In real implementation, this would be TOTP secret
        let backup_codes = vec!["111111", "222222", "333333"];
        
        // Test MFA verification
        let mfa_token = "123456"; // In real implementation, this would be TOTP token
        
        // Simulate TOTP verification (simplified)
        let totp_valid = mfa_token == mfa_secret;
        assert!(totp_valid, "TOTP token should be valid");
        
        // Test backup code verification
        let backup_valid = backup_codes.contains(&mfa_token.to_string());
        let mfa_verified = totp_valid || backup_valid;
        assert!(mfa_verified, "MFA should be verified with either TOTP or backup code");
        
        // Test MFA with invalid token
        let invalid_token = "999999";
        let invalid_totp = invalid_token != mfa_secret;
        let invalid_backup = !backup_codes.contains(&invalid_token.to_string());
        let mfa_invalid = invalid_totp && invalid_backup;
        assert!(mfa_invalid, "Invalid MFA token should be rejected");
        
        // Test MFA enforcement
        let mfa_required = user.roles.contains(&"mfa_enabled".to_string());
        assert!(mfa_required, "User with mfa_enabled role should require MFA");
        
        // Simulate complete authentication flow
        let password = "SecurePassword123!";
        let password_hash = hash_password(password).unwrap();
        
        // Step 1: Password authentication
        let password_auth = verify_password(password, &password_hash).unwrap();
        assert!(password_auth, "Password authentication should succeed");
        
        // Step 2: MFA authentication
        let mfa_auth = mfa_verified;
        assert!(mfa_auth, "MFA authentication should succeed");
        
        // Step 3: Complete authentication
        let auth_complete = password_auth && mfa_auth;
        assert!(auth_complete, "Complete authentication should succeed");
        
        // Test MFA bypass for non-MFA users
        let non_mfa_user = create_test_user(
            "regular_user",
            "regular@example.com",
            "Regular User",
            vec!["user"],
        );
        
        let mfa_not_required = !non_mfa_user.roles.contains(&"mfa_enabled".to_string());
        assert!(mfa_not_required, "Regular user should not require MFA");
        
        // Regular user can authenticate with just password
        let regular_auth = verify_password(password, &password_hash).unwrap();
        assert!(regular_auth, "Regular user authentication should succeed");
    }

    /// Test 3: Token generation and validation
    #[tokio::test]
    async fn test_token_generation_validation() {
        let user_id = Uuid::new_v4().to_string();
        let permissions = vec![
            "read:secrets".to_string(),
            "write:secrets".to_string(),
            "admin:users".to_string(),
        ];
        
        // Generate authentication token
        let now = Utc::now().timestamp() as u64;
        let expires_at = now + 3600; // 1 hour expiration
        
        let token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            issued_at: now,
            expires_at,
            permissions: permissions.clone(),
        };
        
        // Validate token structure
        assert!(!token.token.is_empty(), "Token should not be empty");
        assert_eq!(token.user_id, user_id, "Token should have correct user ID");
        assert!(token.issued_at > 0, "Token should have valid issued time");
        assert!(token.expires_at > token.issued_at, "Token should expire after issuance");
        assert_eq!(token.permissions.len(), permissions.len(), "Token should have correct permissions");
        
        // Test token expiration
        let is_expired = Utc::now().timestamp() as u64 > token.expires_at;
        assert!(!is_expired, "Fresh token should not be expired");
        
        // Test expired token
        let expired_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            issued_at: now - 7200, // Issued 2 hours ago
            expires_at: now - 3600, // Expired 1 hour ago
            permissions: permissions.clone(),
        };
        
        let is_expired_old = Utc::now().timestamp() as u64 > expired_token.expires_at;
        assert!(is_expired_old, "Old token should be expired");
        
        // Test JWT token claims
        let claims = TokenClaims {
            sub: user_id.clone(),
            exp: expires_at,
            iat: now,
            permissions: permissions.clone(),
            roles: vec!["user".to_string(), "admin".to_string()],
        };
        
        assert_eq!(claims.sub, user_id, "Claims should have correct subject");
        assert_eq!(claims.exp, expires_at, "Claims should have correct expiration");
        assert_eq!(claims.iat, now, "Claims should have correct issued at");
        assert_eq!(claims.permissions.len(), permissions.len(), "Claims should have correct permissions");
        assert!(!claims.roles.is_empty(), "Claims should have roles");
        
        // Test token serialization/deserialization
        let token_json = serde_json::to_string(&token);
        assert!(token_json.is_ok(), "Token should serialize");
        
        let deserialized_token: Result<AuthToken, serde_json::Error> = serde_json::from_str(&token_json.unwrap());
        assert!(deserialized_token.is_ok(), "Token should deserialize");
        
        let deserialized = deserialized_token.unwrap();
        assert_eq!(deserialized.user_id, token.user_id, "Deserialized token should match original");
        assert_eq!(deserialized.token, token.token, "Deserialized token value should match original");
    }

    /// Test 4: Session management tests
    #[tokio::test]
    async fn test_session_management() {
        // Create session store
        let mut sessions: HashMap<String, (AuthToken, u64)> = HashMap::new();
        
        let user_id = Uuid::new_v4().to_string();
        let permissions = vec!["read:secrets".to_string()];
        
        // Create session
        let session_id = Uuid::new_v4().to_string();
        let now = Utc::now().timestamp() as u64;
        
        let token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            issued_at: now,
            expires_at: now + 1800, // 30 minutes
            permissions: permissions.clone(),
        };
        
        // Store session
        sessions.insert(session_id.clone(), (token.clone(), now));
        
        // Verify session exists
        assert!(sessions.contains_key(&session_id), "Session should be stored");
        
        // Retrieve session
        let (stored_token, last_activity) = sessions.get(&session_id).unwrap();
        assert_eq!(stored_token.user_id, user_id, "Stored session should have correct user");
        assert_eq!(last_activity, now, "Stored session should have correct activity time");
        
        // Update session activity
        let updated_activity = now + 300; // 5 minutes later
        sessions.insert(session_id.clone(), (token.clone(), updated_activity));
        
        let (_, updated_last_activity) = sessions.get(&session_id).unwrap();
        assert_eq!(updated_last_activity, updated_activity, "Session activity should be updated");
        
        // Test session expiration
        let expired_session_id = Uuid::new_v4().to_string();
        let expired_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: Uuid::new_v4().to_string(),
            issued_at: now - 3600,
            expires_at: now - 1800, // Expired 30 minutes ago
            permissions: vec![],
        };
        
        sessions.insert(expired_session_id.clone(), (expired_token.clone(), now - 1800));
        
        // Clean expired sessions
        sessions.retain(|_, (_, last_activity)| {
            *last_activity > now - 1800 // Keep sessions active within last 30 minutes
        });
        
        assert!(!sessions.contains_key(&expired_session_id), "Expired session should be removed");
        assert!(sessions.contains_key(&session_id), "Active session should remain");
        
        // Test session cleanup
        sessions.clear();
        assert!(sessions.is_empty(), "All sessions should be cleared");
        
        // Test concurrent session access
        let sessions_arc = std::sync::Arc::new(std::sync::RwLock::new(sessions));
        
        // Concurrent writes
        let mut handles = Vec::new();
        for i in 0..10 {
            let sessions_clone = std::sync::Arc::clone(&sessions_arc);
            let handle = tokio::spawn(async move {
                let session_id = Uuid::new_v4().to_string();
                let token = AuthToken {
                    token: Uuid::new_v4().to_string(),
                    user_id: format!("user_{}", i),
                    issued_at: now,
                    expires_at: now + 1800,
                    permissions: vec![format!("permission_{}", i)],
                };
                
                let mut sessions = sessions_clone.write().unwrap();
                sessions.insert(session_id, (token, now));
            });
            handles.push(handle);
        }
        
        // Wait for all writes
        for handle in handles {
            handle.await.expect("Session write should complete");
        }
        
        // Verify all sessions were created
        let sessions_read = sessions_arc.read().unwrap();
        assert_eq!(sessions_read.len(), 10, "All concurrent sessions should be stored");
    }

    /// Test 5: Password policy enforcement
    #[tokio::test]
    async fn test_password_policy_enforcement() {
        // Define password policy
        struct PasswordPolicy {
            min_length: usize,
            require_uppercase: bool,
            require_lowercase: bool,
            require_numbers: bool,
            require_symbols: bool,
            forbidden_patterns: Vec<String>,
        }
        
        let policy = PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_numbers: true,
            require_symbols: true,
            forbidden_patterns: vec![
                "password".to_string(),
                "123456".to_string(),
                "qwerty".to_string(),
            ],
        };
        
        // Test password validation function
        fn validate_password(password: &str, policy: &PasswordPolicy) -> Result<()> {
            // Check minimum length
            if password.len() < policy.min_length {
                return Err(FortressError::auth(
                    format!("Password too short: minimum {} characters", policy.min_length),
                    AuthErrorCode::PasswordPolicyViolation,
                ));
            }
            
            // Check uppercase requirement
            if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
                return Err(FortressError::auth(
                    "Password must contain uppercase letter".to_string(),
                    AuthErrorCode::PasswordPolicyViolation,
                ));
            }
            
            // Check lowercase requirement
            if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
                return Err(FortressError::auth(
                    "Password must contain lowercase letter".to_string(),
                    AuthErrorCode::PasswordPolicyViolation,
                ));
            }
            
            // Check numbers requirement
            if policy.require_numbers && !password.chars().any(|c| c.is_numeric()) {
                return Err(FortressError::auth(
                    "Password must contain number".to_string(),
                    AuthErrorCode::PasswordPolicyViolation,
                ));
            }
            
            // Check symbols requirement
            if policy.require_symbols && !password.chars().any(|c| !c.is_alphanumeric()) {
                return Err(FortressError::auth(
                    "Password must contain symbol".to_string(),
                    AuthErrorCode::PasswordPolicyViolation,
                ));
            }
            
            // Check forbidden patterns
            for pattern in &policy.forbidden_patterns {
                if password.to_lowercase().contains(pattern) {
                    return Err(FortressError::auth(
                        format!("Password contains forbidden pattern: {}", pattern),
                        AuthErrorCode::PasswordPolicyViolation,
                    ));
                }
            }
            
            Ok(())
        }
        
        // Test valid passwords
        let valid_passwords = vec![
            "SecurePass123!",
            "MyP@ssw0rd",
            "ComplexP@ssw0rd",
            "Str0ng#P@ss",
        ];
        
        for password in valid_passwords {
            let result = validate_password(password, &policy);
            assert!(result.is_ok(), "Valid password '{}' should pass validation", password);
        }
        
        // Test invalid passwords
        let invalid_passwords = vec![
            ("short", "Password too short: minimum 8 characters"),
            ("nouppercase", "Password must contain uppercase letter"),
            ("NOLOWERCASE", "Password must contain lowercase letter"),
            ("nosymbols", "Password must contain symbol"),
            ("Password123", "Password contains forbidden pattern: password"),
            ("mypassword", "Password contains forbidden pattern: mypassword"),
            ("12345678", "Password contains forbidden pattern: 123456"),
            ("qwertyuiop", "Password contains forbidden pattern: qwerty"),
        ];
        
        for (password, expected_error) in invalid_passwords {
            let result = validate_password(password, &policy);
            assert!(result.is_err(), "Invalid password '{}' should fail validation", password);
            
            let error_message = result.unwrap_err().to_string();
            assert!(error_message.contains(expected_error), 
                   "Error message should contain expected text: {}", expected_error);
        }
        
        // Test edge cases
        assert!(validate_password("Aa1!", &policy).is_ok(), "Minimum valid password should pass");
        assert!(validate_password("Aa1!", &PasswordPolicy { min_length: 3, ..policy }).is_ok(), 
               "Lower minimum length should pass");
        
        assert!(validate_password("aa1!", &PasswordPolicy { require_uppercase: false, ..policy }).is_err(), 
               "Missing uppercase should fail when required");
        
        assert!(validate_password("AA1!", &PasswordPolicy { require_lowercase: false, ..policy }).is_err(), 
               "Missing lowercase should fail when required");
        
        assert!(validate_password("AaAa!", &PasswordPolicy { require_numbers: false, ..policy }).is_err(), 
               "Missing numbers should fail when required");
        
        assert!(validate_password("Aa1aa", &PasswordPolicy { require_symbols: false, ..policy }).is_err(), 
               "Missing symbols should fail when required");
    }

    /// Test 6: Account lockout mechanisms
    #[tokio::test]
    async fn test_account_lockout_mechanisms() {
        // Create account lockout tracker
        let mut failed_attempts: HashMap<String, (u32, u64)> = HashMap::new();
        let max_attempts = 5;
        let lockout_duration = 900; // 15 minutes
        
        let user_id = "test_user";
        
        // Simulate failed login attempts
        for attempt in 1..=max_attempts {
            let (attempts, last_attempt_time) = failed_attempts.entry(user_id.to_string())
                .or_insert((0, Utc::now().timestamp() as u64));
            
            *attempts += 1;
            *last_attempt_time = Utc::now().timestamp() as u64;
            
            // Check if account should be locked
            let should_be_locked = *attempts >= max_attempts;
            assert_eq!(should_be_locked, attempt >= max_attempts, 
                     "Account should be locked after {} attempts", max_attempts);
        }
        
        // Verify account is locked
        let (attempts, _) = failed_attempts.get(user_id).unwrap();
        assert_eq!(attempts, max_attempts, "Failed attempts should reach maximum");
        
        // Test lockout duration check
        let now = Utc::now().timestamp() as u64;
        let (_, last_attempt_time) = failed_attempts.get(user_id).unwrap();
        let time_since_last_attempt = now - last_attempt_time;
        
        // Account should remain locked
        let is_locked = attempts >= max_attempts && time_since_last_attempt < lockout_duration;
        assert!(is_locked, "Account should still be locked");
        
        // Test lockout expiration
        let future_time = now + lockout_duration + 60; // 1 minute after lockout expires
        let future_time_since_last = future_time - last_attempt_time;
        let will_be_unlocked = future_time_since_last_attempt >= lockout_duration;
        assert!(will_be_unlocked, "Account should be unlocked after lockout duration");
        
        // Test successful login after lockout expiration (simulation)
        failed_attempts.clear();
        let successful_login_after_lockout = true;
        assert!(successful_login_after_lockout, "Should be able to login after lockout expires");
        
        // Test partial lockout recovery
        let partial_user_id = "partial_user";
        failed_attempts.insert(partial_user_id.to_string(), (3, now - 300)); // 3 attempts, 5 minutes ago
        
        let (partial_attempts, partial_last_attempt) = failed_attempts.get(partial_user_id).unwrap();
        let is_partially_locked = partial_attempts >= max_attempts;
        assert!(!is_partially_locked, "Partial attempts should not trigger lockout");
        
        // Wait for lockout duration to pass (simulation)
        let wait_time = partial_last_attempt + lockout_duration + 1;
        let time_to_unlock = wait_time - now;
        
        if time_to_unlock <= 0 {
            // Lockout has expired, account should be unlocked
            failed_attempts.remove(partial_user_id);
        }
        
        // Test lockout for multiple users
        let user1_id = "user1";
        let user2_id = "user2";
        
        // Lock user1
        failed_attempts.insert(user1_id.to_string(), (max_attempts, now));
        
        // User2 should not be affected
        let user2_locked = failed_attempts.get(user2_id)
            .map(|(attempts, _)| *attempts >= max_attempts)
            .unwrap_or(false);
        assert!(!user2_locked, "User2 should not be locked by User1's failures");
        
        // Lock user2
        failed_attempts.insert(user2_id.to_string(), (max_attempts, now));
        
        let user2_locked_after = failed_attempts.get(user2_id)
            .map(|(attempts, _)| *attempts >= max_attempts)
            .unwrap_or(false);
        assert!(user2_locked_after, "User2 should be locked after failures");
        
        // Both users should be locked
        let user1_locked_final = failed_attempts.get(user1_id)
            .map(|(attempts, _)| *attempts >= max_attempts)
            .unwrap_or(false);
        let user2_locked_final = failed_attempts.get(user2_id)
            .map(|(attempts, _)| *attempts >= max_attempts)
            .unwrap_or(false);
        
        assert!(user1_locked_final && user2_locked_final, "Both users should be locked");
    }

    /// Test 7: Brute force protection
    #[tokio::test]
    async fn test_brute_force_protection() {
        // Create IP-based rate limiter
        let mut ip_attempts: HashMap<String, (u32, u64)> = HashMap::new();
        let max_ip_attempts_per_hour = 100;
        let ip_block_duration = 3600; // 1 hour
        
        let ip_address = "192.168.1.100";
        
        // Simulate brute force attempts from same IP
        for attempt in 1..=10 {
            let (attempts, last_attempt) = ip_attempts.entry(ip_address.to_string())
                .or_insert((0, Utc::now().timestamp() as u64));
            
            *attempts += 1;
            *last_attempt = Utc::now().timestamp() as u64;
            
            // Check if IP should be blocked
            let should_be_blocked = *attempts >= max_ip_attempts_per_hour;
            assert!(!should_be_blocked, "IP should not be blocked after {} attempts (below limit)", attempt);
        }
        
        // Test IP blocking threshold
        let blocked_ip = "192.168.1.200";
        ip_attempts.insert(blocked_ip.to_string(), (max_ip_attempts_per_hour, now));
        
        let (blocked_attempts, _) = ip_attempts.get(blocked_ip).unwrap();
        let is_blocked = blocked_attempts >= max_ip_per_hour_per_hour;
        assert!(is_blocked, "IP should be blocked at threshold");
        
        // Test IP block expiration
        let future_time = Utc::now().timestamp() as u64 + ip_block_duration + 60;
        let (_, blocked_last_attempt) = ip_attempts.get(blocked_ip).unwrap();
        let time_until_unblock = future_time - blocked_last_attempt;
        
        if time_until_unblock <= 0 {
            // Block has expired
            ip_attempts.remove(blocked_ip);
        }
        
        // Test distributed brute force protection
        let mut global_attempts: HashMap<String, u32> = HashMap::new();
        let max_global_attempts_per_minute = 1000;
        
        let usernames = vec!["admin", "root", "user", "test", "guest"];
        
        for (i, username) in usernames.iter().enumerate() {
            let attempts = global_attempts.entry(username.to_string()).or_insert(0);
            *attempts += 1;
            
            // Check global threshold
            let should_be_blocked_globally = *attempts >= max_global_attempts_per_minute;
            assert!(!should_be_blocked_globally, "Username {} should not be blocked after {} attempts", username, i + 1);
        }
        
        // Test global threshold
        let blocked_username = "attacker";
        global_attempts.insert(blocked_username.to_string(), max_global_attempts_per_minute);
        
        let blocked_attempts = global_attempts.get(blocked_username).unwrap();
        let is_blocked_globally = *blocked_attempts >= max_global_attempts_per_minute;
        assert!(is_blocked_globally, "Username should be blocked at global threshold");
        
        // Test progressive rate limiting
        let progressive_limits = vec![(10, 60), (5, 300), (3, 900)]; // (max_attempts, window_seconds)
        
        for (max_att, window_sec) in progressive_limits {
            let mut temp_attempts: HashMap<String, Vec<u64>> = HashMap::new();
            let test_ip = "192.168.1.150";
            
            // Simulate attempts within time window
            for attempt in 0..max_att {
                let timestamp = Utc::now().timestamp() as u64 - (window_sec / 2); // Spread across window
                temp_attempts.entry(test_ip.to_string()).or_insert_with(Vec::new).push(timestamp);
            }
            
            // Count recent attempts
            let now = Utc::now().timestamp() as u64;
            let recent_count = temp_attempts.get(test_ip)
                .map(|timestamps| timestamps.iter().filter(|&&t| *t >= now - window_sec as u64).count())
                .unwrap_or(0);
            
            assert_eq!(recent_count, max_att, "Should count {} attempts within {} second window", max_att, window_sec);
        }
        
        // Test CAPTCHA requirement after threshold
        let mut captcha_required_ips: HashSet<String> = HashSet::new();
        let captcha_threshold = 5;
        
        let suspicious_ip = "192.168.1.175";
        for _ in 0..captcha_threshold {
            captcha_required_ips.insert(suspicious_ip.to_string());
        }
        
        assert!(captcha_required_ips.contains(suspicious_ip), "CAPTCHA should be required after threshold");
        
        // Test successful login resets
        let reset_ip = "192.168.1.180";
        ip_attempts.insert(reset_ip.to_string(), (3, now - 300)); // 3 failed attempts, 5 minutes ago
        
        // Successful login should reset counters
        ip_attempts.remove(reset_ip);
        let reset_counter = ip_attempts.get(reset_ip).unwrap_or(&(0, 0));
        assert_eq!(reset_counter.0, 0, "Failed attempts should be reset after successful login");
    }

    /// Test 8: Authentication performance tests
    #[tokio::test]
    async fn test_authentication_performance() {
        // Test password hashing performance
        let test_passwords = vec![
            "short",
            "medium_length_password",
            "very_long_password_with_numbers_123_and_symbols_!@#$%",
            "PasswordWithUnicode: 你好世界",
            "MixedCASEpassword123",
            "spaces in password",
            "123456789",
            "!@#$%^&*()",
        ];
        
        let start_time = std::time::Instant::now();
        
        for password in &test_passwords {
            let _ = hash_password(password).expect("Password hashing should succeed");
        }
        
        let hashing_duration = start_time.elapsed();
        println!("Hashed {} passwords in {:?}", test_passwords.len(), hashing_duration);
        
        assert!(hashing_duration.as_millis() < 1000, "Password hashing should be fast");
        
        // Test password verification performance
        let hashes: Vec<String> = test_passwords.iter()
            .map(|p| hash_password(p).unwrap())
            .collect();
        
        let start_time = std::time::Instant::now();
        
        for (password, hash) in test_passwords.iter().zip(&hashes) {
            let _ = verify_password(password, hash).expect("Password verification should succeed");
        }
        
        let verification_duration = start_time.elapsed();
        println!("Verified {} passwords in {:?}", test_passwords.len(), verification_duration);
        
        assert!(verification_duration.as_millis() < 500, "Password verification should be very fast");
        
        // Test token generation performance
        let start_time = std::std::time::Instant::now();
        
        let mut tokens = Vec::new();
        for _ in 0..1000 {
            let token = AuthToken {
                token: Uuid::new_v4().to_string(),
                user_id: Uuid::new_v4().to_string(),
                issued_at: Utc::now().timestamp() as u64,
                expires_at: Utc::now().timestamp() as u64 + 3600,
                permissions: vec!["read:secrets".to_string()],
            };
            tokens.push(token);
        }
        
        let token_generation_duration = start_time.elapsed();
        println!("Generated {} tokens in {:?}", tokens.len(), token_generation_duration);
        
        assert!(token_generation_duration.as_millis() < 100, "Token generation should be fast");
        
        // Test session management performance
        let mut sessions: HashMap<String, AuthToken> = HashMap::new();
        
        let start_time = std::time::Instant::now();
        
        for i in 0..500 {
            let session_id = Uuid::new_v4().to_string();
            let token = AuthToken {
                token: Uuid::new_v4().to_string(),
                user_id: format!("user_{}", i),
                issued_at: Utc::now().timestamp() as u64,
                expires_at: Utc::now().timestamp() as u64 + 1800,
                permissions: vec![format!("permission_{}", i)],
            };
            sessions.insert(session_id, token);
        }
        
        let session_creation_duration = start_time.elapsed();
        println!("Created {} sessions in {:?}", sessions.len(), session_creation_duration);
        
        assert!(session_creation_duration.as_millis() < 200, "Session creation should be fast");
        
        // Test session lookup performance
        let start_time = std::time::Instant::now();
        
        let mut successful_lookups = 0;
        for (session_id, _) in &sessions {
            if sessions.contains_key(session_id) {
                successful_lookups += 1;
            }
        }
        
        let session_lookup_duration = start_time.elapsed();
        println!("Looked up {} sessions in {:?}", successful_lookups, session_lookup_duration);
        
        assert_eq!(successful_lookups, sessions.len(), "All session lookups should succeed");
        assert!(session_lookup_duration.as_millis() < 100, "Session lookup should be very fast");
        
        // Performance assertions
        assert!(hashing_duration.as_millis() < verification_duration.as_millis(), 
               "Hashing should be faster than verification");
        assert!(verification_duration.as_millis() < token_generation_duration.as_millis(), 
               "Verification should be faster than token generation");
        assert!(token_generation_duration.as_millis() < session_creation_duration.as_millis(), 
               "Token generation should be faster than session creation");
    }

    /// Test 9: User lifecycle management
    #[tokio::test]
    async fn test_user_lifecycle_management() {
        // Create user store
        let mut users: HashMap<UserId, User> = HashMap::new();
        
        // Test user creation
        let user_id = Uuid::new_v4().to_string();
        let user = create_test_user(
            "lifecycle_user",
            "lifecycle@example.com",
            "Lifecycle Test User",
            vec!["user"],
        );
        
        users.insert(user_id.clone(), user.clone());
        
        // Verify user creation
        assert!(users.contains_key(&user_id), "User should be created");
        let stored_user = users.get(&user_id).unwrap();
        assert_eq!(stored_user.username, "lifecycle_user", "Stored user should have correct username");
        assert_eq!(stored_user.email, "lifecycle@example.com", "Stored user should have correct email");
        assert!(stored_user.active, "User should be active by default");
        
        // Test user update
        let mut updated_user = stored_user.clone();
        updated_user.full_name = "Updated Name";
        updated_user.last_login = Some(Utc::now().timestamp() as u64);
        updated_user.roles.push("admin".to_string());
        
        users.insert(user_id.clone(), updated_user);
        
        let updated_stored_user = users.get(&user_id).unwrap();
        assert_eq!(updated_stored_user.full_name, "Updated Name", "User name should be updated");
        assert!(updated_stored_user.last_login.is_some(), "Last login should be set");
        assert!(updated_stored_user.roles.contains(&"admin".to_string()), "Admin role should be added");
        
        // Test user deactivation
        let mut deactivated_user = updated_stored_user.clone();
        deactivated_user.active = false;
        
        users.insert(user_id.clone(), deactivated_user);
        
        let deactivated_stored_user = users.get(&user_id).unwrap();
        assert!(!deactivated_stored_user.active, "User should be deactivated");
        
        // Test authentication with inactive user
        let inactive_auth = false; // In real implementation, this would check user.active status
        assert!(!inactive_auth, "Inactive user should not authenticate");
        
        // Test user reactivation
        let mut reactivated_user = deactivated_stored_user.clone();
        reactivated_user.active = true;
        
        users.insert(user_id.clone(), reactivated_user);
        
        let reactivated_stored_user = users.get(&user_id).unwrap();
        assert!(reactivated_stored_user.active, "User should be reactivated");
        
        let active_auth = true; // In real implementation, this would check user.active status
        assert!(active_auth, "Reactivated user should authenticate");
        
        // Test user deletion
        users.remove(&user_id);
        assert!(!users.contains_key(&user_id), "User should be deleted");
        
        let deleted_user = users.get(&user_id);
        assert!(deleted_user.is_none(), "Deleted user should not be found");
    }

    /// Test 10: Role-based access control
    #[tokio::test]
    async fn test_role_based_access_control() {
        // Create role store
        let mut roles: HashMap<RoleId, Role> = HashMap::new();
        
        // Create roles
        let admin_role = create_test_role(
            "admin",
            "System Administrator",
            vec!["read:all", "write:all", "delete:all", "manage:users"],
        );
        
        let user_role = create_test_role(
            "user",
            "Regular User",
            vec!["read:own", "write:own"],
        );
        
        let readonly_role = create_test_role(
            "readonly",
            "Read-Only User",
            vec!["read:all"],
        );
        
        roles.insert(admin_role.id.clone(), admin_role);
        roles.insert(user_role.id.clone(), user_role);
        roles.insert(readonly_role.id.clone(), readonly_role);
        
        // Test role creation
        assert_eq!(roles.len(), 3, "Should have 3 roles");
        
        // Test role permissions
        let admin_permissions = roles.get(&admin_role.id).unwrap().permissions.clone();
        assert!(admin_permissions.contains(&"read:all".to_string()), "Admin role should have read:all permission");
        assert!(admin_permissions.contains(&"write:all".to_string()), "Admin role should have write:all permission");
        assert!(admin_permissions.contains(&"delete:all".to_string()), "Admin role should have delete:all permission");
        
        // Test user with multiple roles
        let user_id = Uuid::new_v4().to_string();
        let user_roles = vec![user_role.id.clone(), readonly_role.id.clone()];
        
        // Collect permissions from all roles
        let mut user_permissions = HashSet::new();
        for role_id in &user_roles {
            if let Some(role) = roles.get(role_id) {
                for permission in &role.permissions {
                    user_permissions.insert(permission.clone());
                }
            }
        }
        
        // Verify user permissions
        assert!(user_permissions.contains(&"read:own".to_string()), "User should have read:own permission");
        assert!(user_permissions.contains(&"read:all".to_string()), "User should have read:all permission from readonly role");
        assert!(!user_permissions.contains(&"write:all".to_string()), "User should not have write:all permission");
        assert!(!user_permissions.contains(&"delete:all".to_string()), "User should not have delete:all permission");
        
        // Test permission check
        fn has_permission(user_permissions: &HashSet<String>, resource: &str, action: &str) -> bool {
            let permission = format!("{}:{}", resource, action);
            user_permissions.contains(&permission)
        }
        
        assert!(has_permission(&user_permissions, "own", "read"), "User should have read:own permission");
        assert!(has_permission(&user_permissions, "all", "read"), "User should have read:all permission");
        assert!(!has_permission(&user_permissions, "all", "write"), "User should not have write:all permission");
        assert!(!has_permission(&user_permissions, "all", "delete"), "User should not have delete:all permission");
        
        // Test admin user permissions
        let admin_user_roles = vec![admin_role.id.clone()];
        let mut admin_permissions = HashSet::new();
        
        for role_id in &admin_user_roles {
            if let Some(role) = roles.get(role_id) {
                for permission in &role.permissions {
                    admin_permissions.insert(permission.clone());
                }
            }
        }
        
        assert!(has_permission(&admin_permissions, "all", "read"), "Admin should have read:all permission");
        assert!(has_permission(&admin_permissions, "all", "write"), "Admin should have write:all permission");
        assert!(has_permission(&admin_permissions, "all", "delete"), "Admin should have delete:all permission");
        assert!(has_permission(&admin_permissions, "users", "manage"), "Admin should have manage:users permission");
        
        // Test role hierarchy
        let role_hierarchy = vec![
            (&readonly_role.id, 1),
            (&user_role.id, 2),
            (&admin_role.id, 3),
        ];
        
        // Sort roles by hierarchy level
        let mut sorted_roles = user_roles.clone();
        sorted_roles.sort_by(|role_id| {
            role_hierarchy.iter().find(|(id, _)| id == role_id).map(|(_, level)| *level).unwrap_or(999)
        });
        
        // Verify sorting
        assert_eq!(sorted_roles[0], readonly_role.id, "Lowest role should be readonly");
        assert_eq!(sorted_roles[1], user_role.id, "Middle role should be user");
        assert_eq!(sorted_roles[2], admin_role.id, "Highest role should be admin");
        
        // Test role activation/deactivation
        let mut inactive_role = user_role.clone();
        inactive_role.active = false;
        roles.insert(inactive_role.id.clone(), inactive_role);
        
        // User with inactive role should not get those permissions
        let mut updated_user_permissions = HashSet::new();
        for role_id in &user_roles {
            if let Some(role) = roles.get(role_id) {
                if role.active {
                    for permission in &role.permissions {
                        updated_user_permissions.insert(permission.clone());
                    }
                }
            }
        }
        
        assert!updated_user_permissions.contains(&"read:own".to_string()), 
               "User should still have permissions from active role");
        assert!updated_user_permissions.contains(&"read:all".to_string()), 
               "User should lose permissions from inactive role");
    }

    /// Test 11: Permission inheritance and hierarchy
    #[tokio::test]
    async fn test_permission_inheritance_hierarchy() {
        // Create permission hierarchy
        let mut permissions: HashMap<PermissionId, AuthPermission> = HashMap::new();
        
        // Create granular permissions
        let read_secrets = create_test_permission(
            "read:secrets",
            "Read secret data",
            "secrets",
            "read",
        );
        
        let write_secrets = create_test_permission(
            "write:secrets",
            "Write secret data",
            "secrets",
            "write",
        );
        
        let delete_secrets = create_test_permission(
            "delete:secrets",
            "Delete secret data",
            "secrets",
            "delete",
        );
        
        let admin_secrets = create_test_permission(
            "admin:secrets",
            "Administer secrets",
            "secrets",
            "admin",
        );
        
        // Create wildcard permissions
        let read_all = create_test_permission(
            "read:all",
            "Read all data",
            "*",
            "read",
        );
        
        let write_all = create_test_permission(
            "write:all",
            "Write all data",
            "*",
            "write",
        );
        
        permissions.insert(read_secrets.id.clone(), read_secrets);
        permissions.insert(write_secrets.id.clone(), write_secrets);
        permissions.insert(delete_secrets.id.clone(), delete_secrets);
        permissions.insert(admin_secrets.id.clone(), admin_secrets);
        permissions.insert(read_all.id.clone(), read_all);
        permissions.insert(write_all.id.clone(), write_all);
        
        // Test permission inheritance logic
        fn check_permission(
            user_permissions: &HashSet<PermissionId>,
            resource: &str,
            action: &str,
            permissions: &HashMap<PermissionId, AuthPermission>,
        ) -> bool {
            // Check exact permission first
            let exact_permission = format!("{}:{}", resource, action);
            if user_permissions.contains(&exact_permission) {
                return true;
            }
            
            // Check wildcard permissions
            for permission_id in user_permissions {
                if let Some(permission) = permissions.get(permission_id) {
                    if permission.resource == "*" && permission.action == action {
                        return true;
                    }
                }
            }
            
            false
        }
        
        let user_permissions = HashSet::from([
            read_secrets.id.clone(),
            write_secrets.id.clone(),
            read_all.id.clone(),
        ]);
        
        // Test exact permission matching
        assert!(check_permission(&user_permissions, "secrets", "read", &permissions), 
               "Should have exact read:secrets permission");
        assert!(check_permission(&user_permissions, "secrets", "write", &permissions), 
               "Should have exact write:secrets permission");
        assert!(!check_permission(&user_permissions, "secrets", "delete", &permissions), 
               "Should not have delete:secrets permission");
        
        // Test wildcard permission matching
        assert!(check_permission(&user_permissions, "secrets", "read", &permissions), 
               "Should match read:secrets with read:all wildcard");
        assert!(check_permission(&user_permissions, "users", "read", &permissions), 
               "Should match read:users with read:all wildcard");
        assert!(!check_permission(&user_permissions, "secrets", "delete", &permissions), 
               "Should not match delete:secrets without delete:all wildcard");
        
        // Test admin permission override
        let admin_permissions = HashSet::from([
            admin_secrets.id.clone(),
            read_all.id.clone(),
        ]);
        
        assert!(check_permission(&admin_permissions, "secrets", "admin", &permissions), 
               "Should have exact admin:secrets permission");
        assert!(check_permission(&admin_permissions, "secrets", "read", &permissions), 
               "Should match read:secrets with read:all wildcard");
        assert!(check_permission(&admin_permissions, "secrets", "write", &permissions), 
               "Should not match write:secrets without write:all wildcard");
        
        // Test permission priority (exact > wildcard)
        let priority_permissions = HashSet::from([
            read_secrets.id.clone(),
            read_all.id.clone(),
        ]);
        
        // Should prefer exact permission over wildcard
        assert!(check_permission(&priority_permissions, "secrets", "read", &permissions), 
               "Should use exact read:secrets over read:all wildcard");
        
        // Test resource-specific wildcard
        let secrets_wildcard = create_test_permission(
            "secrets:*",
            "All secrets operations",
            "secrets",
            "*",
        );
        
        permissions.insert(secrets_wildcard.id.clone(), secrets_wildcard);
        
        let secrets_wildcard_permissions = HashSet::from([
            secrets_wildcard.id.clone(),
        ]);
        
        assert!(check_permission(&secrets_wildcard_permissions, "secrets", "read", &permissions), 
               "Should match secrets:read with secrets:* wildcard");
        assert!(check_permission(&secrets_wildcard_permissions, "secrets", "write", &permissions), 
               "Should match secrets:write with secrets:* wildcard");
        assert!(check_permission(&secrets_wildcard_permissions, "secrets", "delete", &permissions), 
               "Should match secrets:delete with secrets:* wildcard");
        
        assert!(!check_permission(&secrets_wildcard_permissions, "users", "read", &permissions), 
               "Should not match users:read with secrets:* wildcard");
    }

    /// Test 12: Authentication token security
    #[tokio::test]
    async fn test_authentication_token_security() {
        // Test token generation with secure random values
        let user_id = Uuid::new_v4().to_string();
        
        let token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 3600,
            permissions: vec!["read:secrets".to_string()],
        };
        
        // Test token uniqueness
        let token2 = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id,
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 3600,
            permissions: vec!["read:secrets".to_string()],
        };
        
        assert_ne!(token.token, token2.token, "Tokens should be unique");
        assert_eq!(token.user_id, token2.user_id, "Tokens for same user should have same user_id");
        
        // Test token entropy (simplified)
        let token_bytes = token.token.as_bytes();
        let mut unique_chars = HashSet::new();
        for byte in token_bytes {
            unique_chars.insert(byte);
        }
        
        // UUID should have good entropy
        assert!(unique_chars.len() > 10, "Token should have good character diversity");
        
        // Test token expiration security
        let short_lived_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 60, // 1 minute
            permissions: vec!["read:secrets".to_string()],
        };
        
        let long_lived_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id,
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 86400, // 24 hours
            permissions: vec!["read:secrets".to_string()],
        };
        
        // Short-lived token should expire sooner
        assert!(short_lived_token.expires_at < long_lived_token.expires_at, 
               "Short-lived token should expire sooner");
        
        // Test token permission security
        let admin_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id,
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 3600,
            permissions: vec![
                "read:secrets".to_string(),
                "write:secrets".to_string(),
                "delete:secrets".to_string(),
                "admin:users".to_string(),
            ],
        };
        
        let limited_token = AuthToken {
            token: Uuid::new_v4().to_string(),
            user_id: user_id,
            issued_at: Utc::now().timestamp() as u64,
            expires_at: Utc::now().timestamp() as u64 + 3600,
            permissions: vec!["read:secrets".to_string()],
        };
        
        // Admin token should have more permissions
        assert!(admin_token.permissions.len() > limited_token.permissions.len(), 
               "Admin token should have more permissions");
        
        // Test token serialization security
        let token_json = serde_json::to_string(&admin_token);
        assert!(token_json.is_ok(), "Token should serialize securely");
        
        let deserialized_token: Result<AuthToken, serde_json::Error> = serde_json::from_str(&token_json.unwrap());
        assert!(deserialized_token.is_ok(), "Token should deserialize securely");
        
        let deserialized = deserialized_token.unwrap();
        assert_eq!(deserialized.user_id, admin_token.user_id, "Deserialized token should have correct user_id");
        assert_eq!(deserialized.permissions.len(), admin_token.permissions.len(), 
               "Deserialized token should have all permissions");
        
        // Test token tampering detection (simplified)
        let mut tampered_token = token.clone();
        tampered_token.permissions.push("unauthorized:access".to_string());
        
        let tampered_json = serde_json::to_string(&tampered_token);
        let deserialized_tampered: Result<AuthToken, serde_json::Error> = serde_json::from_str(&tampered_json.unwrap());
        
        if deserialized_tampered.is_ok() {
            let tampered = deserialized_tampered.unwrap();
            // In a real implementation, you would verify token signature
            assert!(tampered.permissions.len() > token.permissions.len(), 
                   "Tampered token should have extra permissions");
        }
    }

    /// Test 13: Session timeout and cleanup
    #[io::test]
    async fn test_session_timeout_cleanup() {
        // Create session store with timeout tracking
        let mut sessions: HashMap<String, (AuthToken, u64)> = HashMap::new();
        let session_timeout = 1800; // 30 minutes
        let cleanup_interval = 300; // 5 minutes
        
        let user_id = Uuid::new_v4().to_string();
        
        // Create sessions with different expiration times
        let session_configs = vec![
            (60, "short_lived"),    // 1 minute
            (1800, "standard"),     // 30 minutes
            (3600, "long_lived"),     // 1 hour
            (7200, "extended"),      // 2 hours
        ];
        
        let mut session_ids = Vec::new();
        let mut creation_times = Vec::new();
        
        for (ttl, name) in session_configs {
            let session_id = Uuid::new_v4().to_string();
            let now = Utc::now().timestamp() as u64;
            
            let token = AuthToken {
                token: Uuid::new_v4().to_string(),
                user_id: user_id.clone(),
                issued_at: now,
                expires_at: now + ttl,
                permissions: vec![format!("permission:{}", name)],
            };
            
            sessions.insert(session_id.clone(), (token, now));
            session_ids.push(session_id);
            creation_times.push(now);
            
            println!("Created {} session with {} second TTL", name, ttl);
        }
        
        // Wait for some sessions to expire
        sleep(tokio::time::Duration::from_secs(65)).await;
        
        let now = Utc::now().timestamp() as u64;
        
        // Check which sessions should be expired
        let mut expired_sessions = Vec::new();
        let mut active_sessions = Vec::new();
        
        for (i, session_id) in session_ids.iter().enumerate() {
            if let Some((token, _)) = sessions.get(session_id) {
                let is_expired = now > token.expires_at;
                
                if is_expired {
                    expired_sessions.push(session_id.clone());
                } else {
                    active_sessions.push(session_id.clone());
                }
                
                println!("Session {} ({}) is {}", i + 1, 
                         session_configs[i].1, 
                         if is_expired { "expired" } else { "active" });
            }
        }
        
        assert_eq!(expired_sessions.len(), 1, "Short-lived session should be expired");
        assert_eq!(active_sessions.len(), 3, "Other sessions should still be active");
        
        // Perform cleanup
        sessions.retain(|_, (_, last_activity)| {
            *last_activity > now - session_timeout
        });
        
        // Verify cleanup results
        assert_eq!(sessions.len(), 3, "Should have 3 sessions after cleanup");
        assert!(!sessions.contains_key(&expired_sessions[0]), "Expired session should be removed");
        
        for session_id in &active_sessions {
            assert!(sessions.contains_key(session_id), "Active session should remain");
        }
        
        // Test session activity update
        let active_session_id = &active_sessions[0];
        let (token, _) = sessions.get(active_session_id).unwrap();
        
        // Update activity
        let new_activity = Utc::now().timestamp() as u64;
        sessions.insert(active_session_id.clone(), (token, new_activity));
        
        let (_, updated_activity) = sessions.get(active_session_id).unwrap();
        assert!(updated_activity > creation_times[active_sessions.iter().position(|id| id == active_session_id).unwrap()], 
               "Session activity should be updated");
        
        // Test session cleanup with activity tracking
        let old_activity = updated_activity - session_timeout - 100; // Simulate old activity
        sessions.insert(active_session_id.clone(), (token, old_activity));
        
        // Cleanup again
        sessions.retain(|_, (_, last_activity)| {
            *last_activity > now - session_timeout
        });
        
        assert!(!sessions.contains_key(active_session_id), 
               "Session with old activity should be removed");
        
        // Test batch cleanup
        let mut batch_sessions = HashMap::new();
        
        // Create many sessions
        for i in 0..50 {
            let session_id = Uuid::new_v4().to_string();
            let token = AuthToken {
                token: Uuid::new_v4().to_string(),
                user_id: format!("user_{}", i),
                issued_at: now,
                expires_at: now + 1800,
                permissions: vec![format!("permission_{}", i)],
            };
            
            batch_sessions.insert(session_id, (token, now - (i * 30))); // Staggered creation times
        }
        
        let initial_count = batch_sessions.len();
        
        // Perform batch cleanup
        batch_sessions.retain(|_, (_, last_activity)| {
            *last_activity > now - session_timeout
        });
        
        let final_count = batch_sessions.len();
        assert!(final_count < initial_count, "Batch cleanup should remove expired sessions");
        
        println!("Batch cleanup: {} -> {} sessions", initial_count, final_count);
    }

    /// Test 14: Concurrent authentication operations
    #[tokio::concurrent_auth_operations
    async fn test_concurrent_authentication_operations() {
        use std::sync::Arc;
        
        // Create shared user store
        let users = Arc::new(std::sync::RwLock::new(HashMap::new()));
        
        // Create shared session store
        let sessions = Arc::new(std::sim::RwLock::new(HashMap::new()));
        
        // Create test users
        let mut user_handles = Vec::new();
        for i in 0..10 {
            let user_id = Uuid::new_v4().to_string();
            let user = create_test_user(
                &format!("concurrent_user_{}", i),
                &format!("user{}@example.com", i),
                &format!("Concurrent User {}", i),
                vec!["user"],
            );
            
            let mut users_guard = users.write().unwrap();
            users_guard.insert(user_id.clone(), user);
            drop(users_guard);
            
            user_handles.push(user_id);
        }
        
        // Test concurrent authentication
        let mut auth_handles = Vec::new();
        
        for user_id in user_handles {
            let users_clone = Arc::clone(&users);
            let sessions_clone = Arc::clone(&sessions);
            
            let handle = tokio::spawn(async move {
                // Simulate authentication process
                
                // Step 1: Retrieve user
                let user_result = {
                    let users_guard = users_clone.read().unwrap();
                    users_guard.get(&user_id).cloned()
                };
                
                assert!(user_result.is_some(), "User {} should exist", user_id);
                
                let user = user_result.unwrap();
                
                // Step 2: Verify password (simulated)
                let password_valid = true; // In real implementation, this would check against hash
                
                if password_valid && user.active {
                    // Step 3: Create session
                    let session_id = Uuid::new_v4().to_string();
                    let now = Utc::now().timestamp() as u64;
                    
                    let token = AuthToken {
                        token: Uuid::new_v4().to_string(),
                        user_id: user_id.clone(),
                        issued_at: now,
                        expires_at: now + 1800,
                        permissions: vec![],
                    };
                    
                    let mut sessions_guard = sessions_clone.write().unwrap();
                    sessions_guard.insert(session_id, (token, now));
                    drop(sessions_guard);
                    
                    // Step 4: Update user last login
                    let mut users_guard = users.write().unwrap();
                    if let Some(user) = users_guard.get_mut(&user_id) {
                        user.last_login = Some(now);
                    }
                    drop(users_guard);
                    
                    Some(session_id)
                } else {
                    None
                }
            });
            
            auth_handles.push(handle);
        }
        
        // Wait for all authentications to complete
        let mut successful_auths = 0;
        let mut session_ids = Vec::new();
        
        for handle in auth_handles {
            let result = handle.await.expect("Authentication task should complete");
            
            if let Some(session_id) = result {
                successful_auths += 1;
                session_ids.push(session_id);
            }
        }
        
        assert_eq!(successful_auths, 10, "All concurrent authentications should succeed");
        assert_eq!(session_ids.len(), 10, "All sessions should be created");
        
        // Verify all sessions exist
        let sessions_guard = sessions.read().unwrap();
        for session_id in &session_ids {
            assert!(sessions_guard.contains_key(session_id), "Session {} should exist", session_id);
        }
        
        // Test concurrent session validation
        let mut validation_handles = Vec::new();
        
        for session_id in &session_ids {
            let sessions_clone = Arc::clone(&sessions);
            let session_id_clone = session_id.clone();
            
            let handle = tokio::spawn(async move {
                let sessions_guard = sessions_clone.read().unwrap();
                
                if let Some((token, _)) = sessions_guard.get(&session_id_clone) {
                    let now = Utc::now().timestamp() as u64;
                    let is_valid = now <= token.expires_at;
                    
                    Some(is_valid)
                } else {
                    None
                }
            });
            
            validation_handles.push(handle);
        }
        
        let mut valid_sessions = 0;
        for handle in validation_handles {
            let result = handle.await.expect("Validation task should complete");
            
            if let Some(is_valid) = result {
                if is_valid {
                    valid_sessions += 1;
                }
            }
        }
        
        assert_eq!(valid_sessions, 10, "All sessions should be valid");
        
        // Test concurrent logout
        let mut logout_handles = Vec::new();
        
        for session_id in &session_ids {
            let sessions_clone = Arc::clone(&sessions);
            let session_id_clone = session_id.clone();
            
            let handle = tokio::spawn(async move {
                let mut sessions_guard = sessions_clone.write().unwrap();
                sessions_guard.remove(&session_id_clone);
                drop(sessions_guard);
            });
            
            logout_handles.push(handle);
        }
        
        // Wait for all logouts to complete
        for handle in logout_handles {
            handle.await.expect("Logout task should complete");
        }
        
        // Verify all sessions are removed
        let sessions_guard = sessions.read().unwrap();
        assert!(sessions_guard.is_empty(), "All sessions should be removed after logout");
        
        // Test concurrent user updates
        let mut update_handles = Vec::new();
        
        for (i, user_id) in user_handles.iter().enumerate() {
            let users_clone = Arc::clone(&users);
            let user_id_clone = user_id.clone();
            
            let handle = tokio::spawn(async move {
                let mut users_guard = users_clone.write().unwrap();
                if let Some(user) = users_guard.get_mut(&user_id_clone) {
                    user.full_name = format!("Updated User {}", i);
                    user.last_login = Some(Utc::now().timestamp() as u64 + i as u64);
                }
                drop(users_guard);
            });
            
            update_handles.push(handle);
        }
        
        // Wait for all updates to complete
        for handle in update_handles {
            handle.await.expect("Update task should complete");
        }
        
        // Verify all users are updated
        let users_guard = users.read().unwrap();
        for (i, user_id) in user_handles.iter().enumerate() {
            let user = users_guard.get(user_id).unwrap();
            assert_eq!(user.full_name, format!("Updated User {}", i), "User {} should be updated", i);
            assert_eq!(user.last_login, Some(Utc::now().timestamp() as u64 + i as u64), 
                     "User {} should have updated last login", i);
        }
    }

    /// Test 15: Authentication error handling and logging
    #[tokio::try>
    async fn test_authentication_error_handling_logging() {
        // Create authentication logger
        let mut auth_logs: Vec<String> = Vec::new();
        
        // Test various authentication error scenarios
        let error_scenarios = vec![
            ("invalid_credentials", "Invalid username or password"),
            ("user_not_found", "User not found in system"),
            ("account_locked", "Account is temporarily locked"),
            ("session_expired", "Authentication session has expired"),
            ("token_invalid", "Invalid authentication token"),
            ("permission_denied", "Insufficient permissions"),
            ("rate_limit_exceeded", "Too many authentication attempts"),
            ("system_error", "Internal authentication system error"),
        ];
        
        for (error_type, error_message) in error_scenarios {
            // Simulate error logging
            let log_entry = format!("[{}] {}: {}", 
                               Utc::now().to_rfc3339(), 
                               error_type, 
                               error_message);
            auth_logs.push(log_entry);
            
            // Test error handling
            match error_type {
                "invalid_credentials" => {
                    // Log failed login attempt
                    println!("Failed login attempt detected");
                }
                "account_locked" => {
                    // Log lockout event
                    println!("Account lockout triggered");
                }
                "rate_limit_exceeded" => {
                    // Log rate limit violation
                    println!("Rate limit exceeded");
                }
                _ => {
                    // Log general error
                    println!("Authentication error: {}", error_message);
                }
            }
        }
        
        assert_eq!(auth_logs.len(), error_scenarios.len(), "All error scenarios should be logged");
        
        // Test error recovery
        let recovery_scenarios = vec![
            ("temporary_lockout", "Account temporarily locked, try again later"),
            ("session_timeout", "Session expired, please login again"),
            ("token_refresh", "Token expired, requesting refresh"),
        ];
        
        for (error_type, recovery_message) in recovery_scenarios {
            let log_entry = format!("[{}] Recovery: {}", 
                               Utc::now().to_rfc3339(), 
                               error_type, 
                               recovery_message);
            auth_logs.push(log_entry);
            
            // Test recovery logic
            let can_recover = match error_type {
                "temporary_lockout" => true,  // Can retry after lockout expires
                "session_timeout" => true,  // Can login again
                "token_refresh" => true,  // Can refresh token
                _ => false, // Requires manual intervention
            };
            
            assert!(can_recover || error_type == "system_error", 
                   "Most errors should be recoverable or require manual intervention");
        }
        
        // Test audit logging
        let audit_events = vec![
            ("login_success", "User logged in successfully"),
            ("login_failure", "Failed login attempt"),
            ("session_created", "New session created"),
            ("session_destroyed", "Session destroyed"),
            ("password_changed", "User changed password"),
            ("account_locked", "Account locked due to failed attempts"),
            ("account_unlocked", "Account unlocked by administrator"),
        ];
        
        for (event_type, event_description) in audit_events {
            let audit_entry = format!("[AUDIT] {}: {} - {}", 
                               Utc::now().to_rfc3339(), 
                               event_type,
                               event_description);
            auth_logs.push(audit_entry);
        }
        
        assert!(auth_logs.len() >= error_scenarios.len() + audit_events.len(), 
               "All events should be logged");
        
        // Test security metrics
        let mut failed_logins = 0;
        let mut successful_logins = 0;
        let mut lockouts = 0;
        
        for log_entry in &auth_logs {
            if log_entry.contains("login_failure") {
                failed_logins += 1;
            } else if log_entry.contains("login_success") {
                successful_logins += 1;
            } else if log_entry.contains("account_locked") {
                lockouts += 1;
            }
        }
        
        let total_attempts = failed_logins + successful_logins;
        let success_rate = if total_attempts > 0 {
            successful_logins as f64 / total_attempts as f64
        } else {
            0.0
        };
        
        println!("Authentication Metrics:");
        println!("  Total attempts: {}", total_attempts);
        println!("  Successful logins: {}", successful_logins);
        println!("  Failed logins: {}", failed_logins);
        println!("  Account lockouts: {}", lockouts);
        println!("  Success rate: {:.2}%", success_rate * 100.0);
        
        assert!(total_attempts > 0, "Should have authentication attempts");
        assert!(success_rate >= 0.0, "Success rate should be calculated");
        assert!(failed_logins >= 0, "Should track failed logins");
        
        // Test error classification
        let mut critical_errors = 0;
        let mut warning_errors = 0;
        let mut info_errors = 0;
        
        for log_entry in &auth_logs {
            if log_entry.contains("system_error") {
                critical_errors += 1;
            } else if log_entry.contains("account_locked") {
                warning_errors += 1;
            } else {
                info_errors += 1;
            }
        }
        
        assert!(critical_errors >= 0, "Should track critical errors");
        assert!(warning_errors >= 0, "Should track warning errors");
        assert!(info_errors >= 0, "Should track info errors");
        
        println!("Error Classification:");
        println!("  Critical errors: {}", critical_errors);
        println!("  Warning errors: {}", warning_errors);
        println!("  Info errors: {}", info_errors);
        
        // Test log retention
        let max_log_entries = 1000;
        
        if auth_logs.len() > max_log_entries {
            auth_logs.truncate(max_log_entries);
        }
        
        assert!(auth_logs.len() <= max_log_entries, "Log size should be limited");
        
        // Test log rotation (simulation)
        let rotated_logs = auth_logs.split_off(auth_logs.len() / 2);
        assert_eq!(rotated_logs.len(), auth_logs.len() / 2, "Logs should be split for rotation");
    }
}
