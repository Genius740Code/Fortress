//! Comprehensive integration tests for OIDC Provider and FPE functionality
//!
//! This module provides integration tests to verify the proper functioning
//! of both OIDC Provider and Format-Preserving Encryption features.

use crate::error::FortressError;
use crate::oidc_provider::{
    OidcProvider, OidcConfig, OidcAuthRequest, OidcTokenRequest, OidcClient,
    RegoConfig, TokenExpiration, JwksConfig, RegoPolicyEngine,
};
use crate::format_preserving_encryption::{
    FormatPreservingEncryption, FpeConfig, FpeAlgorithm, DataFormat,
};
use crate::auth::AuthManager;
use serde_json::json;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Integration test suite for OIDC and FPE functionality
pub struct OidcFpeIntegrationTests {
    auth_manager: AuthManager,
    oidc_provider: OidcProvider,
    fpe_credit_card: FormatPreservingEncryption,
    fpe_ssn: FormatPreservingEncryption,
    fpe_phone: FormatPreservingEncryption,
    fpe_email: FormatPreservingEncryption,
}

impl OidcFpeIntegrationTests {
    /// Create a new test suite instance
    pub fn new() -> Result<Self, FortressError> {
        let mut auth_manager = AuthManager::new();
        
        // Create test user
        let user_id = auth_manager.create_user(
            "testuser".to_string(),
            "Password123!".to_string(),
        ).await?;
        
        // Assign test role
        let role_id = auth_manager.create_role(
            "test_role".to_string(),
            "Test role for integration tests".to_string(),
            vec!["read".to_string(), "write".to_string()],
        )?;
        
        auth_manager.assign_role(&user_id, role_id)?;

        // Create OIDC configuration
        let mut oidc_config = OidcConfig::default();
        
        // Add test client
        let client = OidcClient {
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            name: "Test Client".to_string(),
            redirect_uris: vec!["https://client.example.com/callback".to_string()],
            grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
            response_types: vec!["code".to_string()],
            scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string(), "read".to_string()],
            public: false,
            metadata: HashMap::new(),
        };
        
        oidc_config.clients.insert("test_client".to_string(), client);

        // Add Rego policy configuration
        oidc_config.rego_policies = Some(RegoConfig {
            policy_dir: "test_policies".to_string(),
            data_dir: Some("test_data".to_string()),
            enable_cache: true,
            cache_ttl: 300,
        });

        let oidc_provider = OidcProvider::new(oidc_config, auth_manager)?;

        // Create FPE instances
        let key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        
        let fpe_credit_card = FormatPreservingEncryption::new(
            FormatPreservingEncryption::credit_card_config(key.clone())
        )?;
        
        let fpe_ssn = FormatPreservingEncryption::new(
            FormatPreservingEncryption::ssn_config(key.clone())
        )?;
        
        let fpe_phone = FormatPreservingEncryption::new(
            FormatPreservingEncryption::phone_config(key.clone())
        )?;
        
        let fpe_email = FormatPreservingEncryption::new(
            FormatPreservingEncryption::email_config(key)
        )?;

        Ok(Self {
            auth_manager: oidc_provider.auth_manager().clone(),
            oidc_provider,
            fpe_credit_card,
            fpe_ssn,
            fpe_phone,
            fpe_email,
        })
    }

    /// Run all integration tests
    pub async fn run_all_tests(&mut self) -> Result<TestResults, FortressError> {
        let mut results = TestResults::new();

        // OIDC Provider Tests
        results.add_result("OIDC Authorization Flow", self.test_oidc_authorization_flow().await);
        results.add_result("OIDC Token Exchange", self.test_oidc_token_exchange().await);
        results.add_result("OIDC Refresh Token", self.test_oidc_refresh_token().await);
        results.add_result("OIDC User Info", self.test_oidc_user_info().await);
        results.add_result("OIDC Client Credentials", self.test_oidc_client_credentials().await);
        results.add_result("OIDC JWKS Endpoint", self.test_oidc_jwks_endpoint());
        results.add_result("OIDC PKCE Support", self.test_oidc_pkce_support().await);
        results.add_result("OIDC Rego Policies", self.test_oidc_rego_policies().await);

        // FPE Tests
        results.add_result("FPE Credit Card Encryption", self.test_fpe_credit_card_encryption());
        results.add_result("FPE SSN Encryption", self.test_fpe_ssn_encryption());
        results.add_result("FPE Phone Encryption", self.test_fpe_phone_encryption());
        results.add_result("FPE Email Encryption", self.test_fpe_email_encryption());
        results.add_result("FPE Round-trip", self.test_fpe_round_trip());
        results.add_result("FPE Format Preservation", self.test_fpe_format_preservation());
        results.add_result("FPE Luhn Validation", self.test_fpe_luhn_validation());

        // Integration Tests
        results.add_result("OIDC + FPE Integration", self.test_oidc_fpe_integration().await);
        results.add_result("Performance Benchmarks", self.test_performance_benchmarks().await);

        Ok(results)
    }

    /// Test OIDC authorization flow
    async fn test_oidc_authorization_flow(&mut self) -> Result<(), FortressError> {
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: Some("test_state_123".to_string()),
            nonce: Some("test_nonce_456".to_string()),
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        
        // Verify redirect URL contains expected parameters
        assert!(redirect_url.contains("code="));
        assert!(redirect_url.contains("state=test_state_123"));
        
        Ok(())
    }

    /// Test OIDC token exchange
    async fn test_oidc_token_exchange(&mut self) -> Result<(), FortressError> {
        // First, get authorization code
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: None,
            nonce: Some("test_nonce".to_string()),
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        
        // Extract code from redirect URL
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        // Exchange code for token
        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        // Verify token response
        assert!(!token_response.access_token.is_empty());
        assert_eq!(token_response.token_type, "Bearer");
        assert!(token_response.expires_in > 0);
        assert!(token_response.refresh_token.is_some());
        assert!(token_response.id_token.is_some());
        
        Ok(())
    }

    /// Test OIDC refresh token flow
    async fn test_oidc_refresh_token(&mut self) -> Result<(), FortressError> {
        // Get initial token
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        let refresh_token = token_response.refresh_token.as_ref().unwrap();

        // Use refresh token to get new access token
        let refresh_request = OidcTokenRequest {
            grant_type: "refresh_token".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(refresh_token.clone()),
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let new_token_response = self.oidc_provider.token(refresh_request).await?;
        
        // Verify new token
        assert!(!new_token_response.access_token.is_empty());
        assert_eq!(new_token_response.token_type, "Bearer");
        assert!(new_token_response.expires_in > 0);
        // Refresh token flow typically doesn't return a new refresh token
        
        Ok(())
    }

    /// Test OIDC user info endpoint
    async fn test_oidc_user_info(&mut self) -> Result<(), FortressError> {
        // Get access token
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        // Get user info
        let user_info = self.oidc_provider.user_info(&token_response.access_token).await?;
        
        // Verify user info
        assert!(!user_info.sub.is_empty());
        assert!(user_info.name.is_some());
        assert!(user_info.email.is_some());
        assert_eq!(user_info.email_verified, Some(true));
        assert!(user_info.preferred_username.is_some());
        assert!(user_info.groups.is_some());
        
        Ok(())
    }

    /// Test OIDC client credentials grant
    async fn test_oidc_client_credentials(&mut self) -> Result<(), FortressError> {
        let token_request = OidcTokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: Some("client_credentials".to_string()),
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        // Verify client credentials response
        assert!(!token_response.access_token.is_empty());
        assert_eq!(token_response.token_type, "Bearer");
        assert!(token_response.expires_in > 0);
        assert!(token_response.refresh_token.is_none()); // Client credentials don't get refresh tokens
        assert!(token_response.id_token.is_none()); // Client credentials don't get ID tokens
        
        Ok(())
    }

    /// Test OIDC JWKS endpoint
    fn test_oidc_jwks_endpoint(&self) -> Result<(), FortressError> {
        let jwks = self.oidc_provider.jwks();
        
        // Verify JWKS structure
        assert!(!jwks.keys.is_empty());
        
        for key in &jwks.keys {
            assert!(!key.kid.is_empty());
            assert!(!key.kty.is_empty());
            assert!(key.use_.is_some());
            assert!(key.alg.is_some());
        }
        
        Ok(())
    }

    /// Test OIDC PKCE support
    async fn test_oidc_pkce_support(&mut self) -> Result<(), FortressError> {
        use base64::{Engine as _, engine::URL_SAFE_NO_PAD};
        use sha2::{Sha256, Digest};

        // Generate PKCE code verifier and challenge
        let code_verifier = "test_code_verifier_123456789";
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile".to_string(),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: Some(code_challenge.clone()),
            code_challenge_method: Some("S256".to_string()),
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        
        // Extract code from redirect URL
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        // Exchange code with PKCE verifier
        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            code_verifier: Some(code_verifier.to_string()),
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        // Verify PKCE flow worked
        assert!(!token_response.access_token.is_empty());
        assert_eq!(token_response.token_type, "Bearer");
        assert!(token_response.expires_in > 0);
        
        Ok(())
    }

    /// Test OIDC Rego policy evaluation
    async fn test_oidc_rego_policies(&mut self) -> Result<(), FortressError> {
        // This test verifies that Rego policies are properly evaluated
        // In a real implementation, you would load actual Rego policies
        
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile read".to_string(),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        // This should succeed with default policies
        let result = self.oidc_provider.authorize(auth_request).await;
        assert!(result.is_ok());
        
        Ok(())
    }

    /// Test FPE credit card encryption
    fn test_fpe_credit_card_encryption(&self) -> Result<(), FortressError> {
        let card_number = "4532 1234 5678 9012";
        
        // Encrypt
        let encrypted = self.fpe_credit_card.encrypt(card_number)?;
        
        // Verify format preservation
        assert_eq!(encrypted.encrypted_value.len(), card_number.len());
        assert!(encrypted.format_preserved);
        assert_eq!(encrypted.metadata.format, DataFormat::CreditCard);
        
        // Decrypt
        let decrypted = self.fpe_credit_card.decrypt(&encrypted.encrypted_value)?;
        
        // Verify round-trip
        assert_eq!(decrypted, card_number);
        
        Ok(())
    }

    /// Test FPE SSN encryption
    fn test_fpe_ssn_encryption(&self) -> Result<(), FortressError> {
        let ssn = "123-45-6789";
        
        // Encrypt
        let encrypted = self.fpe_ssn.encrypt(ssn)?;
        
        // Verify format preservation
        assert_eq!(encrypted.encrypted_value.len(), ssn.len());
        assert!(encrypted.format_preserved);
        assert_eq!(encrypted.metadata.format, DataFormat::SocialSecurityNumber);
        
        // Decrypt
        let decrypted = self.fpe_ssn.decrypt(&encrypted.encrypted_value)?;
        
        // Verify round-trip
        assert_eq!(decrypted, ssn);
        
        Ok(())
    }

    /// Test FPE phone encryption
    fn test_fpe_phone_encryption(&self) -> Result<(), FortressError> {
        let phone = "+12345678901";
        
        // Encrypt
        let encrypted = self.fpe_phone.encrypt(phone)?;
        
        // Verify format preservation
        assert_eq!(encrypted.encrypted_value.len(), phone.len());
        assert!(encrypted.format_preserved);
        assert_eq!(encrypted.metadata.format, DataFormat::PhoneNumber);
        
        // Decrypt
        let decrypted = self.fpe_phone.decrypt(&encrypted.encrypted_value)?;
        
        // Verify round-trip
        assert_eq!(decrypted, phone);
        
        Ok(())
    }

    /// Test FPE email encryption
    fn test_fpe_email_encryption(&self) -> Result<(), FortressError> {
        let email = "user@example.com";
        
        // Encrypt
        let encrypted = self.fpe_email.encrypt(email)?;
        
        // Verify format preservation
        assert!(encrypted.format_preserved);
        assert_eq!(encrypted.metadata.format, DataFormat::EmailAddress);
        assert!(encrypted.encrypted_value.contains('@'));
        assert!(encrypted.encrypted_value.ends_with("example.com"));
        
        // Decrypt
        let decrypted = self.fpe_email.decrypt(&encrypted.encrypted_value)?;
        
        // Verify round-trip
        assert_eq!(decrypted, email);
        
        Ok(())
    }

    /// Test FPE round-trip for multiple formats
    fn test_fpe_round_trip(&self) -> Result<(), FortressError> {
        let test_cases = vec![
            ("4532123456789012", &self.fpe_credit_card),
            ("123456789", &self.fpe_ssn),
            ("+12345678901", &self.fpe_phone),
            ("user@example.com", &self.fpe_email),
        ];

        for (original, fpe) in test_cases {
            let encrypted = fpe.encrypt(original)?;
            let decrypted = fpe.decrypt(&encrypted.encrypted_value)?;
            assert_eq!(decrypted, original, "Round-trip failed for: {}", original);
        }

        Ok(())
    }

    /// Test FPE format preservation
    fn test_fpe_format_preservation(&self) -> Result<(), FortressError> {
        // Test credit card format preservation
        let card_with_spaces = "4532 1234 5678 9012";
        let card_with_hyphens = "4532-1234-5678-9012";
        
        let encrypted_spaces = self.fpe_credit_card.encrypt(card_with_spaces)?;
        assert!(encrypted.encrypted_value.contains(' '));
        
        let encrypted_hyphens = self.fpe_credit_card.encrypt(card_with_hyphens)?;
        assert!(encrypted_hyphens.encrypted_value.contains('-'));
        
        // Test SSN format preservation
        let ssn = "123-45-6789";
        let encrypted_ssn = self.fpe_ssn.encrypt(ssn)?;
        assert_eq!(encrypted_ssn.encrypted_value.chars().filter(|&c| c == '-').count(), 2);
        
        Ok(())
    }

    /// Test FPE Luhn validation
    fn test_fpe_luhn_validation(&self) -> Result<(), FortressError> {
        // Valid credit cards (pass Luhn)
        let valid_cards = vec![
            "4532015112830366",
            "6011111111111117",
            "371449635398431",
        ];

        // Invalid credit cards (fail Luhn)
        let invalid_cards = vec![
            "4532015112830367",
            "6011111111111118",
            "371449635398432",
        ];

        for card in valid_cards {
            let result = self.fpe_credit_card.encrypt(card);
            assert!(result.is_ok(), "Valid card should encrypt successfully: {}", card);
        }

        for card in invalid_cards {
            let result = self.fpe_credit_card.encrypt(card);
            assert!(result.is_err(), "Invalid card should fail encryption: {}", card);
        }

        Ok(())
    }

    /// Test OIDC + FPE integration
    async fn test_oidc_fpe_integration(&mut self) -> Result<(), FortressError> {
        // Get OIDC token
        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: "test_client".to_string(),
            redirect_uri: "https://client.example.com/callback".to_string(),
            scope: "openid profile email".to_string(),
            state: None,
            nonce: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some("https://client.example.com/callback".to_string()),
            code_verifier: None,
            refresh_token: None,
            client_id: "test_client".to_string(),
            client_secret: Some("test_secret".to_string()),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        // Get user info with sensitive data
        let user_info = self.oidc_provider.user_info(&token_response.access_token).await?;
        
        // Encrypt sensitive user data using FPE
        let test_ssn = "123-45-6789";
        let encrypted_ssn = self.fpe_ssn.encrypt(test_ssn)?;
        
        // Simulate storing encrypted data with user context
        let encrypted_data = json!({
            "user_id": user_info.sub,
            "encrypted_ssn": encrypted_ssn.encrypted_value,
            "encryption_metadata": encrypted_ssn.metadata,
            "access_token": token_response.access_token,
        });
        
        // Verify integration works
        assert!(!encrypted_data["user_id"].as_str().unwrap().is_empty());
        assert!(!encrypted_data["encrypted_ssn"].as_str().unwrap().is_empty());
        assert!(encrypted_data["encryption_metadata"].is_object());
        
        Ok(())
    }

    /// Test performance benchmarks
    async fn test_performance_benchmarks(&mut self) -> Result<(), FortressError> {
        let start_time = SystemTime::now();

        // Benchmark OIDC operations
        let oidc_start = SystemTime::now();
        
        for _ in 0..100 {
            let auth_request = OidcAuthRequest {
                response_type: "code".to_string(),
                client_id: "test_client".to_string(),
                redirect_uri: "https://client.example.com/callback".to_string(),
                scope: "openid profile".to_string(),
                state: None,
                nonce: None,
                response_mode: None,
                code_challenge: None,
                code_challenge_method: None,
                additional_params: HashMap::new(),
            };

            let _ = self.oidc_provider.authorize(auth_request).await;
        }
        
        let oidc_duration = oidc_start.elapsed().unwrap_or_default();
        
        // Benchmark FPE operations
        let fpe_start = SystemTime::now();
        
        let test_card = "4532123456789012";
        for _ in 0..1000 {
            let encrypted = self.fpe_credit_card.encrypt(test_card)?;
            let _ = self.fpe_credit_card.decrypt(&encrypted.encrypted_value)?;
        }
        
        let fpe_duration = fpe_start.elapsed().unwrap_or_default();
        
        let total_duration = start_time.elapsed().unwrap_or_default();
        
        // Performance assertions (these are example thresholds)
        assert!(oidc_duration.as_millis() < 5000, "OIDC operations should complete within 5 seconds");
        assert!(fpe_duration.as_millis() < 1000, "FPE operations should complete within 1 second");
        assert!(total_duration.as_millis() < 6000, "Total benchmark should complete within 6 seconds");
        
        println!("Performance Results:");
        println!("  OIDC Operations (100): {}ms", oidc_duration.as_millis());
        println!("  FPE Operations (1000): {}ms", fpe_duration.as_millis());
        println!("  Total Time: {}ms", total_duration.as_millis());
        
        Ok(())
    }
}

/// Test results container
#[derive(Debug, Clone)]
pub struct TestResults {
    results: Vec<TestResult>,
}

impl TestResults {
    /// Create new test results
    pub fn new() -> Self {
        Self {
            results: Vec::new(),
        }
    }

    /// Add a test result
    pub fn add_result(&mut self, test_name: &str, result: Result<(), FortressError>) {
        let status = match result {
            Ok(()) => TestStatus::Passed,
            Err(_) => TestStatus::Failed,
        };

        self.results.push(TestResult {
            name: test_name.to_string(),
            status,
            error: result.err(),
        });
    }

    /// Print all results
    pub fn print_results(&self) {
        println!("\n=== OIDC + FPE Integration Test Results ===\n");
        
        let mut passed = 0;
        let mut failed = 0;

        for result in &self.results {
            match result.status {
                TestStatus::Passed => {
                    println!("✓ {}: PASSED", result.name);
                    passed += 1;
                }
                TestStatus::Failed => {
                    println!("✗ {}: FAILED", result.name);
                    if let Some(error) = &result.error {
                        println!("   Error: {}", error);
                    }
                    failed += 1;
                }
            }
        }

        println!("\n=== Summary ===");
        println!("Total Tests: {}", self.results.len());
        println!("Passed: {}", passed);
        println!("Failed: {}", failed);
        println!("Success Rate: {:.1}%", (passed as f64 / self.results.len() as f64) * 100.0);

        if failed == 0 {
            println!("\nAll tests passed! OIDC and FPE functionality is working correctly.");
        } else {
            println!("\nSome tests failed. Please review the errors above.");
        }
    }

    /// Get success rate
    pub fn success_rate(&self) -> f64 {
        if self.results.is_empty() {
            return 0.0;
        }

        let passed = self.results.iter().filter(|r| matches!(r.status, TestStatus::Passed)).count();
        (passed as f64 / self.results.len() as f64) * 100.0
    }
}

/// Individual test result
#[derive(Debug, Clone)]
pub struct TestResult {
    name: String,
    status: TestStatus,
    error: Option<FortressError>,
}

/// Test status
#[derive(Debug, Clone, PartialEq)]
pub enum TestStatus {
    Passed,
    Failed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integration_suite() {
        let mut test_suite = OidcFpeIntegrationTests::new().unwrap();
        let results = test_suite.run_all_tests().await.unwrap();
        
        results.print_results();
        assert_eq!(results.success_rate(), 100.0);
    }

    #[tokio::test]
    async fn test_individual_components() {
        let test_suite = OidcFpeIntegrationTests::new().unwrap();
        
        // Test individual components
        assert!(test_suite.test_oidc_authorization_flow().await.is_ok());
        assert!(test_suite.test_fpe_credit_card_encryption().is_ok());
        assert!(test_suite.test_oidc_fpe_integration().await.is_ok());
    }
}
