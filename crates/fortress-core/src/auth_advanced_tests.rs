//! Advanced Authentication Tests
//! 
//! This module contains comprehensive tests for the advanced authentication features
//! including MFA, risk assessment, device fingerprinting, and account lockout.

use crate::auth::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_advanced_authentication_with_mfa() {
        let mut auth = AuthManager::new();
        
        // Create a test user
        let _user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await
            .expect("Failed to create test user");

        // Test authentication with TOTP
        let login_request = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: None,
            ip_address: Some("192.168.1.100".to_string()),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
            mfa_data: Some(MfaData {
                totp_code: Some("123456".to_string()),
                hardware_token: None,
                backup_code: None,
                biometric_data: None,
                push_token: None,
                verification_code: None,
            }),
            risk_context: Some(RiskContext {
                ip_address: Some("192.168.1.100".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                timestamp: Some(1640995200), // 2022-01-01 00:00:00 UTC
                geolocation: Some(GeolocationData {
                    country: Some("US".to_string()),
                    region: Some("California".to_string()),
                    city: Some("San Francisco".to_string()),
                    latitude: Some(37.7749),
                    longitude: Some(-122.4194),
                    isp: Some("Example ISP".to_string()),
                    vpn: Some(false),
                }),
                network_info: Some(NetworkInfo {
                    connection_type: Some("broadband".to_string()),
                    isp: Some("Example ISP".to_string()),
                    organization: Some("Example Org".to_string()),
                    asn: Some(12345),
                    tor: Some(false),
                }),
                device_info: Some(DeviceInfo {
                    device_type: Some("desktop".to_string()),
                    os: Some("Windows".to_string()),
                    browser: Some("Chrome".to_string()),
                    screen_resolution: Some("1920x1080".to_string()),
                    timezone: Some("America/Los_Angeles".to_string()),
                    language: Some("en-US".to_string()),
                    hardware_concurrency: Some(8),
                    device_memory: Some(16777216000), // 16GB
                    canvas_fingerprint: Some("abc123".to_string()),
                    webgl_fingerprint: Some("def456".to_string()),
                }),
            }),
        };

        let result = auth.authenticate(login_request).await;
        assert!(result.is_ok(), "Authentication with MFA should succeed");
        
        let response = result.unwrap();
        assert!(!response.token.is_empty());
        assert!(response.mfa_requirements.is_some());
        assert!(response.risk_assessment.is_some());
        assert!(response.device_trust.is_some());
    }

    #[tokio::test]
    async fn test_risk_assessment_engine() {
        let config = RiskAuthConfig {
            enabled: true,
            risk_scoring: RiskScoringConfig {
                ip_risk: IpRiskConfig {
                    malicious_networks: vec!["192.168.1.0/24".to_string()],
                    trusted_networks: vec!["10.0.0.0/8".to_string()],
                    detect_proxies: true,
                    geolocation_restrictions: GeolocationRestrictions {
                        enabled: false,
                        allowed_countries: vec![],
                        blocked_countries: vec!["CN".to_string()], // Block China
                        require_vpn_countries: vec![],
                    },
                },
                device_risk: DeviceRiskConfig {
                    compromised_devices: vec![],
                    trusted_devices: vec![],
                    trust_period_seconds: 2592000, // 30 days
                    require_verification_new: true,
                },
                behavioral_risk: BehavioralRiskConfig {
                    typing_patterns: false,
                    mouse_movement: false,
                    login_time_patterns: false,
                    unusual_patterns: false,
                },
                time_risk: TimeRiskConfig {
                    business_hours: BusinessHoursConfig {
                        enabled: false,
                        start_time: "09:00".to_string(),
                        end_time: "17:00".to_string(),
                        timezone: "UTC".to_string(),
                        days_of_week: vec![1, 2, 3, 4, 5], // Mon-Fri
                        require_mfa_outside_hours: false,
                    },
                    unusual_time_detection: true,
                    timezone_restrictions: vec![],
                },
            },
            thresholds: RiskThresholds {
                low_threshold: 25,
                medium_threshold: 50,
                high_threshold: 75,
                critical_threshold: 90,
            },
            adaptive_auth: true,
        };

        let risk_engine = RiskAssessmentEngine::new(config);

        // Test low risk scenario
        let low_risk_context = RiskContext {
            ip_address: Some("10.0.0.50".to_string()), // Trusted IP
            user_agent: Some("Mozilla/5.0".to_string()),
            timestamp: Some(1640995200 + 3600), // Business hours
            geolocation: Some(GeolocationData {
                country: Some("US".to_string()),
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                isp: None,
                vpn: Some(false),
            }),
            network_info: None,
            device_info: None,
        };

        let assessment = risk_engine.assess_risk(&low_risk_context);
        assert!(assessment.risk_score < 25);
        assert!(matches!(assessment.risk_level, RiskLevel::Low));

        // Test high risk scenario
        let high_risk_context = RiskContext {
            ip_address: Some("192.168.1.100".to_string()), // Suspicious IP
            user_agent: Some("Mozilla/5.0".to_string()),
            timestamp: Some(1640995200 + 7200), // Unusual time (2 AM)
            geolocation: Some(GeolocationData {
                country: Some("CN".to_string()), // Blocked country
                region: None,
                city: None,
                latitude: None,
                longitude: None,
                isp: None,
                vpn: Some(true),
            }),
            network_info: None,
            device_info: None,
        };

        let assessment = risk_engine.assess_risk(&high_risk_context);
        assert!(assessment.risk_score >= 75);
        assert!(matches!(assessment.risk_level, RiskLevel::High));
    }

    #[tokio::test]
    async fn test_device_fingerprinting() {
        let config = DeviceFingerprintConfig {
            enabled: true,
            methods: vec![
                FingerprintMethod::UserAgent,
                FingerprintMethod::ScreenResolution,
                FingerprintMethod::Timezone,
                FingerprintMethod::Language,
                FingerprintMethod::Platform,
            ],
            storage: FingerprintStorageConfig {
                backend: FingerprintStorageBackend::Memory,
                encrypt_fingerprints: true,
                retention_seconds: 7776000, // 90 days
            },
            trust_duration_seconds: 2592000, // 30 days
        };

        let device_manager = DeviceFingerprintManager::new(config);

        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
        let ip = "192.168.1.100";
        let user_id = "test_user";

        // Generate fingerprint
        let fingerprint = device_manager.generate_fingerprint(user_agent, ip).unwrap();
        assert!(!fingerprint.is_empty());

        // Assess trust for new device
        let trust_status = device_manager.assess_trust(&fingerprint, user_id).unwrap();
        assert!(!trust_status.trusted);
        assert_eq!(trust_status.trust_score, 0);
        assert!(trust_status.first_seen.is_some());
        assert!(trust_status.trust_reasons.contains(&"New device".to_string()));
    }

    #[tokio::test]
    async fn test_account_lockout() {
        let config = AccountLockoutConfig {
            enabled: true,
            max_attempts: 3,
            lockout_duration_seconds: 900, // 15 minutes
            progressive_lockout: true,
            reset_on_success: true,
            permanent_lockout_threshold: Some(10),
        };

        let mut lockout_manager = AccountLockoutManager::new(config);
        let username = "testuser";

        // Record failed attempts
        for _i in 1..=3 {
            lockout_manager.record_failed_attempt(username).unwrap();
        }

        // Check if account is locked
        assert!(lockout_manager.is_account_locked(username).unwrap());

        // Check remaining lockout time
        let remaining = lockout_manager.get_lockout_remaining(username).unwrap();
        assert!(remaining.is_some());
        assert!(remaining.unwrap() > 0);

        // Test successful login resets lockout
        lockout_manager.reset_failed_attempt(username).unwrap();
        assert!(!lockout_manager.is_account_locked(username).unwrap());
    }

    #[tokio::test]
    async fn test_totp_config() {
        let config = TotpConfig {
            enabled: true,
            issuer: "Fortress".to_string(),
            window: 1,
            require_for_new_devices: true,
            secret_length: 32,
        };

        assert!(config.enabled);
        assert_eq!(config.issuer, "Fortress");
        assert_eq!(config.window, 1);
        assert!(config.require_for_new_devices);
        assert_eq!(config.secret_length, 32);
    }

    #[tokio::test]
    async fn test_hardware_token_config() {
        let config = HardwareTokenConfig {
            enabled: true,
            supported_types: vec![
                HardwareTokenType::YubiKey,
                HardwareTokenType::RSASecurId,
                HardwareTokenType::GoogleTitan,
                HardwareTokenType::Fido2,
            ],
            require_for_admin: true,
        };

        assert!(config.enabled);
        assert_eq!(config.supported_types.len(), 4);
        assert!(config.require_for_admin);
    }

    #[tokio::test]
    async fn test_backup_codes_config() {
        let config = BackupCodesConfig {
            enabled: true,
            code_count: 10,
            code_length: 8,
            valid_for_seconds: 604800, // 7 days
        };

        assert!(config.enabled);
        assert_eq!(config.code_count, 10);
        assert_eq!(config.code_length, 8);
        assert_eq!(config.valid_for_seconds, 604800);
    }

    #[tokio::test]
    async fn test_risk_based_mfa_methods() {
        let config = RiskBasedMfaMethods {
            low_risk: vec![MfaMethod::Password],
            medium_risk: vec![MfaMethod::Password, MfaMethod::Totp],
            high_risk: vec![MfaMethod::Password, MfaMethod::Totp, MfaMethod::HardwareToken],
            critical_risk: vec![
                MfaMethod::Password, 
                MfaMethod::Totp, 
                MfaMethod::HardwareToken, 
                MfaMethod::Biometric
            ],
        };

        // Test low risk requirements
        let low_methods = config.get_required_methods(RiskLevel::Low);
        assert_eq!(low_methods.len(), 1);
        assert!(low_methods.contains(&MfaMethod::Password));

        // Test medium risk requirements
        let medium_methods = config.get_required_methods(RiskLevel::Medium);
        assert_eq!(medium_methods.len(), 2);
        assert!(medium_methods.contains(&MfaMethod::Password));
        assert!(medium_methods.contains(&MfaMethod::Totp));

        // Test critical risk requirements
        let critical_methods = config.get_required_methods(RiskLevel::Critical);
        assert_eq!(critical_methods.len(), 4);
        assert!(critical_methods.contains(&MfaMethod::Biometric));
    }

    #[tokio::test]
    async fn test_authentication_with_high_risk() {
        let mut auth = AuthManager::new();
        
        // Create a test user
        let _user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await
            .expect("Failed to create test user");

        // Test authentication from high-risk location (China)
        let login_request = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: None,
            ip_address: Some("203.0.113.1".to_string()), // IP from China
            user_agent: Some("Mozilla/5.0".to_string()),
            mfa_data: None, // No MFA provided
            risk_context: Some(RiskContext {
                ip_address: Some("203.0.113.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                timestamp: Some(1640995200),
                geolocation: Some(GeolocationData {
                    country: Some("CN".to_string()), // China is blocked
                    region: Some("Beijing".to_string()),
                    city: Some("Beijing".to_string()),
                    latitude: Some(39.9042),
                    longitude: Some(116.4074),
                    isp: Some("China Telecom".to_string()),
                    vpn: Some(false),
                }),
                network_info: Some(NetworkInfo {
                    connection_type: Some("broadband".to_string()),
                    isp: Some("China Telecom".to_string()),
                    organization: Some("China Telecom".to_string()),
                    asn: Some(4808),
                    tor: Some(false),
                }),
                device_info: None,
            }),
        };

        let result = auth.authenticate(login_request).await;
        // Should fail due to high risk and no MFA
        assert!(result.is_err());
        
        let error = result.unwrap_err();
        assert!(error.to_string().contains("Multi-factor authentication required"));
    }

    #[tokio::test]
    async fn test_authentication_with_mfa_success() {
        let mut auth = AuthManager::new();
        
        // Create a test user
        let _user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await
            .expect("Failed to create test user");

        // Test authentication with proper MFA for high risk
        let login_request = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: None,
            ip_address: Some("203.0.113.1".to_string()), // IP from China
            user_agent: Some("Mozilla/5.0".to_string()),
            mfa_data: Some(MfaData {
                totp_code: Some("123456".to_string()), // Valid TOTP
                hardware_token: None,
                backup_code: None,
                biometric_data: None,
                push_token: None,
                verification_code: None,
            }),
            risk_context: Some(RiskContext {
                ip_address: Some("203.0.113.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                timestamp: Some(1640995200),
                geolocation: Some(GeolocationData {
                    country: Some("CN".to_string()),
                    region: Some("Beijing".to_string()),
                    city: Some("Beijing".to_string()),
                    latitude: Some(39.9042),
                    longitude: Some(116.4074),
                    isp: Some("China Telecom".to_string()),
                    vpn: Some(false),
                }),
                network_info: Some(NetworkInfo {
                    connection_type: Some("broadband".to_string()),
                    isp: Some("China Telecom".to_string()),
                    organization: Some("China Telecom".to_string()),
                    asn: Some(4808),
                    tor: Some(false),
                }),
                device_info: None,
            }),
        };

        let result = auth.authenticate(login_request).await;
        // Should succeed with MFA
        assert!(result.is_ok());
        
        let response = result.unwrap();
        assert!(!response.token.is_empty());
        assert!(response.mfa_requirements.is_some());
        assert!(response.risk_assessment.is_some());
        
        // Check risk assessment
        let risk = response.risk_assessment.unwrap();
        assert!(risk.risk_score >= 75); // High risk due to geolocation
        assert!(matches!(risk.risk_level, RiskLevel::High));
        
        // Check security measures
        assert!(!response.security_measures.is_empty());
    }

    #[tokio::test]
    async fn test_device_trust_escalation() {
        let mut auth = AuthManager::new();
        
        // Create a test user
        let _user_id = auth.create_user("testuser".to_string(), "Password123!".to_string()).await
            .expect("Failed to create test user");

        let fingerprint = "test_device_fingerprint_12345";

        // First login - new device, low trust
        let login_request1 = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: Some(fingerprint.to_string()),
            ip_address: Some("10.0.0.50".to_string()), // Trusted IP
            user_agent: Some("Mozilla/5.0".to_string()),
            mfa_data: None,
            risk_context: Some(RiskContext {
                ip_address: Some("10.0.0.50".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                timestamp: Some(1640995200),
                geolocation: None,
                network_info: None,
                device_info: None,
            }),
        };

        let result1 = auth.authenticate(login_request1).await;
        assert!(result1.is_ok());
        
        let response1 = result1.unwrap();
        let trust1 = response1.device_trust.unwrap();
        assert!(!trust1.trusted); // New device not trusted initially
        assert_eq!(trust1.trust_score, 0);

        // Simulate multiple successful logins over time to build trust
        for i in 1..=35 { // Simulate 35 days of logins
            let mut auth_mut = AuthManager::new();
            auth_mut.create_user("testuser".to_string(), "Password123!".to_string()).await.unwrap();
            
            let login_request = LoginRequest {
                username: "testuser".to_string(),
                password: "Password123!".to_string(),
                device_fingerprint: Some(fingerprint.to_string()),
                ip_address: Some("10.0.0.50".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                mfa_data: None,
                risk_context: Some(RiskContext {
                    ip_address: Some("10.0.0.50".to_string()),
                    user_agent: Some("Mozilla/5.0".to_string()),
                    timestamp: Some(1640995200 + (i * 86400)), // i days later
                    geolocation: None,
                    network_info: None,
                    device_info: None,
                }),
            };

            let _ = auth_mut.authenticate(login_request).await;
        }

        // After 30+ days, device should be trusted
        let mut auth_final = AuthManager::new();
        auth_final.create_user("testuser".to_string(), "Password123!".to_string()).await.unwrap();
        
        let login_request_final = LoginRequest {
            username: "testuser".to_string(),
            password: "Password123!".to_string(),
            device_fingerprint: Some(fingerprint.to_string()),
            ip_address: Some("10.0.0.50".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
            mfa_data: None,
            risk_context: Some(RiskContext {
                ip_address: Some("10.0.0.50".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                timestamp: Some(1640995200 + (35 * 86400)),
                geolocation: None,
                network_info: None,
                device_info: None,
            }),
        };

        let result_final = auth_final.authenticate(login_request_final).await;
        assert!(result_final.is_ok());
        
        let response_final = result_final.unwrap();
        let trust_final = response_final.device_trust.unwrap();
        assert!(trust_final.trusted); // Should be trusted after 30+ days
        assert!(trust_final.trust_score >= 30); // Trust score should be at least 30
        assert!(trust_final.trust_reasons.contains(&"Established trust".to_string()));
    }
}
