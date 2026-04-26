//! OIDC Provider and FPE Integration Example
//!
//! This example demonstrates how to use Fortress's OIDC Provider
//! and Format-Preserving Encryption together in a realistic application scenario.

use fortress_core::prelude::*;
use fortress_core::oidc_provider::*;
use fortress_core::format_preserving_encryption::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::time::{sleep, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UserProfile {
    id: String,
    username: String,
    email: String,
    full_name: String,
    encrypted_ssn: Option<String>,
    encrypted_credit_card: Option<String>,
    ssn_metadata: Option<FpeMetadata>,
    credit_card_metadata: Option<FpeMetadata>,
    roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ServiceConfig {
    name: String,
    client_id: String,
    client_secret: Option<String>,
    required_scopes: Vec<String>,
    encryption_key: Vec<u8>,
}

/// Example application demonstrating OIDC + FPE integration
pub struct SecureUserService {
    oidc_provider: OidcProvider,
    fpe_ssn: FormatPreservingEncryption,
    fpe_credit_card: FormatPreservingEncryption,
    services: HashMap<String, ServiceConfig>,
    user_profiles: HashMap<String, UserProfile>,
}

impl SecureUserService {
    /// Create a new secure user service
    pub fn new() -> Result<Self, FortressError> {
        // Initialize OIDC provider
        let mut oidc_config = OidcConfig::default();
        
        // Add service clients
        let services = vec![
            ServiceConfig {
                name: "Web Portal".to_string(),
                client_id: "web-portal".to_string(),
                client_secret: Some("web-secret-123".to_string()),
                required_scopes: vec!["openid".to_string(), "profile".to_string(), "email".to_string(), "read".to_string()],
                encryption_key: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            },
            ServiceConfig {
                name: "Mobile App".to_string(),
                client_id: "mobile-app".to_string(),
                client_secret: None, // Public client
                required_scopes: vec!["openid".to_string(), "profile".to_string(), "read".to_string()],
                encryption_key: vec![16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
            },
            ServiceConfig {
                name: "API Service".to_string(),
                client_id: "api-service".to_string(),
                client_secret: Some("api-secret-456".to_string()),
                required_scopes: vec!["openid".to_string(), "profile".to_string(), "write".to_string()],
                encryption_key: vec![8, 6, 4, 2, 1, 3, 5, 7, 9, 10, 12, 14, 16, 15, 13, 11],
            },
        ];

        for service in &services {
            let client = OidcClient {
                client_id: service.client_id.clone(),
                client_secret: service.client_secret.clone(),
                name: service.name.clone(),
                redirect_uris: vec![format!("https://{}.example.com/callback", service.client_id)],
                grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
                response_types: vec!["code".to_string()],
                scopes: service.required_scopes.clone(),
                public: service.client_secret.is_none(),
                metadata: HashMap::new(),
            };
            
            oidc_config.clients.insert(service.client_id.clone(), client);
        }

        // Enable Rego policies
        oidc_config.rego_policies = Some(RegoConfig {
            policy_dir: "examples/policies".to_string(),
            data_dir: Some("examples/data".to_string()),
            enable_cache: true,
            cache_ttl: 300,
        });

        let auth_manager = AuthManager::new();
        let oidc_provider = OidcProvider::new(oidc_config, auth_manager)?;

        // Initialize FPE instances
        let fpe_ssn = FormatPreservingEncryption::new(
            FormatPreservingEncryption::ssn_config(services[0].encryption_key.clone())
        )?;
        
        let fpe_credit_card = FormatPreservingEncryption::new(
            FormatPreservingEncryption::credit_card_config(services[0].encryption_key.clone())
        )?;

        // Create service map
        let mut service_map = HashMap::new();
        for service in services {
            service_map.insert(service.client_id.clone(), service);
        }

        Ok(Self {
            oidc_provider,
            fpe_ssn,
            fpe_credit_card,
            services: service_map,
            user_profiles: HashMap::new(),
        })
    }

    /// Simulate user authentication with OIDC
    pub async fn authenticate_user(&mut self, client_id: &str, username: &str, password: &str) -> Result<String, FortressError> {
        println!("Authenticating user '{}' for client '{}'", username, client_id);

        // In a real implementation, you would validate credentials against a user database
        if username != "testuser" || password != "Password123!" {
            return Err(FortressError::authentication("Invalid credentials", None));
        }

        // Create user in auth manager
        let user_id = self.oidc_provider.auth_manager().create_user(
            username.to_string(),
            password.to_string(),
        ).await?;

        // Assign user role
        let role_id = self.oidc_provider.auth_manager().create_role(
            "user".to_string(),
            "Standard user role".to_string(),
            vec!["read".to_string(), "profile".to_string()],
        )?;
        
        self.oidc_provider.auth_manager().assign_role(&user_id, role_id)?;

        // Create authorization request
        let service = self.services.get(client_id)
            .ok_or_else(|| FortressError::validation("Unknown client", None, None))?;

        let auth_request = OidcAuthRequest {
            response_type: "code".to_string(),
            client_id: client_id.to_string(),
            redirect_uri: format!("https://{}.example.com/callback", client_id),
            scope: service.required_scopes.join(" "),
            state: Some(format!("state_{}", uuid::Uuid::new_v4())),
            nonce: Some(format!("nonce_{}", uuid::Uuid::new_v4())),
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            additional_params: HashMap::new(),
        };

        let redirect_url = self.oidc_provider.authorize(auth_request).await?;
        println!("📎 Authorization redirect URL: {}", redirect_url);

        // Extract authorization code (in real implementation, this would be done by the client)
        let code_start = redirect_url.find("code=").unwrap() + 5;
        let code_end = redirect_url.find('&').unwrap_or(redirect_url.len());
        let auth_code = &redirect_url[code_start..code_end];

        // Exchange code for tokens
        let token_request = OidcTokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(auth_code.to_string()),
            redirect_uri: Some(format!("https://{}.example.com/callback", client_id)),
            code_verifier: None,
            refresh_token: None,
            client_id: client_id.to_string(),
            client_secret: service.client_secret.clone(),
            scope: None,
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        println!("🎫 Access token obtained successfully");

        Ok(token_response.access_token)
    }

    /// Create or update user profile with encrypted sensitive data
    pub async fn create_user_profile(&mut self, access_token: &str, user_data: UserProfileData) -> Result<UserProfile, FortressError> {
        println!("👤 Creating user profile for '{}'", user_data.username);

        // Validate access token and get user info
        let user_info = self.oidc_provider.user_info(access_token).await?;
        
        // Encrypt sensitive data
        let (encrypted_ssn, ssn_metadata) = if let Some(ssn) = &user_data.ssn {
            let encrypted = self.fpe_ssn.encrypt(ssn)?;
            (Some(encrypted.encrypted_value), Some(encrypted.metadata))
        } else {
            (None, None)
        };

        let (encrypted_credit_card, credit_card_metadata) = if let Some(credit_card) = &user_data.credit_card {
            let encrypted = self.fpe_credit_card.encrypt(credit_card)?;
            (Some(encrypted.encrypted_value), Some(encrypted.metadata))
        } else {
            (None, None)
        };

        // Create user profile
        let profile = UserProfile {
            id: user_info.sub.clone(),
            username: user_data.username.clone(),
            email: user_info.email.clone().unwrap_or_default(),
            full_name: user_info.name.clone().unwrap_or_default(),
            encrypted_ssn,
            encrypted_credit_card,
            ssn_metadata,
            credit_card_metadata,
            roles: user_info.groups.clone().unwrap_or_default(),
        };

        // Store profile
        self.user_profiles.insert(user_info.sub.clone(), profile.clone());
        
        println!("✓ User profile created successfully");
        Ok(profile)
    }

    /// Get user profile with decrypted sensitive data
    pub async fn get_user_profile(&self, access_token: &str, user_id: &str) -> Result<UserProfileData, FortressError> {
        println!("Retrieving user profile for '{}'", user_id);

        // Validate access token
        let _user_info = self.oidc_provider.user_info(access_token).await?;

        // Get user profile
        let profile = self.user_profiles.get(user_id)
            .ok_or_else(|| FortressError::validation("User profile not found", None, None))?;

        // Decrypt sensitive data
        let decrypted_ssn = if let (Some(encrypted_ssn), Some(_metadata)) = (&profile.encrypted_ssn, &profile.ssn_metadata) {
            Some(self.fpe_ssn.decrypt(encrypted_ssn)?)
        } else {
            None
        };

        let decrypted_credit_card = if let (Some(encrypted_cc), Some(_metadata)) = (&profile.encrypted_credit_card, &profile.credit_card_metadata) {
            Some(self.fpe_credit_card.decrypt(encrypted_cc)?)
        } else {
            None
        };

        let user_data = UserProfileData {
            username: profile.username.clone(),
            email: profile.email.clone(),
            full_name: profile.full_name.clone(),
            ssn: decrypted_ssn,
            credit_card: decrypted_credit_card,
            roles: profile.roles.clone(),
        };

        println!("✅ User profile retrieved successfully");
        Ok(user_data)
    }

    /// Demonstrate service-to-service authentication
    pub async fn service_to_service_auth(&mut self, from_service: &str, to_service: &str) -> Result<String, FortressError> {
        println!("🔄 Performing service-to-service authentication: {} -> {}", from_service, to_service);

        let from_config = self.services.get(from_service)
            .ok_or_else(|| FortressError::validation("Unknown source service", None, None))?;

        let to_config = self.services.get(to_service)
            .ok_or_else(|| FortressError::validation("Unknown target service", None, None))?;

        // Use client credentials grant
        let token_request = OidcTokenRequest {
            grant_type: "client_credentials".to_string(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            client_id: from_config.client_id.clone(),
            client_secret: from_config.client_secret.clone(),
            scope: Some("service-to-service".to_string()),
        };

        let token_response = self.oidc_provider.token(token_request).await?;
        
        println!("✅ Service-to-service authentication successful");
        Ok(token_response.access_token)
    }

    /// Batch encrypt sensitive data
    pub fn batch_encrypt_sensitive_data(&self, data: Vec<(String, SensitiveDataType)>) -> Result<Vec<EncryptedData>, FortressError> {
        println!("Batch encrypting {} sensitive data items", data.len());

        let mut results = Vec::new();

        for (value, data_type) in data {
            let encrypted = match data_type {
                SensitiveDataType::SSN => {
                    let encrypted = self.fpe_ssn.encrypt(&value)?;
                    EncryptedData {
                        original_value: value,
                        encrypted_value: encrypted.encrypted_value,
                        data_type,
                        metadata: encrypted.metadata,
                    }
                }
                SensitiveDataType::CreditCard => {
                    let encrypted = self.fpe_credit_card.encrypt(&value)?;
                    EncryptedData {
                        original_value: value,
                        encrypted_value: encrypted.encrypted_value,
                        data_type,
                        metadata: encrypted.metadata,
                    }
                }
                SensitiveDataType::Phone => {
                    let fpe = FormatPreservingEncryption::new(
                        FormatPreservingEncryption::phone_config(self.services.values().next().unwrap().encryption_key.clone())
                    )?;
                    let encrypted = fpe.encrypt(&value)?;
                    EncryptedData {
                        original_value: value,
                        encrypted_value: encrypted.encrypted_value,
                        data_type,
                        metadata: encrypted.metadata,
                    }
                }
            };
            
            results.push(encrypted);
        }

        println!("✓ Batch encryption completed successfully");
        Ok(results)
    }

    /// Demonstrate compliance reporting
    pub fn generate_compliance_report(&self) -> ComplianceReport {
        println!("Generating compliance report");

        let total_profiles = self.user_profiles.len();
        let mut profiles_with_ssn = 0;
        let mut profiles_with_credit_card = 0;

        for profile in self.user_profiles.values() {
            if profile.encrypted_ssn.is_some() {
                profiles_with_ssn += 1;
            }
            if profile.encrypted_credit_card.is_some() {
                profiles_with_credit_card += 1;
            }
        }

        let report = ComplianceReport {
            total_user_profiles: total_profiles,
            encrypted_ssn_count: profiles_with_ssn,
            encrypted_credit_card_count: profiles_with_credit_card,
            ssn_encryption_coverage: if total_profiles > 0 {
                (profiles_with_ssn as f64 / total_profiles as f64) * 100.0
            } else {
                0.0
            },
            credit_card_encryption_coverage: if total_profiles > 0 {
                (profiles_with_credit_card as f64 / total_profiles as f64) * 100.0
            } else {
                0.0
            },
            oidc_clients_configured: self.services.len(),
            rego_policies_enabled: self.oidc_provider.oidc_config().rego_policies.is_some(),
            timestamp: chrono::Utc::now(),
        };

        println!("✓ Compliance report generated");
        report
    }

    /// Run demonstration scenario
    pub async fn run_demo(&mut self) -> Result<(), FortressError> {
        println!("Starting OIDC + FPE Integration Demo\n");

        // Step 1: Authenticate users from different services
        println!("\n=== Step 1: User Authentication ===");
        let web_token = self.authenticate_user("web-portal", "testuser", "Password123!").await?;
        let mobile_token = self.authenticate_user("mobile-app", "testuser", "Password123!").await?;
        
        sleep(Duration::from_millis(100)).await;

        // Step 2: Create user profiles with sensitive data
        println!("\n=== Step 2: Create User Profiles ===");
        let web_profile_data = UserProfileData {
            username: "testuser".to_string(),
            email: "testuser@example.com".to_string(),
            full_name: "Test User".to_string(),
            ssn: Some("123-45-6789".to_string()),
            credit_card: Some("4532 1234 5678 9012".to_string()),
            roles: vec!["user".to_string(), "profile".to_string()],
        };

        let web_profile = self.create_user_profile(&web_token, web_profile_data).await?;
        
        sleep(Duration::from_millis(100)).await;

        // Step 3: Retrieve and decrypt user data
        println!("\n=== Step 3: Retrieve User Profiles ===");
        let retrieved_web_data = self.get_user_profile(&web_token, &web_profile.id).await?;
        
        println!("Retrieved data:");
        println!("  Username: {}", retrieved_web_data.username);
        println!("  Email: {}", retrieved_web_data.email);
        println!("  SSN: {:?}", retrieved_web_data.ssn);
        println!("  Credit Card: {:?}", retrieved_web_data.credit_card);
        
        sleep(Duration::from_millis(100)).await;

        // Step 4: Service-to-service authentication
        println!("\n=== Step 4: Service-to-Service Authentication ===");
        let service_token = self.service_to_service_auth("web-portal", "api-service").await?;
        println!("Service token obtained: {}...", &service_token[..20]);
        
        sleep(Duration::from_millis(100)).await;

        // Step 5: Batch encryption demonstration
        println!("\n=== Step 5: Batch Encryption ===");
        let sensitive_data = vec![
            ("987-65-4321".to_string(), SensitiveDataType::SSN),
            ("5678 9012 3456 7890".to_string(), SensitiveDataType::CreditCard),
            ("+19876543210".to_string(), SensitiveDataType::Phone),
        ];
        
        let encrypted_data = self.batch_encrypt_sensitive_data(sensitive_data)?;
        
        println!("Encrypted data:");
        for data in &encrypted_data {
            println!("  {}: {} -> {}", 
                format!("{:?}", data.data_type), 
                data.original_value, 
                data.encrypted_value
            );
        }
        
        sleep(Duration::from_millis(100)).await;

        // Step 6: Generate compliance report
        println!("\n=== Step 6: Compliance Report ===");
        let report = self.generate_compliance_report();
        
        println!("Compliance Summary:");
        println!("  Total User Profiles: {}", report.total_user_profiles);
        println!("  Encrypted SSNs: {} ({:.1}% coverage)", 
            report.encrypted_ssn_count, 
            report.ssn_encryption_coverage
        );
        println!("  Encrypted Credit Cards: {} ({:.1}% coverage)", 
            report.encrypted_credit_card_count, 
            report.credit_card_encryption_coverage
        );
        println!("  OIDC Clients: {}", report.oidc_clients_configured);
        println!("  Rego Policies Enabled: {}", report.rego_policies_enabled);
        
        println!("\nDemo completed successfully!");
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfileData {
    pub username: String,
    pub email: String,
    pub full_name: String,
    pub ssn: Option<String>,
    pub credit_card: Option<String>,
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SensitiveDataType {
    SSN,
    CreditCard,
    Phone,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    pub original_value: String,
    pub encrypted_value: String,
    pub data_type: SensitiveDataType,
    pub metadata: FpeMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceReport {
    pub total_user_profiles: usize,
    pub encrypted_ssn_count: usize,
    pub encrypted_credit_card_count: usize,
    pub ssn_encryption_coverage: f64,
    pub credit_card_encryption_coverage: f64,
    pub oidc_clients_configured: usize,
    pub rego_policies_enabled: bool,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🏰 Fortress OIDC + FPE Integration Example");
    println!("==========================================\n");

    // Create and run the secure user service
    let mut service = SecureUserService::new()?;
    
    // Run the demonstration
    service.run_demo().await?;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_user_authentication_flow() {
        let mut service = SecureUserService::new().unwrap();
        
        // Test authentication
        let token = service.authenticate_user("web-portal", "testuser", "Password123!").await;
        assert!(token.is_ok());
        
        // Test invalid credentials
        let invalid_token = service.authenticate_user("web-portal", "testuser", "wrongpassword").await;
        assert!(invalid_token.is_err());
    }

    #[tokio::test]
    async fn test_profile_encryption_decryption() {
        let mut service = SecureUserService::new().unwrap();
        
        // Create profile with sensitive data
        let token = service.authenticate_user("web-portal", "testuser", "Password123!").await.unwrap();
        let profile_data = UserProfileData {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            full_name: "Test User".to_string(),
            ssn: Some("123-45-6789".to_string()),
            credit_card: Some("4532123456789012".to_string()),
            roles: vec!["user".to_string()],
        };
        
        let profile = service.create_user_profile(&token, profile_data).await.unwrap();
        
        // Retrieve and verify decryption
        let retrieved_data = service.get_user_profile(&token, &profile.id).await.unwrap();
        assert_eq!(retrieved_data.ssn, Some("123-45-6789".to_string()));
        assert_eq!(retrieved_data.credit_card, Some("4532123456789012".to_string()));
    }

    #[tokio::test]
    async fn test_service_to_service_auth() {
        let mut service = SecureUserService::new().unwrap();
        
        let token = service.service_to_service_auth("web-portal", "api-service").await;
        assert!(token.is_ok());
    }

    #[test]
    fn test_batch_encryption() {
        let service = SecureUserService::new().unwrap();
        
        let data = vec![
            ("123-45-6789".to_string(), SensitiveDataType::SSN),
            ("4532123456789012".to_string(), SensitiveDataType::CreditCard),
        ];
        
        let encrypted_data = service.batch_encrypt_sensitive_data(data).unwrap();
        assert_eq!(encrypted_data.len(), 2);
        
        // Verify format preservation
        for encrypted in &encrypted_data {
            match encrypted.data_type {
                SensitiveDataType::SSN => {
                    assert_eq!(encrypted.encrypted_value.len(), encrypted.original_value.len());
                    assert!(encrypted.encrypted_value.contains('-'));
                }
                SensitiveDataType::CreditCard => {
                    assert_eq!(encrypted.encrypted_value.len(), encrypted.original_value.len());
                }
                _ => {}
            }
        }
    }

    #[test]
    fn test_compliance_report() {
        let mut service = SecureUserService::new().unwrap();
        
        // Add some test profiles
        let token = service.authenticate_user("web-portal", "testuser", "Password123!").await.unwrap();
        let profile_data = UserProfileData {
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            full_name: "Test User".to_string(),
            ssn: Some("123-45-6789".to_string()),
            credit_card: Some("4532123456789012".to_string()),
            roles: vec!["user".to_string()],
        };
        
        let _profile = service.create_user_profile(&token, profile_data).await.unwrap();
        
        let report = service.generate_compliance_report();
        assert_eq!(report.total_user_profiles, 1);
        assert_eq!(report.encrypted_ssn_count, 1);
        assert_eq!(report.encrypted_credit_card_count, 1);
        assert!(report.ssn_encryption_coverage > 0.0);
        assert!(report.credit_card_encryption_coverage > 0.0);
    }
}
