//! Test module for Fortress authentication plugins

pub mod integration_tests;

#[cfg(test)]
pub mod test_utils {
    use fortress_auth_plugins::{AuthContext, AuthResult};
    
    use serde_json::{json, Value};
    
    pub fn create_test_auth_context(method: &str, credentials: Value) -> AuthContext {
        AuthContext {
            method: method.to_string(),
            credentials,
            request_id: format!("test-req-{}", uuid::Uuid::new_v4()),
        }
    }
    
    pub fn create_test_jwt_config() -> Value {
        json!({
            "jwt_secret": "test-secret-key",
            "token_expiration": 3600,
            "issuer": "test-issuer",
            "audience": "test-audience"
        })
    }
    
    pub fn create_test_oauth_config() -> Value {
        json!({
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "redirect_uri": "https://localhost:8080/callback",
            "authorization_endpoint": "https://oauth-test.com/oauth/authorize",
            "token_endpoint": "https://oauth-test.com/oauth/token"
        })
    }
    
    pub fn create_test_saml_config() -> Value {
        json!({
            "entity_id": "https://test.com/saml",
            "sso_url": "https://idp-test.com/sso",
            "certificate": "-----BEGIN CERTIFICATE-----\nTEST_CERT\n-----END CERTIFICATE-----"
        })
    }
    
    pub fn assert_auth_result_success(result: &AuthResult) {
        assert!(result.success, "Authentication should succeed");
        assert!(!result.user_id.is_empty(), "User ID should not be empty");
        assert!(result.error_message.is_empty(), "Error message should be empty");
    }
    
    pub fn assert_auth_result_failure(result: &AuthResult) {
        assert!(!result.success, "Authentication should fail");
        assert!(!result.error_message.is_empty(), "Error message should not be empty");
    }
}
