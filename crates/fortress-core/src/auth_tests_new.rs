#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;

    #[tokio::test]
    async fn test_user_creation() {
        let mut auth = AuthManager::new();
        
        let user_id = auth.create_user("testuser".to_string(), "test@example.com".to_string(), "Password123!".to_string()).await
            .expect("Failed to create test user");
        
        let user = auth.get_user(&user_id)
            .expect("Failed to retrieve created user");
        assert_eq!(user.username, "testuser");
        assert!(user.active);
    }
    // ... add others ...
}
