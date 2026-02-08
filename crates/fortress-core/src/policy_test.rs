//! Policy engine tests

use crate::policy::*;
use tokio::test;

#[test]
async fn test_role_creation() {
    let role = Role::new("test")
        .with_description("Test role")
        .with_permission(Permission::Read, Resource::Database("users"));

    assert_eq!(role.name, "test");
    assert_eq!(role.description, Some("Test role".to_string()));
    assert_eq!(role.permissions.len(), 1);
}

#[test]
async fn test_policy_engine_basic() {
    let engine = PolicyEngine::new();
    
    let role = Role::new("readonly")
        .with_permission(Permission::Read, Resource::Database("users"));
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "readonly").await.unwrap();
    
    let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    let can_write = engine.check_permission("user1", Permission::Write, Resource::Database("users")).await.unwrap();
    
    assert!(can_read);
    assert!(!can_write);
}

#[test]
async fn test_resource_matching() {
    let engine = PolicyEngine::new();
    
    let role = Role::new("db_access")
        .with_permission(Permission::Read, Resource::Database("users"));
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "db_access").await.unwrap();
    
    // Should match database access
    let can_read_db = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    // Should match table access within database
    let can_read_table = engine.check_permission("user1", Permission::Read, Resource::Table("users", "profiles")).await.unwrap();
    // Should match field access within database
    let can_read_field = engine.check_permission("user1", Permission::Read, Resource::Field("users", "profiles", "email")).await.unwrap();
    
    assert!(can_read_db);
    assert!(can_read_table);
    assert!(can_read_field);
}

#[test]
async fn test_user_roles() {
    let engine = PolicyEngine::new();
    
    let role1 = Role::new("admin").with_permission(Permission::Admin, Resource::All);
    let role2 = Role::new("reader").with_permission(Permission::Read, Resource::Database("users"));
    
    engine.add_role(role1).await.unwrap();
    engine.add_role(role2).await.unwrap();
    
    engine.assign_role("user1", "admin").await.unwrap();
    engine.assign_role("user1", "reader").await.unwrap();
    
    let roles = engine.get_user_roles("user1").await.unwrap();
    assert_eq!(roles.len(), 2);
    assert!(roles.contains(&"admin".to_string()));
    assert!(roles.contains(&"reader".to_string()));
}

#[test]
async fn test_user_permissions() {
    let engine = PolicyEngine::new();
    
    let role = Role::new("multi_access")
        .with_permission(Permission::Read, Resource::Database("users"))
        .with_permission(Permission::Write, Resource::Database("orders"));
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "multi_access").await.unwrap();
    
    let permissions = engine.get_user_permissions("user1").await.unwrap();
    assert_eq!(permissions.len(), 2);
}

#[test]
async fn test_role_removal() {
    let engine = PolicyEngine::new();
    
    let role = Role::new("temp_role")
        .with_permission(Permission::Read, Resource::Database("users"));
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "temp_role").await.unwrap();
    
    // Verify role exists and user has access
    let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    assert!(can_read);
    
    // Remove role
    engine.remove_role("temp_role").await.unwrap();
    
    // Verify access is revoked
    let can_read_after = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    assert!(!can_read_after);
}

#[test]
async fn test_role_assignment_removal() {
    let engine = PolicyEngine::new();
    
    let role = Role::new("test_role")
        .with_permission(Permission::Read, Resource::Database("users"));
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "test_role").await.unwrap();
    
    // Verify access
    let can_read = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    assert!(can_read);
    
    // Remove role assignment
    engine.remove_role_assignment("user1", "test_role").await.unwrap();
    
    // Verify access is revoked
    let can_read_after = engine.check_permission("user1", Permission::Read, Resource::Database("users")).await.unwrap();
    assert!(!can_read_after);
}

#[test]
async fn test_nonexistent_role() {
    let engine = PolicyEngine::new();
    
    // Try to assign non-existent role
    let result = engine.assign_role("user1", "nonexistent").await;
    assert!(result.is_err());
}

#[test]
async fn test_permissions_with_conditions() {
    let engine = PolicyEngine::new();
    
    let time_condition = TimeCondition {
        start_time: Some(1000),
        end_time: Some(2000),
        days_of_week: None,
        timezone: None,
    };
    
    let role = Role::new("conditional")
        .with_permission_conditions(
            Permission::Read,
            Resource::Database("users"),
            vec![Condition::Time(time_condition)],
        );
    
    engine.add_role(role).await.unwrap();
    engine.assign_role("user1", "conditional").await.unwrap();
    
    // This test will need to be adjusted based on actual time condition evaluation
    // For now, just verify the role was created successfully
    let roles = engine.get_user_roles("user1").await.unwrap();
    assert_eq!(roles.len(), 1);
}
