//! GraphQL schema definition
//!
//! Combines all GraphQL types, queries, mutations, and subscriptions
//! into a complete Fortress GraphQL schema.

use async_graphql::Schema;
use crate::graphql::{
    query::Query,
    mutation::Mutation,
    subscription::Subscription,
};

/// Create a new Fortress GraphQL schema
pub fn create_schema() -> Schema<Query, Mutation, Subscription> {
    Schema::build(Query, Mutation, Subscription)
        .finish()
}

/// Complete Fortress GraphQL schema
pub type FortressSchema = Schema<Query, Mutation, Subscription>;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_schema_creation() {
        let schema = create_schema();
        
        // Test a simple query
        let query = r#"
        {
            version
        }
        "#;
        
        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        // Check the version field exists
        let data = result.data.into_json().unwrap();
        assert!(data.get("version").is_some());
    }

    #[tokio::test]
    async fn test_health_query() {
        let schema = create_schema();
        
        let query = r#"
        {
            health {
                healthy
                services {
                    name
                    healthy
                    responseTimeMs
                }
                lastCheck
            }
        }
        "#;
        
        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        let data = result.data.into_json().unwrap();
        let health = data.get("health").unwrap().as_object().unwrap();
        
        assert!(health.get("healthy").unwrap().as_bool().unwrap());
        assert!(health.get("services").unwrap().as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_databases_query() {
        let schema = create_schema();
        
        let query = r#"
        {
            databases {
                id
                name
                status
                encryptionAlgorithm
                createdAt
                tableCount
                storageSizeBytes
            }
        }
        "#;
        
        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        let data = result.data.into_json().unwrap();
        let databases = data.get("databases").unwrap().as_array().unwrap();
        
        assert!(databases.len() > 0);
        
        let db = &databases[0];
        assert!(db.get("id").is_some());
        assert!(db.get("name").is_some());
        assert!(db.get("status").is_some());
        assert!(db.get("encryptionAlgorithm").is_some());
    }

    #[tokio::test]
    async fn test_create_database_mutation() {
        let schema = create_schema();
        
        let mutation = r#"
        mutation {
            createDatabase(input: {
                name: "test_db"
                description: "Test database"
                encryptionAlgorithm: AEGIS256
                tags: ["test", "example"]
            }) {
                success
                data {
                    id
                    name
                    description
                    status
                    encryptionAlgorithm
                    tags
                }
                errorMessage
                errorCode
            }
        }
        "#;
        
        let result = schema.execute(mutation).await;
        
        // This should fail due to missing authentication in tests
        // But the schema should be valid
        assert!(!result.errors.is_empty());
        
        // Check if it's an authentication error
        let error = &result.errors[0];
        assert!(error.message.contains("Authentication required") || 
                error.message.contains("admin"));
    }

    #[tokio::test]
    async fn test_query_data() {
        let schema = create_schema();
        
        let query = r#"
        {
            queryData(input: {
                database: "example_db"
                table: "users"
                pagination: {
                    page: 0
                    pageSize: 10
                }
            }) {
                records {
                    id
                    data
                    createdAt
                    updatedAt
                }
                totalCount
                hasMore
                pagination {
                    page
                    pageSize
                    totalPages
                    totalRecords
                    hasNext
                    hasPrevious
                }
            }
        }
        "#;
        
        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        let data = result.data.into_json().unwrap();
        let query_result = data.get("queryData").unwrap().as_object().unwrap();
        
        assert!(query_result.get("records").unwrap().as_array().unwrap().len() > 0);
        assert!(query_result.get("totalCount").unwrap().as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_subscription_schema() {
        let schema = create_schema();
        
        // Test subscription introspection
        let query = r#"
        {
            __schema {
                subscriptionType {
                    fields {
                        name
                        description
                    }
                }
            }
        }
        "#;
        
        let result = schema.execute(query).await;
        assert!(result.errors.is_empty());
        
        let data = result.data.into_json().unwrap();
        let schema_data = data.get("__schema").unwrap().as_object().unwrap();
        let subscription_type = schema_data.get("subscriptionType").unwrap().as_object().unwrap();
        let fields = subscription_type.get("fields").unwrap().as_array().unwrap();
        
        // Should have subscription fields
        assert!(fields.len() > 0);
        
        let field_names: Vec<String> = fields.iter()
            .filter_map(|f| f.as_object())
            .filter_map(|obj| obj.get("name"))
            .filter_map(|name| name.as_str())
            .map(|s| s.to_string())
            .collect();
        
        assert!(field_names.contains(&"dataChanges".to_string()));
        assert!(field_names.contains(&"healthEvents".to_string()));
        assert!(field_names.contains(&"performanceMetrics".to_string()));
    }
}
