//! GraphQL API tests
//!
//! Tests for the Fortress GraphQL API implementation.

#[cfg(test)]
mod tests {
    use async_graphql::Request;

    #[tokio::test]
    async fn test_graphql_schema_creation() {
        let _schema = crate::graphql::create_schema();
        
        // Test that schema can be created without panicking
        assert!(true, "Schema creation should not panic");
    }

    #[tokio::test]
    async fn test_databases_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
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
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let databases = data.get("databases").unwrap().as_array().unwrap();
        assert!(!databases.is_empty(), "Should return at least one database");
    }

    #[tokio::test]
    async fn test_health_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
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
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Health query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let health = data.get("health").unwrap().as_object().unwrap();
        
        assert!(health.get("healthy").unwrap().as_bool().unwrap());
        assert!(health.get("services").unwrap().as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_version_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
            {
                version
            }
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Version query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let version = data.get("version").unwrap().as_str().unwrap();
        assert!(!version.is_empty(), "Version should not be empty");
    }

    #[tokio::test]
    async fn test_database_by_name_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
            {
                database(name: "example_db") {
                    id
                    name
                    description
                    status
                    encryptionAlgorithm
                    createdAt
                    tableCount
                }
            }
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Database query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let database = data.get("database").unwrap();
        
        if !database.is_null() {
            let db_obj = database.as_object().unwrap();
            assert_eq!(db_obj.get("name").unwrap().as_str().unwrap(), "example_db");
        }
    }

    #[tokio::test]
    async fn test_tables_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
            {
                tables(database: "example_db") {
                    id
                    name
                    database
                    description
                    encryptionEnabled
                    recordCount
                    fields {
                        name
                        fieldType
                        required
                        encrypted
                    }
                    primaryKey
                }
            }
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Tables query should not have errors");
        
        let data = response.data.into_json().unwrap();
        let tables = data.get("tables").unwrap().as_array().unwrap();
        
        if !tables.is_empty() {
            let table = &tables[0];
            let table_obj = table.as_object().unwrap();
            assert_eq!(table_obj.get("name").unwrap().as_str().unwrap(), "users");
            assert_eq!(table_obj.get("database").unwrap().as_str().unwrap(), "example_db");
        }
    }

    #[tokio::test]
    async fn test_query_data() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
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
                }
            }
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Query data should not have errors");
        
        let data = response.data.into_json().unwrap();
        let query_result = data.get("queryData").unwrap().as_object().unwrap();
        
        assert!(query_result.get("records").unwrap().as_array().unwrap().len() > 0);
        assert!(query_result.get("totalCount").unwrap().as_i64().unwrap() > 0);
    }

    #[tokio::test]
    async fn test_create_database_mutation() {
        let schema = crate::graphql::create_schema();
        
        let mutation = Request::new(r#"
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
        "#);
        
        let response = schema.execute(mutation).await;
        
        // This should fail due to missing authentication in tests
        // But the schema should be valid
        assert!(!response.errors.is_empty(), "Should have authentication error");
        
        // Check if it's an authentication error
        let error = &response.errors[0];
        assert!(error.message.contains("Authentication required") || 
                error.message.contains("admin"));
    }

    #[tokio::test]
    async fn test_introspection_query() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
            {
                __schema {
                    queryType {
                        name
                        description
                    }
                    mutationType {
                        name
                        description
                    }
                    subscriptionType {
                        name
                        description
                    }
                    types {
                        name
                        kind
                        description
                    }
                }
            }
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Introspection should not have errors");
        
        let data = response.data.into_json().unwrap();
        let schema_data = data.get("__schema").unwrap().as_object().unwrap();
        
        assert!(schema_data.get("queryType").is_some());
        assert!(schema_data.get("mutationType").is_some());
        assert!(schema_data.get("subscriptionType").is_some());
        assert!(schema_data.get("types").is_some());
    }

    #[tokio::test]
    async fn test_subscription_schema() {
        let schema = crate::graphql::create_schema();
        
        let query = Request::new(r#"
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
        "#);
        
        let response = schema.execute(query).await;
        assert!(response.errors.is_empty(), "Subscription introspection should not have errors");
        
        let data = response.data.into_json().unwrap();
        let schema_data = data.get("__schema").unwrap().as_object().unwrap();
        let subscription_type = schema_data.get("subscriptionType").unwrap().as_object().unwrap();
        let fields = subscription_type.get("fields").unwrap().as_array().unwrap();
        
        // Should have subscription fields
        assert!(!fields.is_empty());
        
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
