//! Comprehensive Security Tests for Production-Ready SQL Parser
//! 
//! Tests all SQL injection prevention mechanisms and validates that the
//! production-ready parser properly handles security threats.

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::graphql::query_executor::{OptimizedQueryExecutor, ExecutorConfig};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Mock implementations for testing
    struct MockCache;
    struct MockQueryPlanner;
    struct MockConnectionPool;
    
    #[async_trait::async_trait]
    impl Cache for MockCache {
        async fn get(&self, _key: &str) -> Option<QueryResult> { None }
        async fn set(&self, _key: &str, _value: &QueryResult, _ttl: Duration) {}
        async fn invalidate(&self, _key: &str) {}
        async fn clear(&self) {}
        async fn stats(&self) -> CacheStats { CacheStats::default() }
    }
    
    #[async_trait::async_trait]
    impl QueryPlanner for MockQueryPlanner {
        async fn optimize(&self, query: &str, _parameters: &Option<Vec<serde_json::Value>>) -> Result<OptimizedPlan> {
            Ok(OptimizedPlan {
                optimized_query: query.to_string(),
                execution_plan: "mock_plan".to_string(),
                estimated_cost: 1.0,
                optimization_applied: Vec::new(),
                indexes_used: Vec::new(),
                parallel_execution: false,
            })
        }
        
        async fn explain(&self, _query: &str) -> Result<QueryExplanation> {
            Ok(QueryExplanation {
                plan: Vec::new(),
                estimated_cost: 1.0,
                optimization_opportunities: Vec::new(),
            })
        }
    }
    
    #[async_trait::async_trait]
    impl ConnectionPool for MockConnectionPool {
        async fn get_connection(&self) -> Result<Box<dyn DatabaseConnection>> {
            Ok(Box::new(MockDatabaseConnection))
        }
        
        async fn return_connection(&self, _conn: Box<dyn DatabaseConnection>) {}
        async fn stats(&self) -> PoolStats { PoolStats::default() }
    }
    
    struct MockDatabaseConnection;
    
    #[async_trait::async_trait]
    impl DatabaseConnection for MockDatabaseConnection {
        async fn execute(&mut self, _query: &str, _params: &[serde_json::Value]) -> Result<QueryResult> {
            Ok(QueryResult::default())
        }
        
        async fn execute_batch(&mut self, _queries: &[BatchQuery]) -> Result<Vec<QueryResult>> {
            Ok(Vec::new())
        }
        
        async fn prepare(&mut self, _query: &str) -> Result<PreparedStatement> {
            Ok(PreparedStatement {
                id: "mock".to_string(),
                query: _query.to_string(),
                parameter_count: 0,
                prepared_at: Utc::now(),
            })
        }
        
        fn connection_info(&self) -> ConnectionInfo {
            ConnectionInfo {
                id: "mock".to_string(),
                created_at: Utc::now(),
                last_used: Utc::now(),
                queries_executed: 0,
                total_execution_time: Duration::ZERO,
            }
        }
    }

    fn create_test_executor() -> OptimizedQueryExecutor {
        let config = ExecutorConfig::default();
        OptimizedQueryExecutor::new(
            Arc::new(MockCache),
            Arc::new(MockQueryPlanner),
            Arc::new(MockConnectionPool),
            config,
        )
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_quotes() {
        let executor = create_test_executor();
        
        // Test single quote injection
        let result = executor.parse_query("SELECT * FROM users WHERE name = 'admin' OR '1'='1");
        assert!(result.is_err(), "Should reject SQL injection with single quotes");
        
        // Test double quote injection
        let result = executor.parse_query("SELECT * FROM users WHERE name = \"admin\" OR \"1\"=\"1");
        assert!(result.is_err(), "Should reject SQL injection with double quotes");
        
        // Test mixed quotes
        let result = executor.parse_query("SELECT * FROM users WHERE name = 'admin' --");
        assert!(result.is_err(), "Should reject SQL injection with comment");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_semicolon() {
        let executor = create_test_executor();
        
        // Test multiple statements
        let result = executor.parse_query("SELECT * FROM users; DROP TABLE users; --");
        assert!(result.is_err(), "Should reject multiple statements with semicolon");
        
        // Test semicolon injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1; DELETE FROM users");
        assert!(result.is_err(), "Should reject semicolon injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_comments() {
        let executor = create_test_executor();
        
        // Test line comment injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 -- DELETE FROM users");
        assert!(result.is_err(), "Should reject line comment injection");
        
        // Test block comment injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 /* DELETE FROM users */");
        assert!(result.is_err(), "Should reject block comment injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_union_select() {
        let executor = create_test_executor();
        
        // Test UNION injection
        let result = executor.parse_query("SELECT name FROM users UNION SELECT password FROM admin");
        assert!(result.is_err(), "Should reject UNION SELECT injection");
        
        // Test UNION ALL injection
        let result = executor.parse_query("SELECT name FROM users UNION ALL SELECT password FROM admin");
        assert!(result.is_err(), "Should reject UNION ALL injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_boolean_blind() {
        let executor = create_test_executor();
        
        // Test OR 1=1 injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 OR 1=1");
        assert!(result.is_err(), "Should reject OR 1=1 injection");
        
        // Test AND 1=1 injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 AND 1=1");
        assert!(result.is_err(), "Should reject AND 1=1 injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_stored_procedures() {
        let executor = create_test_executor();
        
        // Test xp_cmdshell injection
        let result = executor.parse_query("EXEC xp_cmdshell 'dir'");
        assert!(result.is_err(), "Should reject xp_cmdshell injection");
        
        // Test sp_executesql injection
        let result = executor.parse_query("EXEC sp_executesql N'DELETE FROM users'");
        assert!(result.is_err(), "Should reject sp_executesql injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_file_operations() {
        let executor = create_test_executor();
        
        // Test LOAD_FILE injection
        let result = executor.parse_query("SELECT LOAD_FILE('/etc/passwd')");
        assert!(result.is_err(), "Should reject LOAD_FILE injection");
        
        // Test INTO OUTFILE injection
        let result = executor.parse_query("SELECT * FROM users INTO OUTFILE '/tmp/users.txt'");
        assert!(result.is_err(), "Should reject INTO OUTFILE injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_system_tables() {
        let executor = create_test_executor();
        
        // Test information_schema access
        let result = executor.parse_query("SELECT * FROM information_schema.tables");
        assert!(result.is_err(), "Should reject information_schema access");
        
        // Test mysql.user access
        let result = executor.parse_query("SELECT * FROM mysql.user");
        assert!(result.is_err(), "Should reject mysql.user access");
        
        // Test pg_catalog access
        let result = executor.parse_query("SELECT * FROM pg_catalog.pg_user");
        assert!(result.is_err(), "Should reject pg_catalog access");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_timing_attacks() {
        let executor = create_test_executor();
        
        // Test WAITFOR DELAY injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 WAITFOR DELAY '00:00:05'");
        assert!(result.is_err(), "Should reject WAITFOR DELAY injection");
        
        // Test SLEEP injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 AND SLEEP(5)");
        assert!(result.is_err(), "Should reject SLEEP injection");
        
        // Test BENCHMARK injection
        let result = executor.parse_query("SELECT * FROM users WHERE id = 1 AND BENCHMARK(5000000, MD5('test'))");
        assert!(result.is_err(), "Should reject BENCHMARK injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_dynamic_execution() {
        let executor = create_test_executor();
        
        // Test EXEC injection
        let result = executor.parse_query("EXEC('DELETE FROM users')");
        assert!(result.is_err(), "Should reject EXEC injection");
        
        // Test EXECUTE injection
        let result = executor.parse_query("EXECUTE IMMEDIATE 'DELETE FROM users'");
        assert!(result.is_err(), "Should reject EXECUTE injection");
        
        // Test EVAL injection
        let result = executor.parse_query("SELECT EVAL('system(\"rm -rf /\")')");
        assert!(result.is_err(), "Should reject EVAL injection");
    }

    #[tokio::test]
    async fn test_sql_injection_prevention_shell_commands() {
        let executor = create_test_executor();
        
        // Test SYSTEM function
        let result = executor.parse_query("SELECT SYSTEM('rm -rf /')");
        assert!(result.is_err(), "Should reject SYSTEM function");
        
        // Test SHELL function
        let result = executor.parse_query("SELECT SHELL('cat /etc/passwd')");
        assert!(result.is_err(), "Should reject SHELL function");
    }

    #[tokio::test]
    async fn test_legitimate_queries_allowed() {
        let executor = create_test_executor();
        
        // Test legitimate SELECT queries
        let result = executor.parse_query("SELECT id, name FROM users WHERE active = 1");
        assert!(result.is_ok(), "Should allow legitimate SELECT query");
        
        // Test legitimate INSERT queries
        let result = executor.parse_query("INSERT INTO users (name, email) VALUES ('John', 'john@example.com')");
        assert!(result.is_ok(), "Should allow legitimate INSERT query");
        
        // Test legitimate UPDATE queries
        let result = executor.parse_query("UPDATE users SET name = 'John' WHERE id = 1");
        assert!(result.is_ok(), "Should allow legitimate UPDATE query");
        
        // Test legitimate DELETE queries
        let result = executor.parse_query("DELETE FROM users WHERE id = 1");
        assert!(result.is_ok(), "Should allow legitimate DELETE query");
    }

    #[tokio::test]
    async fn test_complex_legitimate_queries_allowed() {
        let executor = create_test_executor();
        
        // Test complex JOIN queries
        let result = executor.parse_query("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = 1");
        assert!(result.is_ok(), "Should allow legitimate JOIN query");
        
        // Test subquery
        let result = executor.parse_query("SELECT name FROM users WHERE id IN (SELECT user_id FROM orders WHERE total > 100)");
        assert!(result.is_ok(), "Should allow legitimate subquery");
        
        // Test CTE (Common Table Expression)
        let result = executor.parse_query("WITH active_users AS (SELECT * FROM users WHERE active = 1) SELECT * FROM active_users");
        assert!(result.is_ok(), "Should allow legitimate CTE");
        
        // Test aggregation
        let result = executor.parse_query("SELECT COUNT(*) as total, AVG(price) as avg_price FROM products WHERE category = 'electronics'");
        assert!(result.is_ok(), "Should allow legitimate aggregation query");
    }

    #[tokio::test]
    async fn test_admin_operation_detection() {
        let executor = create_test_executor();
        
        // Test DDL operations detected as admin
        let admin_queries = [
            "CREATE TABLE users (id INT, name VARCHAR(100))",
            "DROP TABLE users",
            "ALTER TABLE users ADD COLUMN email VARCHAR(255)",
            "TRUNCATE TABLE users",
            "GRANT SELECT ON users TO webapp",
            "REVOKE SELECT ON users FROM webapp",
        ];
        
        for query in admin_queries {
            let result = executor.parse_query(query);
            assert!(result.is_ok(), "Should parse admin query: {}", query);
            let parsed = result.unwrap();
            assert!(parsed.is_admin_operation, "Should detect admin operation in: {}", query);
        }
    }

    #[tokio::test]
    async fn test_table_extraction_accuracy() {
        let executor = create_test_executor();
        
        // Test SELECT table extraction
        let result = executor.parse_query("SELECT id, name FROM users WHERE active = 1");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.tables, vec!["users"]);
        
        // Test INSERT table extraction
        let result = executor.parse_query("INSERT INTO users (name, email) VALUES ('John', 'john@example.com')");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.tables, vec!["users"]);
        
        // Test UPDATE table extraction
        let result = executor.parse_query("UPDATE users SET name = 'John' WHERE id = 1");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.tables, vec!["users"]);
        
        // Test DELETE table extraction
        let result = executor.parse_query("DELETE FROM users WHERE id = 1");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert_eq!(parsed.tables, vec!["users"]);
        
        // Test JOIN table extraction
        let result = executor.parse_query("SELECT u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id");
        assert!(result.is_ok());
        let parsed = result.unwrap();
        assert!(parsed.tables.contains(&"users".to_string()));
        assert!(parsed.tables.contains(&"orders".to_string()));
    }

    #[tokio::test]
    async fn test_operation_type_detection() {
        let executor = create_test_executor();
        
        // Test each operation type
        let test_cases = [
            ("SELECT * FROM users", QueryOperation::Select),
            ("INSERT INTO users VALUES (1, 'John')", QueryOperation::Insert),
            ("UPDATE users SET name = 'John'", QueryOperation::Update),
            ("DELETE FROM users WHERE id = 1", QueryOperation::Delete),
            ("CREATE TABLE test (id INT)", QueryOperation::Create),
            ("DROP TABLE test", QueryOperation::Drop),
            ("ALTER TABLE test ADD COLUMN name VARCHAR(100)", QueryOperation::Alter),
            ("TRUNCATE TABLE test", QueryOperation::Truncate),
            ("GRANT SELECT ON test TO user", QueryOperation::Grant),
            ("REVOKE SELECT ON test FROM user", QueryOperation::Revoke),
            ("WITH cte AS (SELECT * FROM test) SELECT * FROM cte", QueryOperation::With),
        ];
        
        for (query, expected_operation) in test_cases {
            let result = executor.parse_query(query);
            assert!(result.is_ok(), "Should parse query: {}", query);
            let parsed = result.unwrap();
            assert!(matches!(parsed.operation, expected_operation), 
                     "Expected {:?} for query: {}", expected_operation, query);
        }
    }

    #[tokio::test]
    async fn test_sql_normalization() {
        let executor = create_test_executor();
        
        // Test comment removal
        let result = executor.parse_query("SELECT * FROM users -- This is a comment\nWHERE id = 1");
        assert!(result.is_ok());
        
        // Test block comment removal
        let result = executor.parse_query("SELECT * FROM users /* This is a block comment */ WHERE id = 1");
        assert!(result.is_ok());
        
        // Test whitespace normalization
        let result = executor.parse_query("SELECT   *   FROM   users   WHERE   id   =   1");
        assert!(result.is_ok());
        
        // Test mixed comments and whitespace
        let result = executor.parse_query("SELECT * /* comment */ FROM users -- line comment\nWHERE id = 1");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_tokenization_edge_cases() {
        let executor = create_test_executor();
        
        // Test quoted identifiers
        let result = executor.parse_query("SELECT * FROM \"users\" WHERE \"name\" = 'John'");
        assert!(result.is_ok());
        
        // Test parentheses handling
        let result = executor.parse_query("SELECT * FROM users WHERE id IN (1, 2, 3)");
        assert!(result.is_ok());
        
        // Test nested parentheses
        let result = executor.parse_query("SELECT * FROM users WHERE id IN (SELECT id FROM orders WHERE total > (SELECT AVG(total) FROM orders))");
        assert!(result.is_ok());
        
        // Test comma handling
        let result = executor.parse_query("SELECT id, name, email FROM users");
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_empty_and_invalid_queries() {
        let executor = create_test_executor();
        
        // Test empty query
        let result = executor.parse_query("");
        assert!(result.is_err(), "Should reject empty query");
        
        // Test whitespace-only query
        let result = executor.parse_query("   \t\n   ");
        assert!(result.is_err(), "Should reject whitespace-only query");
        
        // Test comment-only query
        let result = executor.parse_query("-- This is just a comment");
        assert!(result.is_err(), "Should reject comment-only query");
    }

    #[tokio::test]
    async fn test_comprehensive_injection_patterns() {
        let executor = create_test_executor();
        
        // Advanced injection patterns that should be blocked
        let injection_patterns = [
            "SELECT * FROM users WHERE name = 'admin' OR 'x'='x",
            "SELECT * FROM users WHERE name = 'admin' UNION SELECT password FROM admin",
            "SELECT * FROM users WHERE id = 1; DROP TABLE users; --",
            "SELECT * FROM users WHERE id = 1 AND (SELECT COUNT(*) FROM information_schema.tables) > 0",
            "SELECT * FROM users WHERE id = 1 AND SLEEP(5)",
            "SELECT * FROM users WHERE id = 1 AND BENCHMARK(5000000, MD5('test'))",
            "SELECT * FROM users WHERE id = 1; EXEC xp_cmdshell 'dir'",
            "SELECT * FROM users WHERE id = 1; EXEC sp_executesql N'DELETE FROM users'",
            "SELECT * FROM users WHERE id = 1 UNION SELECT LOAD_FILE('/etc/passwd')",
            "SELECT * FROM users WHERE id = 1 INTO OUTFILE '/tmp/dump.txt'",
            "SELECT * FROM users WHERE id = 1' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            "SELECT * FROM users WHERE id = 1' AND (SELECT SLEEP(5)) --",
            "SELECT * FROM users WHERE id = 1' UNION SELECT @@version --",
            "SELECT * FROM users WHERE id = 1' UNION SELECT database() --",
            "SELECT * FROM users WHERE id = 1' UNION SELECT user() --",
        ];
        
        for pattern in injection_patterns {
            let result = executor.parse_query(pattern);
            assert!(result.is_err(), "Should reject injection pattern: {}", pattern);
        }
    }

    #[tokio::test]
    async fn test_legitimate_edge_cases() {
        let executor = create_test_executor();
        
        // Edge cases that should be allowed
        let legitimate_queries = [
            "SELECT * FROM users WHERE name = 'O'Reilly'",  // Single quote in name
            "SELECT * FROM users WHERE description = 'This contains \"quotes\"'",  // Double quotes in string
            "SELECT * FROM users WHERE notes LIKE '%important%'",  // LIKE with wildcards
            "SELECT * FROM users WHERE id IN (1, 2, 3, 4, 5)",  // IN clause
            "SELECT * FROM users WHERE name IS NOT NULL",  // IS NOT NULL
            "SELECT * FROM users WHERE created_at > '2023-01-01'",  // Date comparison
            "SELECT COUNT(*) as total FROM users",  // Aggregate with alias
            "SELECT DISTINCT category FROM products",  // DISTINCT
            "SELECT * FROM users ORDER BY name DESC LIMIT 10",  // ORDER BY and LIMIT
            "SELECT * FROM users WHERE name LIKE 'test\\_%' ESCAPE '\\'",  // ESCAPE clause
        ];
        
        for query in legitimate_queries {
            let result = executor.parse_query(query);
            assert!(result.is_ok(), "Should allow legitimate query: {}", query);
        }
    }
}
