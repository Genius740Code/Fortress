//! Query engine and execution

//!

//! This module provides SQL parsing, optimization, and execution capabilities

//! for Fortress encrypted databases.



use crate::error::{FortressError, Result, QueryErrorCode};

use crate::encryption::{EncryptionAlgorithm, SecureKey};

use async_trait::async_trait;

use bytes::Bytes;

use serde::{Deserialize, Serialize};

use std::collections::HashMap;

use std::fmt;



/// Query engine trait

#[async_trait]

pub trait QueryEngine: Send + Sync + fmt::Debug {

    /// Execute a SQL query

    async fn execute(&self, query: &str, parameters: &[QueryParameter]) -> Result<QueryResult>;



    /// Parse a SQL query into an execution plan

    async fn parse(&self, query: &str) -> Result<ExecutionPlan>;



    /// Optimize an execution plan

    async fn optimize(&self, plan: ExecutionPlan) -> Result<ExecutionPlan>;



    /// Explain a query (show execution plan)

    async fn explain(&self, query: &str) -> Result<ExecutionPlan>;



    /// Get table schema

    async fn get_table_schema(&self, table_name: &str) -> Result<TableSchema>;



    /// List all tables

    async fn list_tables(&self) -> Result<Vec<String>>;



    /// Prepare a statement for repeated execution

    async fn prepare(&self, query: &str) -> Result<PreparedStatement>;

}



/// Query parameter

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum QueryParameter {

    /// Null value

    Null,

    /// Boolean value

    Boolean(bool),

    /// Integer value

    Integer(i64),

    /// Float value

    Float(f64),

    /// String value

    String(String),

    /// Binary value

    Binary(Vec<u8>),

    /// UUID value

    Uuid(uuid::Uuid),

    /// Timestamp value

    Timestamp(chrono::DateTime<chrono::Utc>),

}



impl QueryParameter {

    /// Get the parameter type

    pub fn param_type(&self) -> ParameterType {

        match self {

            Self::Null => ParameterType::Null,

            Self::Boolean(_) => ParameterType::Boolean,

            Self::Integer(_) => ParameterType::Integer,

            Self::Float(_) => ParameterType::Float,

            Self::String(_) => ParameterType::String,

            Self::Binary(_) => ParameterType::Binary,

            Self::Uuid(_) => ParameterType::Uuid,

            Self::Timestamp(_) => ParameterType::Timestamp,

        }

    }

}



/// Parameter type

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum ParameterType {

    Null,

    Boolean,

    Integer,

    Float,

    String,

    Binary,

    Uuid,

    Timestamp,

}



/// Query result

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct QueryResult {

    /// Result rows

    pub rows: Vec<Row>,

    /// Column information

    pub columns: Vec<ColumnInfo>,

    /// Total number of rows (might be more than returned)

    pub total_rows: Option<u64>,

    /// Execution time in milliseconds

    pub execution_time_ms: u64,

    /// Query metadata

    pub metadata: QueryMetadata,

}



/// Row in query result

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct Row {

    /// Column values

    pub values: Vec<QueryParameter>,

    /// Row metadata

    pub metadata: HashMap<String, String>,

}



impl Row {

    /// Create a new row

    pub fn new(values: Vec<QueryParameter>) -> Self {

        Self {

            values,

            metadata: HashMap::new(),

        }

    }



    /// Get value by index

    pub fn get(&self, index: usize) -> Option<&QueryParameter> {

        self.values.get(index)

    }



    /// Get value by index, converting to a specific type

    pub fn get_as<T>(&self, index: usize) -> Result<T>

    where

        T: TryFromQueryParameter,

    {

        self.values

            .get(index)

            .ok_or_else(|| FortressError::query_execution(

                format!("Index out of bounds: {}", index),

                None,

                QueryErrorCode::InvalidParameter,

            ))?

            .try_into()

    }



    /// Add metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }

}



/// Column information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ColumnInfo {

    /// Column name

    pub name: String,

    /// Column type

    pub column_type: ColumnType,

    /// Whether the column is nullable

    pub nullable: bool,

    /// Whether the column is encrypted

    pub encrypted: bool,

    /// Column size (if applicable)

    pub size: Option<usize>,

}



/// Column type

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum ColumnType {

    /// UUID type

    Uuid,

    /// Text/string type

    Text,

    /// Integer type

    Integer,

    /// Float type

    Float,

    /// Boolean type

    Boolean,

    /// Binary/blob type

    Binary,

    /// Encrypted type

    Encrypted,

    /// Timestamp type

    Timestamp,

}



/// Query metadata

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct QueryMetadata {

    /// Query type

    pub query_type: QueryType,

    /// Tables accessed

    pub tables_accessed: Vec<String>,

    /// Whether the query was read-only

    pub read_only: bool,

    /// Estimated cost

    pub estimated_cost: Option<f64>,

    /// Additional metadata

    pub metadata: HashMap<String, String>,

}



/// Query type

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum QueryType {

    Select,

    Insert,

    Update,

    Delete,

    Create,

    Drop,

    Alter,

}



/// Execution plan

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ExecutionPlan {

    /// Plan nodes

    pub nodes: Vec<PlanNode>,

    /// Estimated cost

    pub estimated_cost: f64,

    /// Plan metadata

    pub metadata: HashMap<String, String>,

}



/// Plan node in execution plan

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PlanNode {

    /// Node type

    pub node_type: PlanNodeType,

    /// Node children

    pub children: Vec<PlanNode>,

    /// Node parameters

    pub parameters: HashMap<String, serde_json::Value>,

    /// Estimated cost

    pub estimated_cost: f64,

}



/// Plan node type

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]

pub enum PlanNodeType {

    /// Table scan

    TableScan,

    /// Index scan

    IndexScan,

    /// Filter operation

    Filter,

    /// Projection operation

    Project,

    /// Sort operation

    Sort,

    /// Limit operation

    Limit,

    /// Join operation

    Join,

    /// Aggregate operation

    Aggregate,

    /// Insert operation

    Insert,

    /// Update operation

    Update,

    /// Delete operation

    Delete,

}



/// Table schema

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct TableSchema {

    /// Table name

    pub name: String,

    /// Table columns

    pub columns: Vec<ColumnInfo>,

    /// Primary key columns

    pub primary_key: Vec<String>,

    /// Table metadata

    pub metadata: HashMap<String, String>,

}



impl TableSchema {

    /// Create a new table schema

    pub fn new(name: String) -> Self {

        Self {

            name,

            columns: Vec::new(),

            primary_key: Vec::new(),

            metadata: HashMap::new(),

        }

    }



    /// Add a column

    pub fn add_column(mut self, column: ColumnInfo) -> Self {

        self.columns.push(column);

        self

    }



    /// Set primary key

    pub fn with_primary_key(mut self, primary_key: Vec<String>) -> Self {

        self.primary_key = primary_key;

        self

    }



    /// Add metadata

    pub fn with_metadata(mut self, key: String, value: String) -> Self {

        self.metadata.insert(key, value);

        self

    }



    /// Get column by name

    pub fn get_column(&self, name: &str) -> Option<&ColumnInfo> {

        self.columns.iter().find(|col| col.name == name)

    }

}



/// Prepared statement for repeated execution

#[async_trait]

pub trait PreparedStatement: Send + Sync + fmt::Debug {

    /// Execute the prepared statement with parameters

    async fn execute(&self, parameters: &[QueryParameter]) -> Result<QueryResult>;



    /// Get the parameter types

    fn parameter_types(&self) -> Vec<ParameterType>;



    /// Get the result column types

    fn result_column_types(&self) -> Vec<ColumnInfo>;

}



/// Trait for converting QueryParameter to specific types

pub trait TryFromQueryParameter: Sized {

    /// Try to convert from QueryParameter

    fn try_from(param: &QueryParameter) -> Result<Self>;

}



// Implement conversions for common types

impl TryFromQueryParameter for String {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::String(s) => Ok(s.clone()),

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to String",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to String", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for i64 {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Integer(i) => Ok(*i),

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Integer",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Integer", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for f64 {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Float(f) => Ok(*f),

            QueryParameter::Integer(i) => Ok(*i as f64),

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Float",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Float", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for bool {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Boolean(b) => Ok(*b),

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Boolean",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Boolean", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for Vec<u8> {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Binary(data) => Ok(data.clone()),

            QueryParameter::String(s) => Ok(s.as_bytes().to_vec()),

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Binary",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Binary", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for uuid::Uuid {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Uuid(uuid) => Ok(*uuid),

            QueryParameter::String(s) => {

                uuid::Uuid::parse_str(s)

                    .map_err(|_| FortressError::query_execution(

                        format!("Invalid UUID string: {}", s),

                        None,

                        QueryErrorCode::InvalidParameter,

                    ))

            }

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Uuid",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Uuid", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



impl TryFromQueryParameter for chrono::DateTime<chrono::Utc> {

    fn try_from(param: &QueryParameter) -> Result<Self> {

        match param {

            QueryParameter::Timestamp(dt) => Ok(*dt),

            QueryParameter::String(s) => {

                s.parse::<chrono::DateTime<chrono::Utc>>()

                    .map_err(|_| FortressError::query_execution(

                        format!("Invalid timestamp string: {}", s),

                        None,

                        QueryErrorCode::InvalidParameter,

                    ))

            }

            QueryParameter::Null => Err(FortressError::query_execution(

                "Cannot convert NULL to Timestamp",

                None,

                QueryErrorCode::InvalidParameter,

            )),

            _ => Err(FortressError::query_execution(

                format!("Cannot convert {:?} to Timestamp", param.param_type()),

                None,

                QueryErrorCode::InvalidParameter,

            )),

        }

    }

}



/// In-memory query engine for testing

#[derive(Debug)]

pub struct InMemoryQueryEngine {

    tables: std::sync::Arc<tokio::sync::RwLock<HashMap<String, TableSchema>>>,

    data: std::sync::Arc<tokio::sync::RwLock<HashMap<String, Vec<Row>>>>,

}



impl InMemoryQueryEngine {

    /// Create a new in-memory query engine

    pub fn new() -> Self {

        Self {

            tables: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),

            data: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),

        }

    }



    /// Create a table

    pub async fn create_table(&self, schema: TableSchema) -> Result<()> {

        let mut tables = self.tables.write().await;

        let mut data = self.data.write().await;

        

        tables.insert(schema.name.clone(), schema.clone());

        data.insert(schema.name, Vec::new());

        

        Ok(())

    }



    /// Insert data into a table

    pub async fn insert(&self, table_name: &str, row: Row) -> Result<()> {

        let mut data = self.data.write().await;

        let rows = data.get_mut(table_name)

            .ok_or_else(|| FortressError::query_execution(

                format!("Table not found: {}", table_name),

                None,

                QueryErrorCode::TableNotFound,

            ))?;

        

        rows.push(row);

        Ok(())

    }

}



impl Default for InMemoryQueryEngine {

    fn default() -> Self {

        Self::new()

    }

}



#[async_trait]

impl QueryEngine for InMemoryQueryEngine {

    async fn execute(&self, query: &str, _parameters: &[QueryParameter]) -> Result<QueryResult> {

        // This is a very basic implementation for testing

        let start = std::time::Instant::now();

        

        if query.trim().to_uppercase().starts_with("SELECT") {

            // Simple SELECT * FROM table_name parsing

            let parts: Vec<&str> = query.split_whitespace().collect();

            if parts.len() >= 4 && parts[1].to_uppercase() == "*" && parts[2].to_uppercase() == "FROM" {

                let table_name = parts[3];

                

                let tables = self.tables.read().await;

                let schema = tables.get(table_name)

                    .ok_or_else(|| FortressError::query_execution(

                        format!("Table not found: {}", table_name),

                        Some(query.to_string()),

                        QueryErrorCode::TableNotFound,

                    ))?;

                

                let data = self.data.read().await;

                let rows = data.get(table_name).unwrap_or(&vec![]).clone();

                

                let execution_time = start.elapsed().as_millis() as u64;

                

                return Ok(QueryResult {

                    rows,

                    columns: schema.columns.clone(),

                    total_rows: Some(rows.len() as u64),

                    execution_time_ms: execution_time,

                    metadata: QueryMetadata {

                        query_type: QueryType::Select,

                        tables_accessed: vec![table_name.to_string()],

                        read_only: true,

                        estimated_cost: Some(1.0),

                        metadata: HashMap::new(),

                    },

                });

            }

        }

        

        Err(FortressError::query_execution(

            "Unsupported query",

            Some(query.to_string()),

            QueryErrorCode::InvalidSyntax,

        ))

    }



    async fn parse(&self, query: &str) -> Result<ExecutionPlan> {

        // Simple parsing implementation

        Ok(ExecutionPlan {

            nodes: vec![PlanNode {

                node_type: PlanNodeType::TableScan,

                children: Vec::new(),

                parameters: HashMap::new(),

                estimated_cost: 1.0,

            }],

            estimated_cost: 1.0,

            metadata: HashMap::new(),

        })

    }



    async fn optimize(&self, plan: ExecutionPlan) -> Result<ExecutionPlan> {

        // For now, just return the plan as-is

        Ok(plan)

    }



    async fn explain(&self, query: &str) -> Result<ExecutionPlan> {

        self.parse(query).await

    }



    async fn get_table_schema(&self, table_name: &str) -> Result<TableSchema> {

        let tables = self.tables.read().await;

        tables.get(table_name)

            .cloned()

            .ok_or_else(|| FortressError::query_execution(

                format!("Table not found: {}", table_name),

                None,

                QueryErrorCode::TableNotFound,

            ))

    }



    async fn list_tables(&self) -> Result<Vec<String>> {

        let tables = self.tables.read().await;

        Ok(tables.keys().cloned().collect())

    }



    async fn prepare(&self, _query: &str) -> Result<Box<dyn PreparedStatement>> {

        Err(FortressError::query_execution(

            "Prepared statements not supported in in-memory engine",

            None,

            QueryErrorCode::InvalidOperation,

        ))

    }

}



#[cfg(test)]

mod tests {

    use super::*;



    #[tokio::test]

    async fn test_in_memory_query_engine() {

        let engine = InMemoryQueryEngine::new();

        

        // Create a table

        let schema = TableSchema::new("users".to_string())

            .add_column(ColumnInfo {

                name: "id".to_string(),

                column_type: ColumnType::Uuid,

                nullable: false,

                encrypted: false,

                size: None,

            })

            .add_column(ColumnInfo {

                name: "name".to_string(),

                column_type: ColumnType::Text,

                nullable: false,

                encrypted: false,

                size: None,

            })

            .with_primary_key(vec!["id".to_string()]);

        

        engine.create_table(schema).await.unwrap();

        

        // Insert data

        let row = Row::new(vec![

            QueryParameter::Uuid(uuid::Uuid::new_v4()),

            QueryParameter::String("Alice".to_string()),

        ]);

        engine.insert("users", row).await.unwrap();

        

        // Query data

        let result = engine.execute("SELECT * FROM users", &[]).await.unwrap();

        assert_eq!(result.rows.len(), 1);

        assert_eq!(result.columns.len(), 2);

        assert_eq!(result.total_rows, Some(1));

        

        // Test row access

        let row = &result.rows[0];

        let name: String = row.get_as(1).unwrap();

        assert_eq!(name, "Alice");

        

        let id: uuid::Uuid = row.get_as(0).unwrap();

        assert_eq!(row.get(0).unwrap().param_type(), ParameterType::Uuid);

    }



    #[test]

    fn test_query_parameter_conversions() {

        let string_param = QueryParameter::String("test".to_string());

        let converted: String = string_param.try_into().unwrap();

        assert_eq!(converted, "test");

        

        let int_param = QueryParameter::Integer(42);

        let converted: i64 = int_param.try_into().unwrap();

        assert_eq!(converted, 42);

        

        let float_param = QueryParameter::Float(3.14);

        let converted: f64 = float_param.try_into().unwrap();

        assert_eq!(converted, 3.14);

        

        let bool_param = QueryParameter::Boolean(true);

        let converted: bool = bool_param.try_into().unwrap();

        assert_eq!(converted, true);

    }



    #[test]

    fn test_table_schema() {

        let schema = TableSchema::new("test".to_string())

            .add_column(ColumnInfo {

                name: "id".to_string(),

                column_type: ColumnType::Uuid,

                nullable: false,

                encrypted: false,

                size: None,

            })

            .with_primary_key(vec!["id".to_string()]);

        

        assert_eq!(schema.name, "test");

        assert_eq!(schema.columns.len(), 1);

        assert_eq!(schema.primary_key, vec!["id"]);

        

        let column = schema.get_column("id").unwrap();

        assert_eq!(column.name, "id");

        assert_eq!(column.column_type, ColumnType::Uuid);

    }



    #[test]

    fn test_row_metadata() {

        let row = Row::new(vec![QueryParameter::String("test".to_string())])

            .with_metadata("source".to_string(), "test".to_string());

        

        assert_eq!(row.metadata.get("source"), Some(&"test".to_string()));

    }



    #[tokio::test]

    async fn test_query_engine_metadata() {

        let engine = InMemoryQueryEngine::new();

        

        let tables = engine.list_tables().await.unwrap();

        assert_eq!(tables.len(), 0);

        

        let schema = TableSchema::new("test".to_string());

        engine.create_table(schema).await.unwrap();

        

        let tables = engine.list_tables().await.unwrap();

        assert_eq!(tables.len(), 1);

        assert_eq!(tables[0], "test");

        

        let retrieved_schema = engine.get_table_schema("test").await.unwrap();

        assert_eq!(retrieved_schema.name, "test");

    }

}

