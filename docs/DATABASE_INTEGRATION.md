# Database Integration Guide

This guide provides comprehensive information about MongoDB and PostgreSQL integration in Fortress, including push/pull operations, performance optimizations, and best practices.

## Overview

Fortress supports multiple database backends with specialized implementations for MongoDB and PostgreSQL. These implementations provide:

- **Native database operations** with optimized performance
- **Push/Pull synchronization** between different database types
- **Advanced querying capabilities** including full-text search and JSONB operations
- **Replication and partitioning** support for enterprise deployments
- **Connection pooling** and performance monitoring

## MongoDB Integration

### Features

- **Bulk Operations**: High-performance bulk insert/update operations
- **Aggregation Pipeline**: Support for MongoDB's powerful aggregation framework
- **Full-Text Search**: Native text search with relevance scoring
- **GridFS Support**: Large file storage capabilities
- **Replica Set Support**: High availability with automatic failover
- **Change Streams**: Real-time data change notifications

### Configuration

```rust
use fortress_core::mongodb_database::{MongoConfig, MongoReadPreference, MongoWriteConcern};

let config = MongoConfig {
    connection_string: "mongodb://localhost:27017".to_string(),
    database_name: "fortress".to_string(),
    keys_collection: "fortress_keys".to_string(),
    data_collection: "fortress_data".to_string(),
    max_pool_size: 10,
    tls_enabled: false,
    auth_database: None,
    replica_set: Some("my_replica_set".to_string()),
    read_preference: MongoReadPreference::PrimaryPreferred,
    write_concern: MongoWriteConcern::Majority,
};
```

### Usage Examples

#### Basic Operations

```rust
use fortress_core::mongodb_database::MongoKeyDatabase;

// Create database instance
let mongo_db = MongoKeyDatabase::new(config).await?;
mongo_db.initialize().await?;

// Store data
let entries = vec![
    ("key1".to_string(), b"data1".to_vec(), HashMap::new()),
    ("key2".to_string(), b"data2".to_vec(), HashMap::new()),
];
let count = mongo_db.push_bulk(entries).await?;

// Retrieve data
let results = mongo_db.pull_filtered(MongoPullFilter::All).await?;
```

#### Advanced Operations

```rust
// Aggregation pipeline
let pipeline = MongoPipeline {
    operation: "count_by_type".to_string(),
    stages: vec![],
};
let results = mongo_db.aggregate(pipeline).await?;

// Full-text search
let search_results = mongo_db.text_search("search term", Some(10)).await?;
```

### Performance Optimizations

1. **Connection Pooling**: Configure appropriate pool size based on workload
2. **Bulk Operations**: Use bulk operations for better performance
3. **Indexing**: Create indexes on frequently queried fields
4. **Sharding**: Enable sharding for horizontal scaling
5. **Read Preferences**: Use appropriate read preferences for your use case

## PostgreSQL Integration

### Features

- **JSONB Support**: Native JSON document storage with indexing
- **Full-Text Search**: Advanced text search with ranking
- **Table Partitioning**: Automatic data partitioning by date, hash, or size
- **Streaming Replication**: Real-time replication support
- **COPY Operations**: High-performance bulk data loading
- **Window Functions**: Advanced analytics capabilities

### Configuration

```rust
use fortress_core::postgres_database::{PostgresConfig, PostgresPartitioning, PostgresReplicationConfig};

let config = PostgresConfig {
    connection_string: "postgresql://localhost:5432/fortress".to_string(),
    database_name: "fortress".to_string(),
    schema: "public".to_string(),
    keys_table: "fortress_keys".to_string(),
    data_table: "fortress_data".to_string(),
    max_connections: 20,
    connection_timeout_seconds: 30,
    ssl_enabled: true,
    log_statements: false,
    enable_pooling: true,
    partitioning: Some(PostgresPartitioning::ByDate { 
        column: "created_at".to_string(), 
        interval: "1 month".to_string() 
    }),
    replication: PostgresReplicationConfig {
        streaming_enabled: true,
        slot_name: Some("fortress_replication".to_string()),
        publication_name: Some("fortress_publication".to_string()),
        sync_mode: PostgresSyncMode::Synchronous,
    },
};
```

### Usage Examples

#### Basic Operations

```rust
use fortress_core::postgres_database::PostgresKeyDatabase;

// Create database instance
let postgres_db = PostgresKeyDatabase::new(config).await?;
postgres_db.initialize().await?;

// Bulk operations
let bulk_entries = vec![
    PostgresBulkEntry {
        key: "key1".to_string(),
        data: b"data1".to_vec(),
        metadata: HashMap::new(),
        content_type: "application/json".to_string(),
        encoding: "utf-8".to_string(),
        compression: "gzip".to_string(),
        partition_key: Some("2023-12".to_string()),
    },
];
let count = postgres_db.push_bulk_copy(bulk_entries).await?;

// Cursor-based queries
let query = PostgresQuery {
    key_filter: Some("prefix".to_string()),
    date_start: Some(chrono::Utc::now() - chrono::Duration::days(7)),
    date_end: Some(chrono::Utc::now()),
    min_size: Some(1024),
    max_size: Some(1024 * 1024),
    content_type: Some("application/json".to_string()),
    offset: Some(0),
    limit: Some(100),
};
let cursor = postgres_db.pull_cursor(query).await?;
```

#### Advanced Operations

```rust
// Full-text search
let search_results = postgres_db.full_text_search("search query", Some(20)).await?;

// JSONB queries
let jsonb_query = PostgresJsonbQuery::Contains {
    path: "metadata.tags",
    value: serde_json::Value::Array(vec![
        serde_json::Value::String("important".to_string())
    ]),
};
let results = postgres_db.jsonb_query(jsonb_query).await?;
```

### Performance Optimizations

1. **Connection Pooling**: Use PgBouncer for connection pooling
2. **Partitioning**: Enable table partitioning for large datasets
3. **Indexes**: Create appropriate B-tree and GIN indexes
4. **COPY Operations**: Use COPY for bulk data loading
5. **Vacuum**: Regular vacuum and analyze operations
6. **Work Mem**: Tune work_mem for complex queries

## Push/Pull Operations

### Overview

Push/Pull operations provide bidirectional synchronization between different database backends. They support:

- **Batch Processing**: Efficient processing of large datasets
- **Conflict Resolution**: Multiple strategies for handling conflicts
- **Progress Tracking**: Real-time progress updates
- **Cancellation**: Ability to cancel long-running operations
- **Incremental Sync**: Only transfer changed data

### Configuration

```rust
use fortress_core::push_pull_operations::{PushPullConfig, ConflictResolution};

let config = PushPullConfig {
    max_batch_size: 1000,
    max_concurrent_ops: 10,
    timeout_seconds: 300,
    enable_compression: true,
    conflict_resolution: ConflictResolution::Timestamp,
    enable_incremental: true,
    verify_checksums: true,
    enable_progress: true,
};
```

### Usage Examples

#### MongoDB to PostgreSQL Push

```rust
use fortress_core::push_pull_operations::{PushPullManager, PushRequest, StorageSource, StorageTarget, PushFilter};

let manager = PushPullManager::new(config);

let push_request = PushRequest {
    operation_id: "mongo_to_postgres_sync".to_string(),
    source: StorageSource::Mongo { config: mongo_config },
    target: StorageTarget::Postgres { config: postgres_config },
    filter: PushFilter::DateRange { 
        start: chrono::Utc::now() - chrono::Duration::hours(24),
        end: chrono::Utc::now(),
    },
    config: PushPullConfig::default(),
    started_at: chrono::Utc::now(),
};

let result = manager.push(push_request).await?;
println!("Pushed {} items", result.items_succeeded);
```

#### PostgreSQL to MongoDB Pull

```rust
use fortress_core::push_pull_operations::{PullRequest, PullFilter};

let pull_request = PullRequest {
    operation_id: "postgres_to_mongo_sync".to_string(),
    source: StorageSource::Postgres { config: postgres_config },
    target: StorageTarget::Mongo { config: mongo_config },
    filter: PullFilter::Incremental { 
        since: chrono::Utc::now() - chrono::Duration::hours(1),
    },
    config: PushPullConfig::default(),
    started_at: chrono::Utc::now(),
};

let result = manager.pull(pull_request).await?;
println!("Pulled {} items", result.items_succeeded);
```

### Conflict Resolution Strategies

1. **Timestamp**: Use the most recent version based on timestamps
2. **SourceWins**: Always prefer the source version
3. **TargetWins**: Always prefer the target version
4. **Manual**: Require manual intervention for conflicts
5. **Merge**: Attempt to merge both versions when possible

## Best Practices

### MongoDB

1. **Schema Design**: Use appropriate schema design for your data
2. **Indexing Strategy**: Create indexes based on query patterns
3. **Sharding Key**: Choose sharding keys carefully for even distribution
4. **Connection Management**: Use connection pooling and proper timeout settings
5. **Monitoring**: Monitor performance metrics and slow queries

### PostgreSQL

1. **Normalization**: Balance normalization with performance requirements
2. **Partitioning**: Use partitioning for large time-series or log data
3. **Vacuum Strategy**: Implement appropriate vacuum scheduling
4. **Index Maintenance**: Regularly maintain and rebuild indexes
5. **Connection Limits**: Set appropriate connection limits

### Push/Pull Operations

1. **Batch Size**: Tune batch size based on network and database capacity
2. **Incremental Sync**: Use incremental sync for large datasets
3. **Conflict Resolution**: Choose appropriate conflict resolution strategy
4. **Monitoring**: Monitor operation progress and performance
5. **Error Handling**: Implement proper error handling and retry logic

## Performance Tuning

### MongoDB Performance

```rust
// Optimize bulk operations
let config = MongoConfig {
    max_pool_size: 50,  // Increase for high throughput
    write_concern: MongoWriteConcern::Acknowledged,  // Use appropriate write concern
    read_preference: MongoReadPreference::SecondaryPreferred,  // Distribute read load
    // ... other config
};

// Use aggregation for complex queries
let pipeline = MongoPipeline {
    operation: "complex_analytics".to_string(),
    stages: vec![
        serde_json::json!({ "$match": { "status": "active" } }),
        serde_json::json!({ "$group": { "_id": "$category", "count": { "$sum": 1 } } }),
        serde_json::json!({ "$sort": { "count": -1 } }),
    ],
};
```

### PostgreSQL Performance

```rust
// Enable partitioning for large tables
let config = PostgresConfig {
    partitioning: Some(PostgresPartitioning::ByDate { 
        column: "created_at".to_string(), 
        interval: "1 day".to_string() 
    }),
    max_connections: 100,  // Increase for high concurrency
    // ... other config
};

// Use COPY for bulk operations
let bulk_entries = prepare_bulk_data();
let count = postgres_db.push_bulk_copy(bulk_entries).await?;
```

## Monitoring and Observability

### Metrics to Monitor

1. **Connection Pool Usage**: Active vs idle connections
2. **Query Performance**: Slow queries and execution times
3. **Replication Lag**: Replication delay between nodes
4. **Storage Usage**: Database size and growth rate
5. **Error Rates**: Failed operations and error types

### Health Checks

```rust
// MongoDB health check
let mongo_health = mongo_db.health_check().await?;

// PostgreSQL health check
let postgres_health = postgres_db.health_check().await?;

// Push/Pull operation status
let operation_status = manager.get_operation_status("operation_id").await?;
```

## Security Considerations

### Authentication

1. **MongoDB**: Use SCRAM-SHA-256 authentication
2. **PostgreSQL**: Use scram-sha-256 or certificate authentication
3. **Network**: Enable TLS/SSL for all connections
4. **Access Control**: Implement principle of least privilege

### Data Protection

1. **Encryption at Rest**: Enable database encryption
2. **Encryption in Transit**: Use TLS for all connections
3. **Key Management**: Use proper key rotation and management
4. **Audit Logging**: Enable comprehensive audit logging

## Troubleshooting

### Common Issues

1. **Connection Timeouts**: Increase timeout values or check network connectivity
2. **Memory Issues**: Tune database memory settings
3. **Slow Queries**: Add appropriate indexes or optimize queries
4. **Replication Lag**: Check network bandwidth and server resources
5. **Lock Contention**: Identify and resolve locking issues

### Debugging Tools

1. **MongoDB**: Use `mongostat`, `mongotop`, and explain plans
2. **PostgreSQL**: Use `pg_stat_statements`, `EXPLAIN ANALYZE`
3. **Fortress**: Use built-in logging and metrics
4. **Network**: Use network monitoring tools

## Migration Guide

### From MongoDB to PostgreSQL

1. **Schema Translation**: Convert MongoDB schema to PostgreSQL tables
2. **Data Type Mapping**: Map MongoDB types to PostgreSQL types
3. **Index Migration**: Convert MongoDB indexes to PostgreSQL indexes
4. **Query Translation**: Adapt MongoDB queries to PostgreSQL syntax
5. **Testing**: Thoroughly test migration with sample data

### From PostgreSQL to MongoDB

1. **Denormalization**: Convert normalized schema to document model
2. **Embedding Strategy**: Decide on embedding vs referencing
3. **Index Strategy**: Create appropriate MongoDB indexes
4. **Query Adaptation**: Adapt SQL queries to MongoDB aggregation
5. **Performance Testing**: Test performance with realistic workloads

## Examples

See the `examples/database_sync_example.rs` file for a comprehensive example demonstrating:

- Database initialization
- Push/pull operations between MongoDB and PostgreSQL
- Advanced database features
- Performance monitoring
- Error handling

## API Reference

For detailed API documentation, see the Rust documentation for:

- `fortress_core::mongodb_database`
- `fortress_core::postgres_database`
- `fortress_core::push_pull_operations`

## Support

For questions, issues, or contributions:

1. **Documentation**: Check this guide and API docs
2. **Issues**: File issues on the GitHub repository
3. **Discussions**: Use GitHub discussions for questions
4. **Contributions**: Follow the contribution guidelines
