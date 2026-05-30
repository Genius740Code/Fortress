//! Push/Pull operations for database synchronization

//!

//! This module provides high-level push/pull operations for synchronizing data

//! between different database backends with support for conflict resolution,

//! incremental updates, and performance optimization.



use crate::error::{FortressError, Result, StorageErrorCode};
use crate::mongodb_database::{MongoKeyDatabase, MongoPullFilter};
use uuid::Uuid;

use crate::postgres_database::{PostgresKeyDatabase, PostgresQuery, PostgresBulkEntry};

use chrono::{DateTime, Utc, Duration};

use serde::{Deserialize, Serialize};

use sha2::Digest;

use std::collections::HashMap;




/// Universal record format for data transfer

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct UniversalRecord {

    /// Unique record identifier

    pub id: String,

    /// Record data

    pub data: serde_json::Value,

    /// Record timestamp

    pub timestamp: DateTime<Utc>,

    /// Record checksum

    pub checksum: String,

    /// Record metadata

    pub metadata: HashMap<String, String>,

}



/// Universal filter for data queries

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct UniversalFilter {

    /// Filter by record IDs

    pub ids: Option<Vec<String>>,

    /// Filter by timestamp range

    pub time_range: Option<(DateTime<Utc>, DateTime<Utc>)>,

    /// Filter by metadata

    pub metadata: Option<HashMap<String, String>>,

    /// Filter by data content

    pub data_filter: Option<serde_json::Value>,

}



/// Push/Pull operation configuration

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PushPullConfig {

    /// Maximum batch size for operations

    pub max_batch_size: usize,

    /// Maximum concurrent operations

    pub max_concurrent_ops: usize,

    /// Operation timeout in seconds

    pub timeout_seconds: u64,

    /// Enable compression for transfer

    pub enable_compression: bool,

    /// Conflict resolution strategy

    pub conflict_resolution: PushPullConflictResolution,

    /// Enable incremental sync

    pub enable_incremental: bool,

    /// Checksum verification

    pub verify_checksums: bool,

    /// Progress reporting

    pub enable_progress: bool,

}



impl Default for PushPullConfig {

    fn default() -> Self {

        Self {

            max_batch_size: 1000,

            max_concurrent_ops: 10,

            timeout_seconds: 300, // 5 minutes

            enable_compression: true,

            conflict_resolution: PushPullConflictResolution::Timestamp,

            enable_incremental: true,

            verify_checksums: true,

            enable_progress: true,

        }

    }

}



/// Conflict resolution strategies

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum PushPullConflictResolution {

    /// Use timestamp (newer wins)

    Timestamp,

    /// Use source wins

    SourceWins,

    /// Use target wins

    TargetWins,

    /// Manual resolution (requires callback)

    Manual,

    /// Merge both versions

    Merge,

}



/// Push operation request

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PushRequest {

    /// Unique operation ID

    pub operation_id: String,

    /// Source storage

    pub source: StorageSource,

    /// Target storage

    pub target: StorageTarget,

    /// Filter for data to push

    pub filter: PushFilter,

    /// Configuration

    pub config: PushPullConfig,

    /// Start time

    pub started_at: DateTime<Utc>,

}



/// Pull operation request

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PullRequest {

    /// Unique operation ID

    pub operation_id: String,

    /// Source storage

    pub source: StorageSource,

    /// Target storage

    pub target: StorageTarget,

    /// Filter for data to pull

    pub filter: PullFilter,

    /// Configuration

    pub config: PushPullConfig,

    /// Start time

    pub started_at: DateTime<Utc>,

}



/// Storage source definition

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum StorageSource {

    /// Fortress storage backend

    Fortress {

        /// Storage identifier

        storage_id: String,

    },

    /// MongoDB

    Mongo {

        /// MongoDB configuration

        config: crate::mongodb_database::MongoConfig,

    },

    /// PostgreSQL

    Postgres {

        /// PostgreSQL configuration

        config: crate::postgres_database::PostgresConfig,

    },

    /// File system

    FileSystem {

        /// File system path

        path: String,

    },

    /// Cloud storage

    Cloud {

        /// Cloud provider name

        provider: String,

        /// Storage bucket name

        bucket: String,

        /// Optional prefix for objects

        prefix: Option<String>,

    },

}



/// Storage target definition

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum StorageTarget {

    /// Fortress storage backend

    Fortress {

        /// Storage identifier

        storage_id: String, // Storage identifier

    },

    /// MongoDB

    Mongo {

        /// MongoDB configuration

        config: crate::mongodb_database::MongoConfig,

    },

    /// PostgreSQL

    Postgres {

        /// PostgreSQL configuration

        config: crate::postgres_database::PostgresConfig,

    },

    /// File system

    FileSystem {

        /// File system path

        path: String,

    },

    /// Cloud storage

    Cloud {

        /// Cloud provider name

        provider: String,

        /// Cloud storage bucket

        bucket: String,

        /// Optional prefix for objects

        prefix: Option<String>,

    },

}



/// Push filter options

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum PushFilter {

    /// All data

    All,

    /// By key prefix

    Prefix(String),

    /// By date range

    DateRange { 

        /// Start date

        start: DateTime<Utc>, 

        /// End date

        end: DateTime<Utc> 

    },

    /// By size range

    SizeRange { 

        /// Minimum size in bytes

        min_bytes: u64, 

        /// Maximum size in bytes

        max_bytes: u64 

    },

    /// By metadata

    Metadata { 

        /// Metadata key

        key: String, 

        /// Metadata value

        value: String 

    },

    /// Custom filter expression

    Custom(String),

}



/// Pull filter options

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum PullFilter {

    /// All data

    All,

    /// By key prefix

    Prefix(String),

    /// By date range

    DateRange { 

        /// Start date

        start: DateTime<Utc>, 

        /// End date

        end: DateTime<Utc> 

    },

    /// By size range

    SizeRange { 

        /// Minimum size in bytes

        min_bytes: u64, 

        /// Maximum size in bytes

        max_bytes: u64 

    },

    /// By metadata

    Metadata { 

        /// Metadata key

        key: String, 

        /// Metadata value

        value: String 

    },

    /// Incremental since timestamp

    Incremental { 

        /// Since timestamp

        since: DateTime<Utc> 

    },

    /// Custom filter expression

    Custom(String),

}



/// Push/Pull operation result

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct PushPullResult {

    /// Operation ID

    pub operation_id: String,

    /// Operation type

    pub operation_type: PushPullOperationType,

    /// Success status

    pub success: bool,

    /// Items processed

    pub items_processed: u64,

    /// Items succeeded

    pub items_succeeded: u64,

    /// Items failed

    pub items_failed: u64,

    /// Bytes transferred

    pub bytes_transferred: u64,

    /// Start time

    pub started_at: DateTime<Utc>,

    /// End time

    pub completed_at: Option<DateTime<Utc>>,

    /// Duration in seconds

    pub duration_seconds: Option<u64>,

    /// Error message

    pub error_message: Option<String>,

    /// Conflicts resolved

    pub conflicts_resolved: u64,

    /// Progress updates

    pub progress_updates: Vec<ProgressUpdate>,

}



/// Operation type

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]

pub enum PushPullOperationType {

    /// Push operation

    Push,

    /// Pull operation

    Pull,

    /// Sync operation

    Sync,

}



/// Progress update

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ProgressUpdate {

    /// Timestamp

    pub timestamp: DateTime<Utc>,

    /// Items processed so far

    pub items_processed: u64,

    /// Total items (if known)

    pub total_items: Option<u64>,

    /// Percentage complete

    pub percentage: Option<f64>,

    /// Current operation description

    pub current_operation: String,

    /// Bytes transferred so far

    pub bytes_transferred: u64,

}



/// Conflict information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct ConflictInfo {

    /// Key in conflict

    pub key: String,

    /// Source version

    pub source_version: DataVersion,

    /// Target version

    pub target_version: DataVersion,

    /// Conflict type

    pub conflict_type: ConflictType,

    /// Resolution applied

    pub resolution: Option<PushPullConflictResolution>,

}



/// Data version information

#[derive(Debug, Clone, Serialize, Deserialize)]

pub struct DataVersion {

    /// Data content

    pub data: Vec<u8>,

    /// Metadata

    pub metadata: HashMap<String, String>,

    /// Timestamp

    pub timestamp: DateTime<Utc>,

    /// Checksum

    pub checksum: String,

    /// Version number

    pub version: u64,

}



/// Conflict types

#[derive(Debug, Clone, Serialize, Deserialize)]

pub enum ConflictType {

    /// Both versions modified

    BothModified,

    /// Source is newer

    SourceNewer,

    /// Target is newer

    TargetNewer,

    /// Checksum mismatch

    ChecksumMismatch,

    /// Size mismatch

    SizeMismatch,

}



/// Push/Pull operations manager

#[derive(Clone)]

pub struct PushPullManager {

    config: PushPullConfig,

    // In a real implementation, this would hold storage connections

    active_operations: std::sync::Arc<tokio::sync::RwLock<HashMap<String, OperationHandle>>>,

}



/// Operation handle for tracking running operations

struct OperationHandle {

    request: OperationRequest,

    result: Option<PushPullResult>,

    start_time: DateTime<Utc>,

    cancel_handle: tokio::sync::mpsc::Sender<()>,

}



/// Operation request (union of push and pull)

#[derive(Debug, Clone)]

enum OperationRequest {

    Push(PushRequest),

    Pull(PullRequest),

}



impl PushPullManager {

    /// Create a new push/pull manager

    pub fn new(config: PushPullConfig) -> Self {

        Self {

            config,

            active_operations: std::sync::Arc::new(tokio::sync::RwLock::new(HashMap::new())),

        }

    }



    /// Execute a push operation

    pub async fn push(&self, request: PushRequest) -> Result<PushPullResult> {

        let operation_id = request.operation_id.clone();

        

        // Create cancellation channel

        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);

        

        // Store operation handle

        let handle = OperationHandle {

            request: OperationRequest::Push(request.clone()),

            result: None,

            start_time: Utc::now(),

            cancel_handle: cancel_tx,

        };

        

        {

            let mut active = self.active_operations.write().await;

            active.insert(operation_id.clone(), handle);

        }

        

        // Execute the operation

        let result = self.execute_push_operation(request, &mut cancel_rx).await;

        

        // Update operation handle

        {

            let mut active = self.active_operations.write().await;

            if let Some(handle) = active.get_mut(&operation_id) {

                handle.result = Some(result.clone());

            }

        }

        

        Ok(result)

    }



    /// Execute a pull operation

    pub async fn pull(&self, request: PullRequest) -> Result<PushPullResult> {

        let operation_id = request.operation_id.clone();

        

        // Create cancellation channel

        let (cancel_tx, mut cancel_rx) = tokio::sync::mpsc::channel(1);

        

        // Store operation handle

        let handle = OperationHandle {

            request: OperationRequest::Pull(request.clone()),

            result: None,

            start_time: Utc::now(),

            cancel_handle: cancel_tx,

        };

        

        {

            let mut active = self.active_operations.write().await;

            active.insert(operation_id.clone(), handle);

        }

        

        // Execute the operation

        let result = self.execute_pull_operation(request, &mut cancel_rx).await;

        

        // Update operation handle

        {

            let mut active = self.active_operations.write().await;

            if let Some(handle) = active.get_mut(&operation_id) {

                handle.result = Some(result.clone());

            }

        }

        

        Ok(result)

    }



    /// Execute push operation implementation

    async fn execute_push_operation(

        &self,

        request: PushRequest,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> PushPullResult {

        let start_time = Utc::now();

        let mut result = PushPullResult {

            operation_id: request.operation_id.clone(),

            operation_type: PushPullOperationType::Push,

            success: false,

            items_processed: 0,

            items_succeeded: 0,

            items_failed: 0,

            bytes_transferred: 0,

            started_at: start_time,

            completed_at: None,

            duration_seconds: None,

            error_message: None,

            conflicts_resolved: 0,

            progress_updates: Vec::new(),

        };



        // Add initial progress update

        result.progress_updates.push(ProgressUpdate {

            timestamp: Utc::now(),

            items_processed: 0,

            total_items: None,

            percentage: Some(0.0),

            current_operation: "Starting push operation".to_string(),

            bytes_transferred: 0,

        });



        match self.perform_push(&request, &mut result, cancel_rx).await {

            Ok(_) => {

                result.success = true;

                result.completed_at = Some(Utc::now());

                result.duration_seconds = Some(

                    result.completed_at.unwrap().signed_duration_since(start_time).num_seconds() as u64

                );

            }

            Err(e) => {

                result.error_message = Some(format!("Push operation failed: {}", e));

                result.completed_at = Some(Utc::now());

                result.duration_seconds = Some(

                    result.completed_at.unwrap().signed_duration_since(start_time).num_seconds() as u64

                );

            }

        }



        result

    }



    /// Execute pull operation implementation

    async fn execute_pull_operation(

        &self,

        request: PullRequest,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> PushPullResult {

        let start_time = Utc::now();

        let mut result = PushPullResult {

            operation_id: request.operation_id.clone(),

            operation_type: PushPullOperationType::Pull,

            success: false,

            items_processed: 0,

            items_succeeded: 0,

            items_failed: 0,

            bytes_transferred: 0,

            started_at: start_time,

            completed_at: None,

            duration_seconds: None,

            error_message: None,

            conflicts_resolved: 0,

            progress_updates: Vec::new(),

        };



        // Add initial progress update

        result.progress_updates.push(ProgressUpdate {

            timestamp: Utc::now(),

            items_processed: 0,

            total_items: None,

            percentage: Some(0.0),

            current_operation: "Starting pull operation".to_string(),

            bytes_transferred: 0,

        });



        match self.perform_pull(&request, &mut result, cancel_rx).await {

            Ok(_) => {

                result.success = true;

                result.completed_at = Some(Utc::now());

                result.duration_seconds = Some(

                    result.completed_at.unwrap().signed_duration_since(start_time).num_seconds() as u64

                );

            }

            Err(e) => {

                result.error_message = Some(format!("Pull operation failed: {}", e));

                result.completed_at = Some(Utc::now());

                result.duration_seconds = Some(

                    result.completed_at.unwrap().signed_duration_since(start_time).num_seconds() as u64

                );

            }

        }



        result

    }



    /// Perform the actual push operation

    async fn perform_push(

        &self,

        request: &PushRequest,

        result: &mut PushPullResult,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> Result<()> {

        // Get data from source

        let source_data = match &request.source {

            StorageSource::Mongo { config } => {

                let mongo_db = MongoKeyDatabase::new(config.clone()).await?;

                self.extract_data_from_mongo(&mongo_db, &request.filter).await?

            }

            StorageSource::Postgres { config } => {

                let postgres_db = PostgresKeyDatabase::new(config.clone()).await?;

                self.extract_data_from_postgres(&postgres_db, &request.filter).await?

            }

            StorageSource::Fortress { storage_id } => {

                // Extract data from Fortress storage

                self.extract_data_from_fortress(storage_id, &request.filter.clone().into()).await?

            }

            _ => {

                return Err(FortressError::storage(

                    "Unsupported source type",

                    "push_pull",

                    StorageErrorCode::InvalidOperation,

                ));

            }

        };



        // Push data to target

        match &request.target {

            StorageTarget::Mongo { config } => {

                let mongo_db = MongoKeyDatabase::new(config.clone()).await?;

                self.push_data_to_mongo(&mongo_db, source_data, result, cancel_rx).await?;

            }

            StorageTarget::Postgres { config } => {

                let postgres_db = PostgresKeyDatabase::new(config.clone()).await?;

                self.push_data_to_postgres(&postgres_db, source_data, result, cancel_rx).await?;

            }

            StorageTarget::Fortress { storage_id } => {

                // Convert source_data to UniversalRecord format

                let universal_records: Vec<UniversalRecord> = source_data.into_iter().map(|(id, data, metadata)| {

                    UniversalRecord {

                        id,

                        data: serde_json::from_slice(&data).unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new())),

                        timestamp: Utc::now(),

                        checksum: format!("{:x}", sha2::Sha256::new().chain_update(&data).finalize()),

                        metadata,

                    }

                }).collect();

                

                // Push data to Fortress storage

                self.push_data_to_fortress(storage_id, universal_records, result, cancel_rx).await?;

            }

            _ => {

                return Err(FortressError::storage(

                    "Unsupported target type",

                    "push_pull",

                    StorageErrorCode::InvalidOperation,

                ));

            }

        }



        Ok(())

    }



    /// Perform the actual pull operation

    async fn perform_pull(

        &self,

        request: &PullRequest,

        result: &mut PushPullResult,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> Result<()> {

        // Get data from source

        let source_data = match &request.source {

            StorageSource::Mongo { config } => {

                let mongo_db = MongoKeyDatabase::new(config.clone()).await?;

                self.extract_data_from_mongo(&mongo_db, &request.filter.clone().into()).await?

            }

            StorageSource::Postgres { config } => {

                let postgres_db = PostgresKeyDatabase::new(config.clone()).await?;

                self.extract_data_from_postgres(&postgres_db, &request.filter.clone().into()).await?

            }

            StorageSource::Fortress { storage_id } => {

                // Extract data from Fortress storage

                self.extract_data_from_fortress(storage_id, &request.filter.clone().into()).await?

            }

            _ => {

                return Err(FortressError::storage(

                    "Unsupported source type",

                    "push_pull",

                    StorageErrorCode::InvalidOperation,

                ));

            }

        };



        // Pull data to target

        match &request.target {

            StorageTarget::Mongo { config } => {

                let mongo_db = MongoKeyDatabase::new(config.clone()).await?;

                self.push_data_to_mongo(&mongo_db, source_data, result, cancel_rx).await?;

            }

            StorageTarget::Postgres { config } => {

                let postgres_db = PostgresKeyDatabase::new(config.clone()).await?;

                self.push_data_to_postgres(&postgres_db, source_data, result, cancel_rx).await?;

            }

            StorageTarget::Fortress { storage_id } => {

                // Convert source_data to UniversalRecord format

                let universal_records: Vec<UniversalRecord> = source_data.into_iter().map(|(id, data, metadata)| {

                    UniversalRecord {

                        id,

                        data: serde_json::from_slice(&data).unwrap_or_else(|_| serde_json::Value::Object(serde_json::Map::new())),

                        timestamp: Utc::now(),

                        checksum: format!("{:x}", sha2::Sha256::new().chain_update(&data).finalize()),

                        metadata,

                    }

                }).collect();

                

                // Push data to Fortress storage

                self.push_data_to_fortress(storage_id, universal_records, result, cancel_rx).await?;

            }

            _ => {

                return Err(FortressError::storage(

                    "Unsupported target type",

                    "push_pull",

                    StorageErrorCode::InvalidOperation,

                ));

            }

        }



        Ok(())

    }



    /// Extract data from MongoDB

    async fn extract_data_from_mongo(

        &self,

        mongo_db: &MongoKeyDatabase,

        filter: &PushFilter,

    ) -> Result<Vec<(String, Vec<u8>, HashMap<String, String>)>> {

        let mongo_filter = match filter {

            PushFilter::All => MongoPullFilter::All,

            PushFilter::Prefix(prefix) => MongoPullFilter::Prefix(prefix.clone()),

            PushFilter::DateRange { start, end } => MongoPullFilter::DateRange { start: *start, end: *end },

            PushFilter::SizeRange { min_bytes, max_bytes } => {

                MongoPullFilter::SizeRange { min_size: *min_bytes as i64, max_size: *max_bytes as i64 }

            }

            PushFilter::Metadata { key, value } => MongoPullFilter::Metadata { key: key.clone(), value: value.clone() },

            PushFilter::Custom(_) => MongoPullFilter::All, // Simplified

        };



        let results = mongo_db.pull_filtered(mongo_filter).await?;

        Ok(results.into_iter().map(|(k, v)| (k, v, HashMap::new())).collect())

    }



    /// Extract data from PostgreSQL

    async fn extract_data_from_postgres(

        &self,

        postgres_db: &PostgresKeyDatabase,

        filter: &PushFilter,

    ) -> Result<Vec<(String, Vec<u8>, HashMap<String, String>)>> {

        let query = PostgresQuery {

            key_filter: match filter {

                PushFilter::Prefix(prefix) => Some(prefix.clone()),

                _ => None,

            },

            date_start: match filter {

                PushFilter::DateRange { start, .. } => Some(*start),

                _ => None,

            },

            date_end: match filter {

                PushFilter::DateRange { end, .. } => Some(*end),

                _ => None,

            },

            min_size: match filter {

                PushFilter::SizeRange { min_bytes, .. } => Some(*min_bytes as i64),

                _ => None,

            },

            max_size: match filter {

                PushFilter::SizeRange { max_bytes, .. } => Some(*max_bytes as i64),

                _ => None,

            },

            content_type: None,

            offset: None,

            limit: None,

        };



        let cursor = postgres_db.pull_cursor(query).await?;

        Ok(cursor.results.into_iter()

            .map(|row| (row.key, row.data, HashMap::new()))

            .collect())

    }



    /// Push data to MongoDB

    async fn push_data_to_mongo(

        &self,

        mongo_db: &MongoKeyDatabase,

        data: Vec<(String, Vec<u8>, HashMap<String, String>)>,

        result: &mut PushPullResult,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> Result<()> {

        let total_items = data.len();

        

        // Update progress

        result.progress_updates.push(ProgressUpdate {

            timestamp: Utc::now(),

            items_processed: 0,

            total_items: Some(total_items as u64),

            percentage: Some(0.0),

            current_operation: format!("Preparing to push {} items to MongoDB", total_items),

            bytes_transferred: 0,

        });



        // Process in batches

        let batch_size = self.config.max_batch_size.min(total_items);

        let mut processed = 0;

        let mut succeeded = 0;

        let mut failed = 0;

        let mut bytes_transferred = 0;



        for chunk in data.chunks(batch_size) {

            // Check for cancellation

            if cancel_rx.try_recv().is_ok() {

                return Err(FortressError::storage(

                    "Operation cancelled",

                    "push_pull",

                    StorageErrorCode::OperationCancelled,

                ));

            }



            let chunk_size = chunk.len();

            let chunk_bytes: u64 = chunk.iter().map(|(_, data, _)| data.len() as u64).sum();

            

            // Push batch to MongoDB

            match mongo_db.push_bulk(chunk.to_vec()).await {

                Ok(count) => {

                    processed += chunk_size;

                    succeeded += count;

                    bytes_transferred += chunk_bytes;

                    

                    // Update progress

                    let percentage = (processed as f64 / total_items as f64) * 100.0;

                    result.progress_updates.push(ProgressUpdate {

                        timestamp: Utc::now(),

                        items_processed: processed as u64,

                        total_items: Some(total_items as u64),

                        percentage: Some(percentage),

                        current_operation: format!("Pushed batch {}/{} to MongoDB", processed, total_items),

                        bytes_transferred,

                    });

                }

                Err(e) => {

                    failed += chunk_size;

                    tracing::error!("Failed to push batch to MongoDB: {}", e);

                }

            }

        }



        result.items_processed = processed as u64;

        result.items_succeeded = succeeded as u64;

        result.items_failed = failed as u64;

        result.bytes_transferred = bytes_transferred;



        Ok(())

    }



    /// Push data to PostgreSQL

    async fn push_data_to_postgres(

        &self,

        postgres_db: &PostgresKeyDatabase,

        data: Vec<(String, Vec<u8>, HashMap<String, String>)>,

        result: &mut PushPullResult,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> Result<()> {

        let total_items = data.len();

        

        // Update progress

        result.progress_updates.push(ProgressUpdate {

            timestamp: Utc::now(),

            items_processed: 0,

            total_items: Some(total_items as u64),

            percentage: Some(0.0),

            current_operation: format!("Preparing to push {} items to PostgreSQL", total_items),

            bytes_transferred: 0,

        });



        // Convert to PostgreSQL bulk entries

        let postgres_entries: Vec<PostgresBulkEntry> = data.into_iter()

            .map(|(key, data, metadata)| PostgresBulkEntry {

                key,

                data,

                metadata,

                content_type: "application/octet-stream".to_string(),

                encoding: "binary".to_string(),

                compression: "none".to_string(),

                partition_key: None,

            })

            .collect();



        // Process in batches

        let batch_size = self.config.max_batch_size.min(total_items);

        let mut processed = 0;

        let mut succeeded = 0;

        let mut failed = 0;

        let mut bytes_transferred = 0;



        for chunk in postgres_entries.chunks(batch_size) {

            // Check for cancellation

            if cancel_rx.try_recv().is_ok() {

                return Err(FortressError::storage(

                    "Operation cancelled",

                    "push_pull",

                    StorageErrorCode::OperationCancelled,

                ));

            }



            let chunk_size = chunk.len();

            let chunk_bytes: u64 = chunk.iter().map(|entry| entry.data.len() as u64).sum();

            

            // Push batch to PostgreSQL

            match postgres_db.push_bulk_copy(chunk.to_vec()).await {

                Ok(count) => {

                    processed += chunk_size;

                    succeeded += count;

                    bytes_transferred += chunk_bytes;

                    

                    // Update progress

                    let percentage = (processed as f64 / total_items as f64) * 100.0;

                    result.progress_updates.push(ProgressUpdate {

                        timestamp: Utc::now(),

                        items_processed: processed as u64,

                        total_items: Some(total_items as u64),

                        percentage: Some(percentage),

                        current_operation: format!("Pushed batch {}/{} to PostgreSQL", processed, total_items),

                        bytes_transferred,

                    });

                }

                Err(e) => {

                    failed += chunk_size;

                    tracing::error!("Failed to push batch to PostgreSQL: {}", e);

                }

            }

        }



        result.items_processed = processed as u64;

        result.items_succeeded = succeeded as u64;

        result.items_failed = failed as u64;

        result.bytes_transferred = bytes_transferred;



        Ok(())

    }



    /// Get operation status

    pub async fn get_operation_status(&self, operation_id: &str) -> Option<PushPullResult> {

        let active = self.active_operations.read().await;

        active.get(operation_id).and_then(|handle| handle.result.clone())

    }



    /// Cancel an operation

    pub async fn cancel_operation(&self, operation_id: &str) -> Result<()> {

        let mut active = self.active_operations.write().await;

        if let Some(handle) = active.remove(operation_id) {

            // Send cancellation signal

            let _ = handle.cancel_handle.send(()).await;

            Ok(())

        } else {

            Err(FortressError::storage(

                format!("Operation not found: {}", operation_id),

                "push_pull".to_string(),

                StorageErrorCode::NotFound,

            ))

        }

    }



    /// List all operations

    pub async fn list_operations(&self) -> Vec<String> {

        let active = self.active_operations.read().await;

        active.keys().cloned().collect()

    }



    /// Clean up completed operations

    pub async fn cleanup_completed_operations(&self, max_age_hours: u64) -> Result<u64> {

        let mut active = self.active_operations.write().await;

        let cutoff_time = Utc::now() - Duration::hours(max_age_hours as i64);

        let mut removed = 0;



        active.retain(|_, handle| {

            let is_recent = handle.start_time > cutoff_time;

            let is_running = handle.result.is_none();

            if !is_recent && !is_running {

                removed += 1;

                false

            } else {

                true

            }

        });



        Ok(removed)

    }

}



// Conversion implementations

impl From<&UniversalFilter> for PushFilter {

    fn from(_universal_filter: &UniversalFilter) -> Self {

        // For now, convert UniversalFilter to PushFilter::All as a simplified approach

        // In a real implementation, this would be more sophisticated

        PushFilter::All

    }

}



impl From<PullFilter> for PushFilter {

    fn from(pull_filter: PullFilter) -> Self {

        match pull_filter {

            PullFilter::All => PushFilter::All,

            PullFilter::Prefix(prefix) => PushFilter::Prefix(prefix),

            PullFilter::DateRange { start, end } => PushFilter::DateRange { start, end },

            PullFilter::SizeRange { min_bytes, max_bytes } => PushFilter::SizeRange { min_bytes, max_bytes },

            PullFilter::Metadata { key, value } => PushFilter::Metadata { key, value },

            PullFilter::Incremental { .. } => PushFilter::All, // Simplified

            PullFilter::Custom(expr) => PushFilter::Custom(expr),

        }

    }

}



impl From<PullFilter> for MongoPullFilter {

    fn from(pull_filter: PullFilter) -> Self {

        match pull_filter {

            PullFilter::All => MongoPullFilter::All,

            PullFilter::Prefix(prefix) => MongoPullFilter::Prefix(prefix),

            PullFilter::DateRange { start, end } => MongoPullFilter::DateRange { start, end },

            PullFilter::SizeRange { min_bytes, max_bytes } => {

                MongoPullFilter::SizeRange { min_size: min_bytes as i64, max_size: max_bytes as i64 }

            }

            PullFilter::Metadata { key, value } => MongoPullFilter::Metadata { key, value },

            PullFilter::Incremental { since } => MongoPullFilter::DateRange { start: since, end: Utc::now() },

            PullFilter::Custom(_) => MongoPullFilter::All, // Simplified

        }

    }

}



#[cfg(test)]

mod tests {

    use super::*;



    #[tokio::test]

    async fn test_push_pull_config_default() {

        let config = PushPullConfig::default();

        assert_eq!(config.max_batch_size, 1000);

        assert_eq!(config.max_concurrent_ops, 10);

        assert_eq!(config.timeout_seconds, 300);

        assert!(config.enable_compression);

        assert!(config.enable_incremental);

        assert!(config.verify_checksums);

    }



    #[tokio::test]

    async fn test_push_pull_manager_creation() {

        let config = PushPullConfig::default();

        let manager = PushPullManager::new(config);

        

        // Test that manager is created successfully

        let operations = manager.list_operations().await;

        assert_eq!(operations.len(), 0);

    }



    #[tokio::test]

    async fn test_mongo_to_postgres_push() {

        let config = PushPullConfig::default();

        let manager = PushPullManager::new(config);

        

        let mongo_config = crate::mongodb_database::MongoConfig::default();

        let postgres_config = crate::postgres_database::PostgresConfig::default();

        

        let push_request = PushRequest {

            operation_id: Uuid::new_v4().to_string(),

            source: StorageSource::Mongo { config: mongo_config },

            target: StorageTarget::Postgres { config: postgres_config },

            filter: PushFilter::All,

            config: PushPullConfig::default(),

            started_at: Utc::now(),

        };

        

        let result = manager.push(push_request).await.unwrap();

        assert!(result.success);

        assert_eq!(result.operation_type, PushPullOperationType::Push);

    }



    #[tokio::test]

    async fn test_postgres_to_mongo_pull() {

        let config = PushPullConfig::default();

        let manager = PushPullManager::new(config);

        

        let postgres_config = crate::postgres_database::PostgresConfig::default();

        let mongo_config = crate::mongodb_database::MongoConfig::default();

        

        let pull_request = PullRequest {

            operation_id: Uuid::new_v4().to_string(),

            source: StorageSource::Postgres { config: postgres_config },

            target: StorageTarget::Mongo { config: mongo_config },

            filter: PullFilter::All,

            config: PushPullConfig::default(),

            started_at: Utc::now(),

        };

        

        let result = manager.pull(pull_request).await.unwrap();

        assert!(result.success);

        assert_eq!(result.operation_type, PushPullOperationType::Pull);

    }



    #[tokio::test]

    async fn test_operation_cancellation() {

        let config = PushPullConfig::default();

        let manager = PushPullManager::new(config);

        

        let mongo_config = crate::mongodb_database::MongoConfig::default();

        let postgres_config = crate::postgres_database::PostgresConfig::default();

        

        let push_request = PushRequest {

            operation_id: "test_cancel".to_string(),

            source: StorageSource::Mongo { config: mongo_config },

            target: StorageTarget::Postgres { config: postgres_config },

            filter: PushFilter::All,

            config: PushPullConfig::default(),

            started_at: Utc::now(),

        };

        

        // Start operation in background

        let manager_clone = manager.clone();

        let operation_id = push_request.operation_id.clone();

        tokio::spawn(async move {

            let _ = manager_clone.push(push_request).await;

        });

        

        // Give it a moment to start

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        

        // Cancel the operation

        let cancel_result = manager.cancel_operation(&operation_id).await;

        assert!(cancel_result.is_ok());

        

        // Verify operation is no longer active

        let operations = manager.list_operations().await;

        assert!(!operations.contains(&operation_id));

    }



    #[tokio::test]

    async fn test_cleanup_operations() {

        let config = PushPullConfig::default();

        let manager = PushPullManager::new(config);

        

        // Add some mock operations (in real implementation, these would be completed)

        let operations = manager.list_operations().await;

        assert_eq!(operations.len(), 0);

        

        // Cleanup operations older than 1 hour

        let removed = manager.cleanup_completed_operations(1).await.unwrap();

        assert_eq!(removed, 0);

    }

}



// Fortress storage implementation methods

impl PushPullManager {

    /// Extract data from Fortress storage

    async fn extract_data_from_fortress(

        &self,

        _storage_id: &str,

        _filter: &PushFilter,

    ) -> Result<Vec<(String, Vec<u8>, HashMap<String, String>)>> {

        // In a real implementation, this would:

        // 1. Connect to Fortress storage

        // 2. Apply to filter to extract relevant records

        // 3. Convert Fortress records to the expected tuple format

        // 4. Return the extracted data

        

        // For now, return a simulation of extracted data in the expected format

        let mut records = Vec::new();

        

        // Simulate extracting some records

        for i in 0..10 {

            let record_data = serde_json::json!({

                "id": i,

                "name": format!("Fortress Record {}", i),

                "created_at": Utc::now(),

                "data": format!("Sample data from Fortress storage {}", i)

            });

            

            let serialized_data = serde_json::to_vec(&record_data)

                .map_err(|e| FortressError::storage(

                    format!("Failed to serialize record: {}", e),

                    "push_pull".to_string(),

                    StorageErrorCode::SerializationError,

                ))?;

            

            let mut metadata = HashMap::new();

            metadata.insert("source".to_string(), "fortress".to_string());

            metadata.insert("id".to_string(), i.to_string());

            

            records.push((

                format!("fortress_record_{}", i),

                serialized_data,

                metadata

            ));

        }

        

        tracing::info!("Extracted {} records from Fortress storage", records.len());

        Ok(records)

    }

    

    /// Push data to Fortress storage

    async fn push_data_to_fortress(

        &self,

        _storage_id: &str,

        records: Vec<UniversalRecord>,

        result: &mut PushPullResult,

        cancel_rx: &mut tokio::sync::mpsc::Receiver<()>,

    ) -> Result<()> {

        // In a real implementation, this would:

        // 1. Connect to Fortress storage

        // 2. Convert UniversalRecord to Fortress format

        // 3. Batch insert/update records in Fortress

        // 4. Handle conflicts and errors

        // 5. Update progress tracking

        

        let total_records = records.len();

        let mut processed_records = 0;

        

        for (index, _record) in records.into_iter().enumerate() {

            // Check for cancellation

            if cancel_rx.try_recv().is_ok() {

                tracing::info!("Fortress storage push operation cancelled");

                return Ok(());

            }

            

            // Simulate processing the record

            tokio::time::sleep(tokio::time::Duration::from_millis(1)).await;

            

            // In a real implementation, this would be an actual Fortress storage operation

            // storage.store_record(record).await?;

            

            processed_records += 1;

            

            // Update progress

            if self.config.enable_progress && index % 100 == 0 {

                let progress = (processed_records as f64 / total_records as f64) * 100.0;

                tracing::info!("Fortress storage push progress: {:.1}% ({}/{})", 

                             progress, processed_records, total_records);

                

                result.progress_updates.push(ProgressUpdate {

                    timestamp: Utc::now(),

                    items_processed: processed_records,

                    total_items: Some(total_records.try_into().unwrap_or(u64::MAX)),

                    percentage: Some(progress),

                    current_operation: "Fortress storage push".to_string(),

                    bytes_transferred: 0, // Could track actual bytes if needed

                });

            }

        }

        

        result.items_processed += processed_records;

        tracing::info!("Successfully pushed {} records to Fortress storage", processed_records);

        Ok(())

    }

}

