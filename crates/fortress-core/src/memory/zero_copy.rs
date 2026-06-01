//! Zero-Copy Data Structures
//!
//! This module provides zero-copy data structures and operations to minimize
//! memory allocations and improve performance in hot paths.

use crate::error::Result;
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Zero-copy data type for efficient string handling
pub type ZeroCopyString = Cow<'static, str>;

/// Zero-copy data type for efficient byte handling
pub type ZeroCopyBytes = Cow<'static, [u8]>;

/// Zero-copy vector that avoids unnecessary allocations
#[derive(Debug, Clone)]
pub struct ZeroCopyVec<T> {
    data: Arc<Vec<T>>,
}

impl<T> ZeroCopyVec<T> {
    /// Create a new zero-copy vector
    pub fn new(data: Vec<T>) -> Self {
        Self {
            data: Arc::new(data),
        }
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[T] {
        &self.data
    }

    /// Get the length of the vector
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the vector is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over the elements
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.data.iter()
    }
}

impl<T> From<Vec<T>> for ZeroCopyVec<T> {
    fn from(data: Vec<T>) -> Self {
        Self::new(data)
    }
}

/// Zero-copy map for efficient key-value operations
#[derive(Debug, Clone)]
pub struct ZeroCopyMap<K, V> {
    data: Arc<HashMap<K, V>>,
}

impl<K, V> ZeroCopyMap<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    /// Create a new zero-copy map
    pub fn new(data: HashMap<K, V>) -> Self {
        Self {
            data: Arc::new(data),
        }
    }

    /// Create a new zero-copy map with default values
    pub fn default() -> Self {
        Self::new(HashMap::new())
    }

    /// Get a value by key
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }

    /// Check if the map contains a key
    pub fn contains_key(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }

    /// Get the number of entries
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the map is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get an iterator over key-value pairs
    pub fn iter(&self) -> std::collections::hash_map::Iter<'_, K, V> {
        self.data.iter()
    }

    /// Get an iterator over keys
    pub fn keys(&self) -> std::collections::hash_map::Keys<'_, K, V> {
        self.data.keys()
    }

    /// Get an iterator over values
    pub fn values(&self) -> std::collections::hash_map::Values<'_, K, V> {
        self.data.values()
    }
}

impl<K, V> From<HashMap<K, V>> for ZeroCopyMap<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    fn from(data: HashMap<K, V>) -> Self {
        Self::new(data)
    }
}

/// Zero-copy buffer for efficient data processing
#[derive(Debug, Clone)]
pub struct ZeroCopyBuffer {
    data: Bytes,
}

impl ZeroCopyBuffer {
    /// Create a new zero-copy buffer
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data: Bytes::from(data),
        }
    }

    /// Create a zero-copy buffer from bytes
    pub fn from_bytes(data: Bytes) -> Self {
        Self { data }
    }

    /// Get a slice of the data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get the length of the buffer
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a slice of the data at the specified range
    pub fn slice(&self, range: std::ops::Range<usize>) -> ZeroCopyBuffer {
        Self {
            data: self.data.slice(range),
        }
    }

    /// Split the buffer at the specified index
    pub fn split_at(&self, mid: usize) -> (ZeroCopyBuffer, ZeroCopyBuffer) {
        let (left, right) = self.data.split_at(mid);
        (
            ZeroCopyBuffer {
                data: Bytes::copy_from_slice(left),
            },
            ZeroCopyBuffer {
                data: Bytes::copy_from_slice(right),
            },
        )
    }
}

impl From<Vec<u8>> for ZeroCopyBuffer {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<Bytes> for ZeroCopyBuffer {
    fn from(data: Bytes) -> Self {
        Self::from_bytes(data)
    }
}

/// Zero-copy string builder for efficient string operations
#[derive(Debug, Clone)]
pub struct ZeroCopyStringBuilder {
    buffer: BytesMut,
}

impl ZeroCopyStringBuilder {
    /// Create a new zero-copy string builder
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Create a zero-copy string builder with initial capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buffer: BytesMut::with_capacity(capacity),
        }
    }

    /// Append a string slice
    pub fn append_str(&mut self, s: &str) -> &mut Self {
        self.buffer.extend_from_slice(s.as_bytes());
        self
    }

    /// Append bytes
    pub fn append_bytes(&mut self, bytes: &[u8]) -> &mut Self {
        self.buffer.extend_from_slice(bytes);
        self
    }

    /// Append another zero-copy buffer
    pub fn append_buffer(&mut self, buffer: &ZeroCopyBuffer) -> &mut Self {
        self.buffer.extend_from_slice(buffer.as_slice());
        self
    }

    /// Build the final string
    pub fn build(self) -> ZeroCopyString {
        ZeroCopyString::Owned(String::from_utf8_lossy(&self.buffer).into_owned())
    }

    /// Build the final bytes
    pub fn build_bytes(self) -> ZeroCopyBuffer {
        ZeroCopyBuffer::new(self.buffer.to_vec())
    }

    /// Get the current length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the builder is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the builder
    pub fn clear(&mut self) {
        self.buffer.clear();
    }
}

impl Default for ZeroCopyStringBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Zero-copy manager for coordinating zero-copy operations
pub struct ZeroCopyManager {
    metrics: Arc<RwLock<ZeroCopyMetrics>>,
    string_cache: Arc<RwLock<HashMap<String, ZeroCopyString>>>,
    buffer_cache: Arc<RwLock<HashMap<usize, ZeroCopyBuffer>>>,
}

/// Zero-copy operation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroCopyMetrics {
    /// Total zero-copy operations
    pub total_operations: u64,
    /// Memory saved through zero-copy (in bytes)
    pub memory_saved_bytes: u64,
    /// String cache hits
    pub string_cache_hits: u64,
    /// String cache misses
    pub string_cache_misses: u64,
    /// Buffer cache hits
    pub buffer_cache_hits: u64,
    /// Buffer cache misses
    pub buffer_cache_misses: u64,
    /// Average operation time in microseconds
    pub avg_operation_time_us: f64,
    /// Last updated timestamp
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl ZeroCopyManager {
    /// Create a new zero-copy manager
    pub fn new() -> Result<Self> {
        Ok(Self {
            metrics: Arc::new(RwLock::new(ZeroCopyMetrics::default())),
            string_cache: Arc::new(RwLock::new(HashMap::new())),
            buffer_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Create a zero-copy string with caching
    pub async fn create_string(&self, s: String) -> Result<ZeroCopyString> {
        let start = std::time::Instant::now();

        // Check cache first
        {
            let cache = self.string_cache.read().await;
            if let Some(cached) = cache.get(&s) {
                let mut metrics = self.metrics.write().await;
                metrics.string_cache_hits += 1;
                metrics.total_operations += 1;
                metrics.avg_operation_time_us = (metrics.avg_operation_time_us
                    * (metrics.total_operations - 1) as f64
                    + start.elapsed().as_micros() as f64)
                    / metrics.total_operations as f64;
                return Ok(cached.clone());
            }
        }

        // Create new zero-copy string
        let zero_copy_str = ZeroCopyString::Owned(s.clone());

        // Add to cache
        {
            let mut cache = self.string_cache.write().await;
            cache.insert(s.clone(), zero_copy_str.clone());
        }

        let mut metrics = self.metrics.write().await;
        metrics.string_cache_misses += 1;
        metrics.total_operations += 1;
        metrics.memory_saved_bytes += s.len() as u64;
        metrics.avg_operation_time_us = (metrics.avg_operation_time_us
            * (metrics.total_operations - 1) as f64
            + start.elapsed().as_micros() as f64)
            / metrics.total_operations as f64;

        Ok(zero_copy_str)
    }

    /// Create a zero-copy buffer with caching
    pub async fn create_buffer(&self, data: Vec<u8>) -> Result<ZeroCopyBuffer> {
        let start = std::time::Instant::now();
        let size = data.len();

        // Check cache first
        {
            let cache = self.buffer_cache.read().await;
            if let Some(cached) = cache.get(&size) {
                let mut metrics = self.metrics.write().await;
                metrics.buffer_cache_hits += 1;
                metrics.total_operations += 1;
                metrics.avg_operation_time_us = (metrics.avg_operation_time_us
                    * (metrics.total_operations - 1) as f64
                    + start.elapsed().as_micros() as f64)
                    / metrics.total_operations as f64;
                return Ok(cached.clone());
            }
        }

        // Create new zero-copy buffer
        let zero_copy_buffer = ZeroCopyBuffer::new(data);

        // Add to cache
        {
            let mut cache = self.buffer_cache.write().await;
            cache.insert(size, zero_copy_buffer.clone());
        }

        let mut metrics = self.metrics.write().await;
        metrics.buffer_cache_misses += 1;
        metrics.total_operations += 1;
        metrics.memory_saved_bytes += size as u64;
        metrics.avg_operation_time_us = (metrics.avg_operation_time_us
            * (metrics.total_operations - 1) as f64
            + start.elapsed().as_micros() as f64)
            / metrics.total_operations as f64;

        Ok(zero_copy_buffer)
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> Result<ZeroCopyMetrics> {
        let metrics = self.metrics.read().await;
        Ok(metrics.clone())
    }

    /// Clear caches
    pub async fn clear_caches(&self) -> Result<()> {
        self.string_cache.write().await.clear();
        self.buffer_cache.write().await.clear();
        Ok(())
    }

    /// Optimize caches (remove least recently used items)
    pub async fn optimize_caches(&self, max_cache_size: usize) -> Result<()> {
        // Optimize string cache
        {
            let mut cache = self.string_cache.write().await;
            if cache.len() > max_cache_size {
                // Remove oldest entries (simple LRU simulation)
                let keys_to_remove: Vec<String> = cache
                    .keys()
                    .take(cache.len() - max_cache_size)
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }

        // Optimize buffer cache
        {
            let mut cache = self.buffer_cache.write().await;
            if cache.len() > max_cache_size {
                let keys_to_remove: Vec<usize> = cache
                    .keys()
                    .take(cache.len() - max_cache_size)
                    .cloned()
                    .collect();
                for key in keys_to_remove {
                    cache.remove(&key);
                }
            }
        }

        Ok(())
    }
}

impl Default for ZeroCopyMetrics {
    fn default() -> Self {
        Self {
            total_operations: 0,
            memory_saved_bytes: 0,
            string_cache_hits: 0,
            string_cache_misses: 0,
            buffer_cache_hits: 0,
            buffer_cache_misses: 0,
            avg_operation_time_us: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_copy_vec() {
        let data = vec![1, 2, 3, 4, 5];
        let zero_copy_vec = ZeroCopyVec::new(data);

        assert_eq!(zero_copy_vec.len(), 5);
        assert!(!zero_copy_vec.is_empty());
        assert_eq!(zero_copy_vec.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_zero_copy_map() {
        let mut data = HashMap::new();
        data.insert("key1".to_string(), "value1");
        data.insert("key2".to_string(), "value2");

        let zero_copy_map = ZeroCopyMap::new(data);

        assert_eq!(zero_copy_map.len(), 2);
        assert!(zero_copy_map.contains_key(&"key1".to_string()));
        assert_eq!(zero_copy_map.get(&"key1".to_string()), Some(&"value1"));
    }

    #[test]
    fn test_zero_copy_buffer() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = ZeroCopyBuffer::new(data);

        assert_eq!(buffer.len(), 5);
        assert!(!buffer.is_empty());
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_zero_copy_string_builder() {
        let mut builder = ZeroCopyStringBuilder::new();
        builder.append_str("Hello, ").append_str("World!");

        let result = builder.build();
        assert_eq!(result.as_ref(), "Hello, World!");
    }

    #[tokio::test]
    async fn test_zero_copy_manager() {
        let manager = ZeroCopyManager::new().unwrap();

        let string = manager.create_string("test".to_string()).await.unwrap();
        assert_eq!(string.as_ref(), "test");

        let buffer = manager.create_buffer(vec![1, 2, 3, 4, 5]).await.unwrap();
        assert_eq!(buffer.as_slice(), &[1, 2, 3, 4, 5]);

        let metrics = manager.get_metrics().await.unwrap();
        assert_eq!(metrics.total_operations, 2);
    }
}
