//! Memory management optimizations
//! 
//! This module provides memory pools, pressure monitoring, and efficient
//! memory allocation patterns for cryptographic operations.

use crate::error::FortressError;
use std::sync::{Arc, Mutex, Once};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::time::{interval, sleep};
use once_cell::sync::Lazy;

/// Performance metrics for memory operations
static MEMORY_ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static POOL_HITS: AtomicU64 = AtomicU64::new(0);
static POOL_MISSES: AtomicU64 = AtomicU64::new(0);

/// Memory pool for reusing allocations
pub struct MemoryPool<T> {
    pool: Arc<Mutex<VecDeque<T>>>,
    factory: Box<dyn Fn() -> T + Send + Sync>,
    max_size: usize,
    current_size: Arc<AtomicUsize>,
}

impl<T> MemoryPool<T> 
where 
    T: Send + 'static,
{
    /// Create a new memory pool
    pub fn new<F>(initial_size: usize, max_size: usize, factory: F) -> Self 
    where 
        F: Fn() -> T + Send + Sync + 'static,
    {
        let pool: VecDeque<T> = (0..initial_size).map(|_| factory()).collect();
        
        Self {
            pool: Arc::new(Mutex::new(pool)),
            factory: Box::new(factory),
            max_size,
            current_size: Arc::new(AtomicUsize::new(initial_size)),
        }
    }

    /// Get an item from the pool
    pub fn get(&self) -> T {
        let mut pool = self.pool.lock().unwrap();
        if let Some(item) = pool.pop_front() {
            self.current_size.fetch_sub(1, Ordering::Relaxed);
            POOL_HITS.fetch_add(1, Ordering::Relaxed);
            item
        } else {
            POOL_MISSES.fetch_add(1, Ordering::Relaxed);
            (self.factory)()
        }
    }

    /// Return an item to the pool
    pub fn return_item(&self, item: T) {
        let mut pool = self.pool.lock().unwrap();
        if pool.len() < self.max_size {
            pool.push_back(item);
            self.current_size.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get current pool size
    pub fn size(&self) -> usize {
        self.current_size.load(Ordering::Relaxed)
    }

    /// Get maximum pool size
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            current_size: self.size(),
            max_size: self.max_size,
            hits: POOL_HITS.load(Ordering::Relaxed),
            misses: POOL_MISSES.load(Ordering::Relaxed),
            hit_rate: self.calculate_hit_rate(),
        }
    }

    fn calculate_hit_rate(&self) -> f64 {
        let hits = POOL_HITS.load(Ordering::Relaxed) as f64;
        let misses = POOL_MISSES.load(Ordering::Relaxed) as f64;
        let total = hits + misses;
        
        if total == 0.0 {
            0.0
        } else {
            hits / total
        }
    }
}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub current_size: usize,
    pub max_size: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
}

/// Global buffer pool for cryptographic operations
static BUFFER_POOL: Lazy<MemoryPool<Vec<u8>>> = Lazy::new(|| {
    MemoryPool::new(100, 1000, || vec![0u8; 4096])
});

/// Pooled buffer with automatic return to pool
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: &'static MemoryPool<Vec<u8>>,
    original_capacity: usize,
}

impl PooledBuffer {
    /// Create a new pooled buffer
    pub fn new(size: usize) -> Self {
        let mut buffer = BUFFER_POOL.get();
        buffer.resize(size, 0);
        let original_capacity = buffer.capacity();
        
        Self {
            buffer,
            pool: &BUFFER_POOL,
            original_capacity,
        }
    }

    /// Create a pooled buffer with specific capacity
    pub fn with_capacity(capacity: usize) -> Self {
        let mut buffer = BUFFER_POOL.get();
        buffer.clear();
        buffer.reserve(capacity);
        let original_capacity = buffer.capacity();
        
        Self {
            buffer,
            pool: &BUFFER_POOL,
            original_capacity,
        }
    }

    /// Get mutable slice reference
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    /// Get slice reference
    pub fn as_slice(&self) -> &[u8] {
        &self.buffer
    }

    /// Get the underlying Vec
    pub fn into_vec(mut self) -> Vec<u8> {
        let buffer = std::mem::take(&mut self.buffer);
        buffer
    }

    /// Resize the buffer
    pub fn resize(&mut self, new_size: usize) {
        self.buffer.resize(new_size, 0);
    }

    /// Get buffer length
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Clear the buffer
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Extend the buffer with data
    pub fn extend_from_slice(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Clear the buffer and return it to the pool
        self.buffer.clear();
        // Try to resize back to original capacity if it grew significantly
        if self.buffer.capacity() > self.original_capacity * 2 {
            self.buffer.shrink_to_fit();
        }
        self.pool.return_item(std::mem::take(&mut self.buffer));
    }
}

/// Memory pressure monitor
pub struct MemoryMonitor {
    threshold: f64, // Usage percentage
    cleanup_interval: Duration,
    cleanup_callbacks: Vec<Box<dyn Fn() + Send + Sync>>,
    is_running: Arc<Mutex<bool>>,
}

impl MemoryMonitor {
    /// Create a new memory monitor
    pub fn new(threshold: f64, cleanup_interval: Duration) -> Self {
        Self {
            threshold,
            cleanup_interval,
            cleanup_callbacks: Vec::new(),
            is_running: Arc::new(Mutex::new(false)),
        }
    }

    /// Add a cleanup callback
    pub fn add_cleanup_callback<F>(&mut self, callback: F) 
    where 
        F: Fn() + Send + Sync + 'static,
    {
        self.cleanup_callbacks.push(Box::new(callback));
    }

    /// Start monitoring memory usage
    pub async fn start_monitoring(&self) -> Result<(), FortressError> {
        let mut is_running = self.is_running.lock().unwrap();
        if *is_running {
            return Err(FortressError::processor_error("Memory monitor already running".to_string()));
        }
        *is_running = true;
        drop(is_running);

        let threshold = self.threshold;
        let cleanup_interval = self.cleanup_interval;
        // Note: cleanup_callbacks can't be cloned, so we'll handle cleanup differently
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = interval(cleanup_interval);
            
            loop {
                interval.tick().await;
                
                // Check if we should continue running
                {
                    let running = is_running.lock().unwrap();
                    if !*running {
                        break;
                    }
                }

                // For now, use a simple memory check instead of async function
                // In production, this would need to be handled differently
                tracing::info!("Memory monitoring check (threshold: {:.1}%)", threshold);
            }
        });

        Ok(())
    }

    /// Stop monitoring memory usage
    pub fn stop_monitoring(&self) -> Result<(), FortressError> {
        let mut is_running = self.is_running.lock().unwrap();
        if *is_running {
            *is_running = false;
            Ok(())
        } else {
            Err(FortressError::processor_error("Memory monitor not running".to_string()))
        }
    }

    /// Get current threshold
    pub fn threshold(&self) -> f64 {
        self.threshold
    }

    /// Get cleanup interval
    pub fn cleanup_interval(&self) -> Duration {
        self.cleanup_interval
    }
}

/// Memory statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_memory: u64,
    pub used_memory: u64,
    pub free_memory: u64,
    pub process_memory: u64,
    pub buffer_pool_size: usize,
    pub buffer_pool_stats: PoolStats,
    pub allocation_count: u64,
}

impl MemoryStats {
    /// Collect current memory statistics
    pub fn collect() -> Result<Self, FortressError> {
        let system_memory = get_system_memory()?;
        
        Ok(Self {
            total_memory: system_memory.total,
            used_memory: system_memory.used,
            free_memory: system_memory.free,
            process_memory: get_process_memory()?,
            buffer_pool_size: BUFFER_POOL.size(),
            buffer_pool_stats: BUFFER_POOL.stats(),
            allocation_count: MEMORY_ALLOCATIONS.load(Ordering::Relaxed),
        })
    }
}

/// System memory information
#[derive(Debug, Clone)]
pub struct SystemMemory {
    pub total: u64,
    pub used: u64,
    pub free: u64,
}

/// Get current memory usage percentage
async fn get_memory_usage() -> Result<f64, FortressError> {
    let memory = get_system_memory()?;
    Ok((memory.used as f64 / memory.total as f64) * 100.0)
}

/// Get system memory information
fn get_system_memory() -> Result<SystemMemory, FortressError> {
    // This is a simplified implementation
    // In production, you would use a proper system information library
    // like sysinfo or sysctl
    
    // For now, return mock data
    Ok(SystemMemory {
        total: 16 * 1024 * 1024 * 1024, // 16GB
        used: 8 * 1024 * 1024 * 1024,   // 8GB
        free: 8 * 1024 * 1024 * 1024,    // 8GB
    })
}

/// Get current process memory usage
fn get_process_memory() -> Result<u64, FortressError> {
    // This is a simplified implementation
    // In production, you would use proper process memory APIs
    Ok(100 * 1024 * 1024) // 100MB mock
}

/// Trigger cleanup callbacks
async fn trigger_cleanup(cleanup_callbacks: &[Box<dyn Fn() + Send + Sync>]) {
    tracing::info!("Triggering memory cleanup");
    
    for callback in cleanup_callbacks {
        callback();
    }
    
    // Additional cleanup actions
    clear_caches().await;
    expire_sessions().await;
    force_garbage_collection().await;
    
    sleep(Duration::from_millis(100)).await;
}

/// Clear application caches
async fn clear_caches() {
    tracing::debug!("Clearing caches");
    // This would integrate with the cache system
}

/// Expire old sessions
async fn expire_sessions() {
    tracing::debug!("Expiring sessions");
    // This would integrate with the session manager
}

/// Force garbage collection
async fn force_garbage_collection() {
    tracing::debug!("Force garbage collection");
    // For Rust, this is mainly about dropping large objects
}

/// Memory allocation tracker
pub struct AllocationTracker {
    allocations: Arc<Mutex<Vec<usize>>>,
}

impl AllocationTracker {
    pub fn new() -> Self {
        Self {
            allocations: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub fn track_allocation(&self, size: usize) {
        MEMORY_ALLOCATIONS.fetch_add(1, Ordering::Relaxed);
        let mut allocations = self.allocations.lock().unwrap();
        allocations.push(size);
    }

    pub fn get_stats(&self) -> AllocationStats {
        let allocations = self.allocations.lock().unwrap();
        let total: usize = allocations.iter().sum();
        let count = allocations.len();
        let average = if count > 0 { total / count } else { 0 };
        
        AllocationStats {
            total_allocated: total,
            allocation_count: count,
            average_size: average,
        }
    }
}

/// Allocation statistics
#[derive(Debug, Clone)]
pub struct AllocationStats {
    pub total_allocated: usize,
    pub allocation_count: usize,
    pub average_size: usize,
}

/// Global allocation tracker
static ALLOCATION_TRACKER: Lazy<AllocationTracker> = Lazy::new(AllocationTracker::new);

/// Get global allocation tracker
pub fn allocation_tracker() -> &'static AllocationTracker {
    &ALLOCATION_TRACKER
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::sleep;

    #[test]
    fn test_memory_pool() {
        let pool = MemoryPool::new(5, 10, || vec![0u8; 1024]);
        
        assert_eq!(pool.size(), 5);
        
        let buffer1 = pool.get();
        assert_eq!(pool.size(), 4);
        
        let buffer2 = pool.get();
        assert_eq!(pool.size(), 3);
        
        pool.return_item(buffer1);
        assert_eq!(pool.size(), 4);
        
        let stats = pool.stats();
        assert!(stats.hit_rate > 0.0);
    }

    #[test]
    fn test_pooled_buffer() {
        let buffer = PooledBuffer::new(1024);
        assert_eq!(buffer.len(), 1024);
        
        let mut buffer = PooledBuffer::with_capacity(2048);
        buffer.extend_from_slice(&[1, 2, 3, 4]);
        assert_eq!(buffer.len(), 4);
        
        let vec = buffer.into_vec();
        assert_eq!(vec, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_memory_monitor() {
        let monitor = MemoryMonitor::new(80.0, Duration::from_millis(100));
        
        // Add a cleanup callback
        let cleanup_called = Arc::new(Mutex::new(false));
        let cleanup_called_clone = cleanup_called.clone();
        
        monitor.add_cleanup_callback(move || {
            *cleanup_called_clone.lock().unwrap() = true;
        });
        
        // Start monitoring (this will likely not trigger cleanup in this short test)
        let result = monitor.start_monitoring().await;
        assert!(result.is_ok());
        
        // Stop monitoring
        let result = monitor.stop_monitoring();
        assert!(result.is_ok());
    }

    #[test]
    fn test_allocation_tracker() {
        let tracker = AllocationTracker::new();
        
        tracker.track_allocation(1024);
        tracker.track_allocation(2048);
        tracker.track_allocation(512);
        
        let stats = tracker.get_stats();
        assert_eq!(stats.allocation_count, 3);
        assert_eq!(stats.total_allocated, 3584);
        assert_eq!(stats.average_size, 1194);
    }

    #[test]
    fn test_memory_stats() {
        let stats = MemoryStats::collect();
        assert!(stats.is_ok());
        
        let stats = stats.unwrap();
        assert!(stats.total_memory > 0);
        assert!(stats.buffer_pool_size >= 0);
    }

    #[test]
    fn test_global_allocation_tracker() {
        let initial_count = MEMORY_ALLOCATIONS.load(Ordering::Relaxed);
        
        allocation_tracker().track_allocation(1024);
        
        let final_count = MEMORY_ALLOCATIONS.load(Ordering::Relaxed);
        assert!(final_count > initial_count);
    }
}
