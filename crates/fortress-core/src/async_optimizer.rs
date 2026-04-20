//! Async Operations Optimizer
//!
//! This module provides utilities for optimizing synchronous operations
//! in async contexts to prevent thread pool starvation and improve performance.

use crate::error::{FortressError, Result};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::task;

/// Async-friendly CPU-intensive operation executor
pub struct AsyncOptimizer;

impl AsyncOptimizer {
    /// Execute CPU-intensive operation in blocking thread pool
    pub async fn execute_cpu_intensive<F, R>(&self, operation: F) -> Result<R>
    where
        F: FnOnce() -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let result = task::spawn_blocking(operation).await
            .map_err(|e| FortressError::internal("Failed to spawn blocking task", Some(e.to_string())))?;
        
        result
    }

    /// Execute multiple CPU-intensive operations in parallel
    pub async fn execute_parallel<F, R>(&self, operations: Vec<F>) -> Vec<Result<R>>
    where
        F: FnOnce() -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let futures: Vec<_> = operations.into_iter()
            .map(|op| task::spawn_blocking(op))
            .collect();
        
        let mut results = Vec::new();
        for future in futures {
            match future.await {
                Ok(result) => results.push(result),
                Err(e) => results.push(Err(FortressError::internal("Failed to spawn blocking task", Some(e.to_string())))),
            }
        }
        
        results
    }

    /// Execute with timeout for CPU-intensive operations
    pub async fn execute_with_timeout<F, R>(&self, operation: F, timeout: Duration) -> Result<R>
    where
        F: FnOnce() -> Result<R> + Send + 'static,
        R: Send + 'static,
    {
        let task_future = task::spawn_blocking(operation);
        
        match tokio::time::timeout(timeout, task_future).await {
            Ok(result) => {
                result.map_err(|e| FortressError::internal("Failed to spawn blocking task", Some(e.to_string())))?
            }
            Err(_) => {
                Err(FortressError::timeout("CPU-intensive operation timed out", Some(timeout.to_string())))
            }
        }
    }

    /// Batch process items with controlled concurrency
    pub async fn batch_process<F, I, R>(&self, items: Vec<I>, processor: F, batch_size: usize) -> Vec<Result<R>>
    where
        F: Fn(Vec<I>) -> Result<Vec<R>> + Send + 'static + Clone,
        I: Send + 'static,
        R: Send + 'static,
    {
        let mut results = Vec::new();
        let mut chunks = items.chunks(batch_size);
        
        // Process chunks in parallel with controlled concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(4)); // Max 4 concurrent tasks
        let mut tasks = Vec::new();
        
        while let Some(chunk) = chunks.next() {
            let chunk = chunk.to_vec();
            let processor = processor.clone();
            let semaphore = semaphore.clone();
            
            let task = task::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                task::spawn_blocking(move || processor(chunk)).await
            });
            
            tasks.push(task);
        }
        
        // Collect results
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => results.push(Err(FortressError::internal("Batch processing failed", Some(e.to_string())))),
                Err(e) => results.push(Err(FortressError::internal("Task failed", Some(e.to_string())))),
            }
        }
        
        // Flatten results
        results.into_iter().flatten().collect()
    }
}

/// Async-friendly iterator for CPU-intensive operations
pub struct AsyncIterator<I, R> {
    items: Vec<I>,
    processor: fn(I) -> Result<R>,
    batch_size: usize,
}

impl<I, R> AsyncIterator<I, R>
where
    I: Send + 'static,
    R: Send + 'static,
{
    pub fn new(items: Vec<I>, processor: fn(I) -> Result<R>, batch_size: usize) -> Self {
        Self {
            items,
            processor,
            batch_size,
        }
    }

    /// Process all items asynchronously
    pub async fn process_all(self) -> Vec<Result<R>> {
        let optimizer = AsyncOptimizer;
        let processor_fn = move |items: Vec<I>| -> Result<Vec<R>> {
            let mut results = Vec::new();
            for item in items {
                results.push((self.processor)(item)?);
            }
            Ok(results)
        };
        
        optimizer.batch_process(self.items, processor_fn, self.batch_size).await
    }

    /// Process items with error recovery
    pub async fn process_with_recovery(self, recovery_fn: fn(I, &FortressError) -> Result<R>) -> Vec<Result<R>> {
        let optimizer = AsyncOptimizer;
        let processor_fn = move |items: Vec<I>| -> Result<Vec<R>> {
            let mut results = Vec::new();
            for item in items {
                match (self.processor)(item) {
                    Ok(result) => results.push(Ok(result)),
                    Err(e) => {
                        // Try recovery
                        if let Ok(recovered) = recovery_fn(items[0].clone(), &e) {
                            results.push(Ok(recovered));
                        } else {
                            results.push(Err(e));
                        }
                    }
                }
            }
            Ok(results)
        };
        
        optimizer.batch_process(self.items, processor_fn, self.batch_size).await
    }
}

/// Async-friendly map-reduce implementation
pub struct AsyncMapReduce;

impl AsyncMapReduce {
    /// Map phase - apply function to items in parallel
    pub async fn map<I, M, F>(&self, items: Vec<I>, mapper: F) -> Vec<Result<M>>
    where
        I: Send + 'static,
        M: Send + 'static,
        F: Fn(I) -> Result<M> + Send + 'static + Clone,
    {
        let optimizer = AsyncOptimizer;
        let map_fn = move |chunk: Vec<I>| -> Result<Vec<M>> {
            let mut results = Vec::new();
            for item in chunk {
                results.push(mapper.clone()(item)?);
            }
            Ok(results)
        };
        
        optimizer.batch_process(items, map_fn, 10).await
    }

    /// Reduce phase - combine results
    pub async fn reduce<R, F>(&self, items: Vec<R>, reducer: F, initial_value: R) -> Result<R>
    where
        R: Send + 'static + Clone,
        F: Fn(R, R) -> Result<R> + Send + 'static,
    {
        let optimizer = AsyncOptimizer;
        let reduce_fn = move |chunk: Vec<R>| -> Result<R> {
            let mut acc = initial_value.clone();
            for item in chunk {
                acc = reducer(acc, item)?;
            }
            Ok(acc)
        };
        
        let mut results = optimizer.batch_process(items, reduce_fn, 10).await;
        
        // Combine all partial results
        let mut final_result = initial_value;
        for result in results.drain(..) {
            final_result = reducer(final_result, result?)?;
        }
        
        Ok(final_result)
    }

    /// Full map-reduce operation
    pub async fn execute<I, M, R, MapF, ReduceF>(
        &self,
        items: Vec<I>,
        mapper: MapF,
        reducer: ReduceF,
        initial_value: R,
    ) -> Result<R>
    where
        I: Send + 'static,
        M: Send + 'static,
        R: Send + 'static + Clone,
        MapF: Fn(I) -> Result<M> + Send + 'static + Clone,
        ReduceF: Fn(R, R) -> Result<R> + Send + 'static,
    {
        let mapped_results = self.map(items, mapper).await;
        
        // Filter out errors and collect successful results
        let successful_mapped: Vec<M> = mapped_results
            .into_iter()
            .filter_map(|result| result.ok())
            .collect();
        
        self.reduce(successful_mapped, reducer, initial_value).await
    }
}

/// Performance monitor for async operations
pub struct AsyncPerformanceMonitor {
    operation_times: Arc<tokio::sync::RwLock<Vec<Duration>>>,
    operation_counts: Arc<tokio::sync::RwLock<HashMap<String, u64>>>,
}

impl AsyncPerformanceMonitor {
    pub fn new() -> Self {
        Self {
            operation_times: Arc::new(tokio::sync::RwLock::new(Vec::new())),
            operation_counts: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Record operation performance
    pub async fn record_operation(&self, operation_name: &str, duration: Duration) {
        // Record timing
        self.operation_times.write().await.push(duration);
        
        // Keep only last 1000 measurements
        if self.operation_times.read().await.len() > 1000 {
            let mut times = self.operation_times.write().await;
            times.drain(0..times.len() - 1000);
        }
        
        // Update count
        let mut counts = self.operation_counts.write().await;
        *counts.entry(operation_name.to_string()).or_insert(0) += 1;
    }

    /// Get performance statistics
    pub async fn get_stats(&self) -> AsyncPerformanceStats {
        let times = self.operation_times.read().await;
        let counts = self.operation_counts.read().await;
        
        if times.is_empty() {
            return AsyncPerformanceStats {
                total_operations: 0,
                average_duration: Duration::ZERO,
                p95_duration: Duration::ZERO,
                p99_duration: Duration::ZERO,
                operation_counts: counts.clone(),
            };
        }
        
        let total_duration: Duration = times.iter().sum();
        let average_duration = total_duration / times.len() as u32;
        
        // Calculate percentiles
        let mut sorted_times = times.clone();
        sorted_times.sort();
        
        let p95_index = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_index = (sorted_times.len() as f64 * 0.99) as usize;
        
        let p95_duration = sorted_times.get(p95_index).cloned().unwrap_or(Duration::ZERO);
        let p99_duration = sorted_times.get(p99_index).cloned().unwrap_or(Duration::ZERO);
        
        AsyncPerformanceStats {
            total_operations: times.len() as u64,
            average_duration,
            p95_duration,
            p99_duration,
            operation_counts: counts.clone(),
        }
    }
}

/// Performance statistics for async operations
#[derive(Debug, Clone)]
pub struct AsyncPerformanceStats {
    pub total_operations: u64,
    pub average_duration: Duration,
    pub p95_duration: Duration,
    pub p99_duration: Duration,
    pub operation_counts: HashMap<String, u64>,
}

/// Macro for easy async optimization
#[macro_export]
macro_rules! async_cpu_intensive {
    ($operation:expr) => {
        $crate::async_optimizer::AsyncOptimizer.execute_cpu_intensive($operation).await
    };
    ($operation:expr, $timeout:expr) => {
        $crate::async_optimizer::AsyncOptimizer.execute_with_timeout($operation, $timeout).await
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_cpu_intensive_operation() {
        let optimizer = AsyncOptimizer;
        
        let result = optimizer.execute_cpu_intensive(|| {
            // Simulate CPU-intensive work
            let mut sum = 0u64;
            for i in 0..1_000_000 {
                sum = sum.wrapping_add(i);
            }
            Ok(sum)
        }).await;
        
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[tokio::test]
    async fn test_parallel_execution() {
        let optimizer = AsyncOptimizer;
        
        let operations: Vec<_> = (0..10).map(|i| {
            move || -> Result<u64> {
                // Simulate varying workloads
                let mut sum = 0u64;
                for j in 0..(i + 1) * 100_000 {
                    sum = sum.wrapping_add(j);
                }
                Ok(sum)
            }
        }).collect();
        
        let results = optimizer.execute_parallel(operations).await;
        
        assert_eq!(results.len(), 10);
        for result in results {
            assert!(result.is_ok());
        }
    }

    #[tokio::test]
    async fn test_timeout_operation() {
        let optimizer = AsyncOptimizer;
        
        let result = optimizer.execute_with_timeout(
            || {
                // Simulate long-running operation
                std::thread::sleep(Duration::from_millis(200));
                Ok("completed")
            },
            Duration::from_millis(100)
        ).await;
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), FortressError::Timeout { .. }));
    }

    #[tokio::test]
    async fn test_batch_processing() {
        let optimizer = AsyncOptimizer;
        
        let items: Vec<i32> = (0..100).collect();
        let processor = |batch: Vec<i32>| -> Result<Vec<i32>> {
            Ok(batch.into_iter().map(|x| x * 2).collect())
        };
        
        let results = optimizer.batch_process(items, processor, 10).await;
        
        assert_eq!(results.len(), 100);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.unwrap(), i as i32 * 2);
        }
    }

    #[tokio::test]
    async fn test_async_iterator() {
        let items: Vec<i32> = (0..50).collect();
        let processor = |x: i32| -> Result<i32> {
            Ok(x * x)
        };
        
        let iterator = AsyncIterator::new(items, processor, 5);
        let results = iterator.process_all().await;
        
        assert_eq!(results.len(), 50);
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.unwrap(), (i as i32) * (i as i32));
        }
    }

    #[tokio::test]
    async fn test_map_reduce() {
        let map_reduce = AsyncMapReduce;
        let items: Vec<i32> = (0..100).collect();
        
        let mapper = |x: i32| -> Result<i32> {
            Ok(x * 2)
        };
        
        let reducer = |acc: i32, val: i32| -> Result<i32> {
            Ok(acc + val)
        };
        
        let result = map_reduce.execute(items, mapper, reducer, 0).await;
        
        assert!(result.is_ok());
        let sum = result.unwrap();
        assert_eq!(sum, (0..100).map(|x| x * 2).sum::<i32>());
    }

    #[tokio::test]
    async fn test_performance_monitor() {
        let monitor = AsyncPerformanceMonitor::new();
        
        // Record some operations
        monitor.record_operation("test_op", Duration::from_millis(10)).await;
        monitor.record_operation("test_op", Duration::from_millis(20)).await;
        monitor.record_operation("other_op", Duration::from_millis(5)).await;
        
        let stats = monitor.get_stats().await;
        
        assert_eq!(stats.total_operations, 3);
        assert_eq!(stats.operation_counts.get("test_op"), Some(&2));
        assert_eq!(stats.operation_counts.get("other_op"), Some(&1));
        assert!(stats.average_duration > Duration::ZERO);
    }
}
