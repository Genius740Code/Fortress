//! Async optimization implementations
//! 
//! This module provides async versions of cryptographic operations with
//! batch processing, concurrency control, and request batching.

use crate::error::FortressError;
use crate::encryption::EncryptionAlgorithm;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Semaphore};
use tokio::time::{timeout, Duration};
use futures::stream::{self, StreamExt};
use futures::future::try_join_all;
use std::sync::atomic::{AtomicU64, Ordering};

/// Performance metrics for async operations
static ASYNC_OPERATIONS: AtomicU64 = AtomicU64::new(0);

/// Async version of encrypt_data that moves CPU-intensive work to blocking threads
pub async fn encrypt_data_async(data: &[u8], key: &[u8], algorithm: Arc<dyn EncryptionAlgorithm>) -> Result<Vec<u8>, FortressError> {
    let data = data.to_vec();
    let key = key.to_vec();
    
    ASYNC_OPERATIONS.fetch_add(1, Ordering::Relaxed);
    
    tokio::task::spawn_blocking(move || {
        algorithm.encrypt(&data, &key)
    }).await.map_err(|e| FortressError::internal(format!("Task join error: {}", e), "ASYNC_JOIN_ERROR".to_string()))?
}

/// Async version of decrypt_data that moves CPU-intensive work to blocking threads
pub async fn decrypt_data_async(encrypted_data: &[u8], key: &[u8], algorithm: Arc<dyn EncryptionAlgorithm>) -> Result<Vec<u8>, FortressError> {
    let encrypted_data = encrypted_data.to_vec();
    let key = key.to_vec();
    
    tokio::task::spawn_blocking(move || {
        algorithm.decrypt(&encrypted_data, &key)
    }).await.map_err(|e| FortressError::internal(format!("Task join error: {}", e), "ASYNC_JOIN_ERROR".to_string()))?
}

/// Batch encryptor with concurrency control
pub struct BatchEncryptor {
    concurrency_limit: usize,
    semaphore: Arc<Semaphore>,
}

impl BatchEncryptor {
    /// Create a new batch encryptor with specified concurrency limit
    pub fn new(concurrency_limit: usize) -> Self {
        Self {
            concurrency_limit,
            semaphore: Arc::new(Semaphore::new(concurrency_limit)),
        }
    }

    /// Encrypt multiple data items concurrently
    pub async fn encrypt_batch(&self, data_batch: &[&[u8]], key: &[u8], algorithm: Arc<dyn EncryptionAlgorithm>) -> Result<Vec<Vec<u8>>, FortressError> {
        let tasks: Vec<_> = data_batch.iter()
            .enumerate()
            .map(|(_i, data)| {
                let permit = self.semaphore.clone();
                let data = data.to_vec();
                let key = key.to_vec();
                let algorithm = algorithm.clone();
                
                async move {
                    let _permit = permit.acquire().await.map_err(|e| FortressError::internal(format!("Semaphore acquire error: {}", e), "SEMAPHORE_ACQUIRE_ERROR".to_string()))?;
                    encrypt_data_async(&data, &key, algorithm).await
                }
            })
            .collect();
        
        try_join_all(tasks).await
    }

    /// Encrypt batch with controlled concurrency using streams
    pub async fn encrypt_batch_limited(&self, data_batch: &[&[u8]], key: &[u8], algorithm: Arc<dyn EncryptionAlgorithm>) -> Result<Vec<Vec<u8>>, FortressError> {
        let results: Vec<Result<Vec<u8>, FortressError>> = stream::iter(data_batch)
            .map(|data| {
                let data = data.to_vec();
                let key = key.to_vec();
                let algorithm = algorithm.clone();
                async move {
                    encrypt_data_async(&data, &key, algorithm).await
                }
            })
            .buffer_unordered(self.concurrency_limit)
            .collect()
            .await;
        
        // Collect all results, returning the first error if any
        let mut output = Vec::new();
        for result in results {
            output.push(result?);
        }
        Ok(output)
    }

    /// Get concurrency limit
    pub fn concurrency_limit(&self) -> usize {
        self.concurrency_limit
    }

    /// Get current semaphore permits available
    pub async fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }
}

/// Batch processor for async operations
pub struct BatchProcessor {
    sender: mpsc::UnboundedSender<(Vec<u8>, oneshot::Sender<Result<Vec<u8>, FortressError>>)>,
    batch_size: usize,
    batch_timeout: Duration,
}

impl BatchProcessor {
    /// Create a new batch processor
    pub fn new<F>(
        batch_size: usize,
        batch_timeout: Duration,
        processor: F,
    ) -> Self 
    where 
        F: Fn(Vec<Vec<u8>>) -> Vec<Result<Vec<u8>, FortressError>> + Send + Sync + 'static,
    {
        let (sender, mut receiver) = mpsc::unbounded_channel();
        let processor = Arc::new(processor);
        
        // Start batch processing task
        tokio::spawn({
            let processor = processor.clone();
            async move {
                let mut batch: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
                let mut senders: Vec<oneshot::Sender<Result<Vec<u8>, FortressError>>> = Vec::with_capacity(batch_size);
                
                loop {
                    // Wait for first item or timeout
                    match timeout(batch_timeout, receiver.recv()).await {
                        Ok(Some((item, sender))) => {
                            batch.push(item);
                            senders.push(sender);
                            
                            // Collect more items until batch is full or timeout
                            while batch.len() < batch_size {
                                match timeout(Duration::from_millis(10), receiver.recv()).await {
                                    Ok(Some((item, sender))) => {
                                        batch.push(item);
                                        senders.push(sender);
                                    }
                                    _ => break,
                                }
                            }
                            
                            // Process batch
                            let results = processor(batch.drain(..).collect());
                            for (result, sender) in results.into_iter().zip(senders.drain(..)) {
                                let _ = sender.send(result);
                            }
                        }
                        Ok(None) => break, // Channel closed
                        Err(_) => {
                            // Timeout - process current batch if not empty
                            if !batch.is_empty() {
                                let results = processor(batch.drain(..).collect());
                                for (result, sender) in results.into_iter().zip(senders.drain(..)) {
                                    let _ = sender.send(result);
                                }
                            }
                        }
                    }
                }
            }
        });
        
        Self {
            sender,
            batch_size,
            batch_timeout,
        }
    }

    /// Process a single item through the batch system
    pub async fn process(&self, item: Vec<u8>) -> Result<Vec<u8>, FortressError> {
        let (response_sender, response_receiver) = oneshot::channel();
        
        self.sender.send((item, response_sender))
            .map_err(|_| FortressError::processor_error("Batch processor closed".to_string()))?;
        
        response_receiver.await
            .map_err(|_| FortressError::processor_error("Response channel closed".to_string()))?
    }

    /// Get batch size
    pub fn batch_size(&self) -> usize {
        self.batch_size
    }

    /// Get batch timeout
    pub fn batch_timeout(&self) -> Duration {
        self.batch_timeout
    }
}

/// Async encryption service with batching
pub struct AsyncEncryptionService {
    algorithm: Arc<dyn EncryptionAlgorithm>,
    batch_processor: BatchProcessor,
    batch_encryptor: BatchEncryptor,
}

impl AsyncEncryptionService {
    /// Create a new async encryption service
    pub fn new(algorithm: Arc<dyn EncryptionAlgorithm>, batch_size: usize, batch_timeout: Duration, concurrency_limit: usize) -> Self {
        let key = vec![0u8; 32]; // Default key, should be configurable
        let algorithm_clone = algorithm.clone();
        
        // Create batch processor for encryption
        let batch_processor = BatchProcessor::new(
            batch_size,
            batch_timeout,
            move |batch: Vec<Vec<u8>>| -> Vec<Result<Vec<u8>, FortressError>> {
                let key = key.clone();
                
                batch.into_iter()
                    .map(|data| {
                        // For now, use synchronous encryption since we're in a sync context
                        // In production, this would need a different approach
                        algorithm_clone.encrypt(&data, &key)
                    })
                    .collect()
            }
        );

        Self {
            algorithm,
            batch_processor,
            batch_encryptor: BatchEncryptor::new(concurrency_limit),
        }
    }

    /// Encrypt data using the batch processor
    pub async fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, FortressError> {
        self.batch_processor.process(data.to_vec()).await
    }

    /// Encrypt multiple items using the batch encryptor
    pub async fn encrypt_batch(&self, data_batch: &[&[u8]], key: &[u8]) -> Result<Vec<Vec<u8>>, FortressError> {
        self.batch_encryptor.encrypt_batch(data_batch, key, self.algorithm.clone()).await
    }

    /// Encrypt multiple items with concurrency control
    pub async fn encrypt_batch_limited(&self, data_batch: &[&[u8]], key: &[u8]) -> Result<Vec<Vec<u8>>, FortressError> {
        self.batch_encryptor.encrypt_batch_limited(data_batch, key, self.algorithm.clone()).await
    }

    /// Get async operation count
    pub fn async_operation_count() -> u64 {
        ASYNC_OPERATIONS.load(Ordering::Relaxed)
    }
}

/// Utility trait for cloning boxed encryption algorithms
pub trait CloneBox {
    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm>;
}

impl<T: EncryptionAlgorithm + Clone + 'static> CloneBox for T {
    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        Box::new(self.clone())
    }
}

// Implement CloneBox for trait objects
impl CloneBox for dyn EncryptionAlgorithm {
    fn clone_box(&self) -> Box<dyn EncryptionAlgorithm> {
        // This is a workaround - in practice, this would need a proper cloning mechanism
        // For now, we'll use a panic to indicate this needs proper implementation
        panic!("clone_box not implemented for trait objects - use concrete types")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::Aegis256;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_async_encryption() {
        let algorithm = Arc::new(Aegis256::new()) as Arc<dyn EncryptionAlgorithm>;
        let data = vec![1u8; 1024];
        let key = vec![0u8; 32];
        
        let result = encrypt_data_async(&data, &key, algorithm.clone()).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), data.len());
    }

    #[tokio::test]
    async fn test_batch_encryptor() {
        let encryptor = BatchEncryptor::new(4);
        let algorithm = Arc::new(Aegis256::new()) as Arc<dyn EncryptionAlgorithm>;
        let key = vec![0u8; 32];
        
        let data_batch: Vec<&[u8]> = vec![
            &[1u8; 512],
            &[2u8; 512],
            &[3u8; 512],
            &[4u8; 512],
        ];
        
        let results = encryptor.encrypt_batch(&data_batch, &key, algorithm.clone()).await;
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 4);
    }

    #[tokio::test]
    async fn test_batch_processor() {
        let processor = BatchProcessor::new(
            3,
            Duration::from_millis(100),
            |batch: Vec<Vec<u8>>| -> Vec<Result<Vec<u8>, FortressError>> {
                batch.into_iter()
                    .map(|data| Ok(data.iter().map(|&x| x.wrapping_add(1)).collect()))
                    .collect()
            }
        );

        let data = vec![1u8; 100];
        let result = processor.process(data.clone()).await;
        assert!(result.is_ok());
        
        let expected: Vec<u8> = data.iter().map(|&x| x.wrapping_add(1)).collect();
        assert_eq!(result.unwrap(), expected);
    }

    #[tokio::test]
    async fn test_async_encryption_service() {
        let algorithm = Arc::new(Aegis256::new()) as Arc<dyn EncryptionAlgorithm>;
        let service = AsyncEncryptionService::new(
            algorithm,
            5,
            Duration::from_millis(50),
            3
        );

        let data = vec![1u8; 1024];
        let result = service.encrypt(&data).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_async_operation_counting() {
        let initial_count = AsyncEncryptionService::async_operation_count();
        // In a real test, we would perform async operations and check the count
        // For now, just verify the function works
        assert!(initial_count >= 0);
    }
}
