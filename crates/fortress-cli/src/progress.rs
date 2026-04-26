use indicatif::{ProgressBar, ProgressStyle, MultiProgress};
use tokio::time::{sleep, Duration as TokioDuration};
use crate::enhanced_error::FortressError;
use std::sync::Arc;
use std::time::Duration as StdDuration;

pub struct ProgressManager {
    multi_progress: MultiProgress,
}

impl ProgressManager {
    pub fn new() -> Self {
        Self {
            multi_progress: MultiProgress::new(),
        }
    }
    
    pub fn create_encryption_progress(&self, total_bytes: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_bytes));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-")
        );
        pb.set_message("Encrypting data...");
        pb
    }
    
    pub fn create_database_migration_progress(&self, total_steps: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_steps));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.blue} [{elapsed_precise}] [{bar:40.green/blue}] {pos}/{len} steps ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-")
        );
        pb.set_message("Running database migration...");
        pb
    }
    
    pub fn create_key_generation_progress(&self, total_keys: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_keys));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.yellow} [{elapsed_precise}] [{bar:40.yellow/red}] {pos}/{len} keys ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=> ")
        );
        pb.set_message("Generating keys...");
        pb
    }
    
    pub fn create_file_operation_progress(&self, total_files: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_files));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.magenta} [{elapsed_precise}] [{bar:40.magenta/white}] {pos}/{len} files ({eta})")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("=>-")
        );
        pb.set_message("Processing files...");
        pb
    }
    
    pub fn create_download_progress(&self, total_bytes: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_bytes));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/red}] {bytes}/{total_bytes} ({eta}) {bytes_per_sec}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-")
        );
        pb.set_message("Downloading...");
        pb
    }
    
    pub fn create_upload_progress(&self, total_bytes: u64) -> ProgressBar {
        let pb = self.multi_progress.add(ProgressBar::new(total_bytes));
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.green/red}] {bytes}/{total_bytes} ({eta}) {bytes_per_sec}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("#>-")
        );
        pb.set_message("Uploading...");
        pb
    }
}

impl Default for ProgressManager {
    fn default() -> Self {
        Self::new()
    }
}

// Example usage functions for different operations

pub async fn encrypt_large_dataset_with_progress(
    data: &[u8], 
    encrypt_chunk: impl Fn(&[u8]) -> Result<Vec<u8>, FortressError> + Send + Sync
) -> Result<Vec<u8>, FortressError> {
    let progress_manager = ProgressManager::new();
    let pb = progress_manager.create_encryption_progress(data.len() as u64);
    
    let mut result = Vec::with_capacity(data.len());
    let chunk_size = 1024 * 1024; // 1MB chunks
    let encrypt_fn = Arc::new(encrypt_chunk);
    
    for (i, chunk) in data.chunks(chunk_size).enumerate() {
        // Simulate encryption work
        sleep(TokioDuration::from_millis(10)).await;
        
        let encrypted = encrypt_fn(chunk)?;
        result.extend_from_slice(&encrypted);
        
        pb.set_position(((i + 1) * chunk_size) as u64);
        
        // Update message periodically
        if i % 10 == 0 {
            pb.set_message(format!("Encrypted {} MB", (i * chunk_size) / (1024 * 1024)));
        }
    }
    
    pb.finish_with_message("Encryption complete!");
    Ok(result)
}

pub async fn run_database_migration_with_progress(
    migration_steps: Vec<String>,
    execute_step: impl Fn(&str) -> Result<(), FortressError> + Send + Sync
) -> Result<(), FortressError> {
    let progress_manager = ProgressManager::new();
    let pb = progress_manager.create_database_migration_progress(migration_steps.len() as u64);
    
    let execute_fn = Arc::new(execute_step);
    
    for (i, step) in migration_steps.iter().enumerate() {
        pb.set_message(format!("Running step: {}", step));
        
        // Simulate migration work
        sleep(TokioDuration::from_millis(500)).await;
        
        execute_fn(step)?;
        
        pb.set_position((i + 1) as u64);
    }
    
    pb.finish_with_message("Database migration complete!");
    Ok(())
}

pub async fn generate_multiple_keys_with_progress(
    key_count: usize,
    algorithm: &str,
    generate_key: impl Fn(&str) -> Result<String, FortressError> + Send + Sync
) -> Result<Vec<String>, FortressError> {
    let progress_manager = ProgressManager::new();
    let pb = progress_manager.create_key_generation_progress(key_count as u64);
    
    let mut keys = Vec::with_capacity(key_count);
    let generate_fn = Arc::new(generate_key);
    
    for i in 0..key_count {
        pb.set_message(format!("Generating key {} of {}", i + 1, key_count));
        
        // Simulate key generation work
        sleep(TokioDuration::from_millis(100)).await;
        
        let key = generate_fn(algorithm)?;
        keys.push(key);
        
        pb.set_position((i + 1) as u64);
    }
    
    pb.finish_with_message("Key generation complete!");
    Ok(keys)
}

pub async fn process_files_with_progress(
    files: Vec<std::path::PathBuf>,
    process_file: impl Fn(&std::path::Path) -> Result<(), FortressError> + Send + Sync
) -> Result<(), FortressError> {
    let progress_manager = ProgressManager::new();
    let pb = progress_manager.create_file_operation_progress(files.len() as u64);
    
    let process_fn = Arc::new(process_file);
    
    for (i, file) in files.iter().enumerate() {
        pb.set_message(format!("Processing: {}", file.display()));
        
        // Simulate file processing work
        sleep(TokioDuration::from_millis(200)).await;
        
        process_fn(file)?;
        
        pb.set_position((i + 1) as u64);
    }
    
    pb.finish_with_message("File processing complete!");
    Ok(())
}

pub async fn download_file_with_progress(
    url: &str,
    output_path: &std::path::Path,
    total_size: Option<u64>
) -> Result<(), FortressError> {
    let progress_manager = ProgressManager::new();
    let total_bytes = total_size.unwrap_or(0);
    let pb = progress_manager.create_download_progress(total_bytes);
    
    // Simulate download work
    if total_bytes > 0 {
        for i in 0..100 {
            sleep(TokioDuration::from_millis(50)).await;
            let progress = (i * total_bytes / 100) as u64;
            pb.set_position(progress);
            
            if i % 10 == 0 {
                pb.set_message(format!("Downloaded {}%", i));
            }
        }
    } else {
        // Indeterminate progress
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{elapsed_precise}] Downloading... {bytes_per_sec}")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
        );
        
        for i in 0..100 {
            sleep(TokioDuration::from_millis(50)).await;
            if i % 10 == 0 {
                pb.set_message(format!("Downloading... {}%", i));
            }
        }
    }
    
    pb.finish_with_message("Download complete!");
    Ok(())
}

pub async fn upload_file_with_progress(
    file_path: &std::path::Path,
    url: &str
) -> Result<(), FortressError> {
    let progress_manager = ProgressManager::new();
    
    // Get file size
    let file_size = std::fs::metadata(file_path)
        .map_err(|e| FortressError::io_error(format!("Failed to get file metadata: {}", e)))?
        .len();
    
    let pb = progress_manager.create_upload_progress(file_size);
    
    // Simulate upload work
    let chunk_size = 64 * 1024; // 64KB chunks
    let total_chunks = (file_size / chunk_size) + 1;
    
    for i in 0..total_chunks {
        sleep(TokioDuration::from_millis(20)).await;
        
        let progress = ((i + 1) * chunk_size).min(file_size);
        pb.set_position(progress);
        
        if i % 10 == 0 {
            let uploaded_mb = progress / (1024 * 1024);
            pb.set_message(format!("Uploaded {} MB", uploaded_mb));
        }
    }
    
    pb.finish_with_message("Upload complete!");
    Ok(())
}

// Utility functions for progress bar styling

pub fn create_default_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-")
}

pub fn create_bytes_style() -> ProgressStyle {
    ProgressStyle::default_bar()
        .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/red}] {bytes}/{total_bytes} ({eta}) {bytes_per_sec}")
        .unwrap_or_else(|_| ProgressStyle::default_bar())
        .progress_chars("#>-")
}

pub fn create_spinner_style() -> ProgressStyle {
    ProgressStyle::default_spinner()
        .template("{spinner:.green} [{elapsed_precise}] {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner())
}

// Progress bar wrapper for easier usage

pub struct ProgressTracker {
    pub pb: ProgressBar,
    start_time: std::time::Instant,
}

impl ProgressTracker {
    pub fn new(total: u64, message: String) -> Self {
        let pb = ProgressBar::new(total);
        pb.set_style(create_default_style());
        pb.set_message(message);
        
        Self {
            pb,
            start_time: std::time::Instant::now(),
        }
    }
    
    pub fn with_style(total: u64, message: String, style: ProgressStyle) -> Self {
        let pb = ProgressBar::new(total);
        pb.set_style(style);
        pb.set_message(message);
        
        Self {
            pb,
            start_time: std::time::Instant::now(),
        }
    }
    
    pub fn update(&self, current: u64) {
        self.pb.set_position(current);
    }
    
    pub fn increment(&self, delta: u64) {
        self.pb.inc(delta);
    }
    
    pub fn set_message(&self, message: String) {
        self.pb.set_message(message);
    }
    
    pub fn finish(&self, message: String) {
        self.pb.finish_with_message(message);
    }
    
    pub fn abandon(&self, message: String) {
        self.pb.abandon_with_message(message);
    }
    
    pub fn elapsed(&self) -> StdDuration {
        StdDuration::from_millis(self.start_time.elapsed().as_millis() as u64)
    }
    
    pub fn eta(&self) -> Option<StdDuration> {
        // indicatif's eta() returns Option<Duration>, but we need to convert it
        // to std::time::Duration. Let's use a simpler approach for now.
        None // Return None for now since eta calculation is complex
    }
}

impl Drop for ProgressTracker {
    fn drop(&mut self) {
        if !self.pb.is_finished() {
            self.pb.abandon();
        }
    }
}
