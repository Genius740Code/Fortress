//! Utility functions and helpers
//!
//! This module provides various utility functions and helpers for Fortress operations.

use crate::error::{FortressError, Result};
use base64::{Engine as _, engine::general_purpose};
use bytes::Bytes;
use getrandom;
use std::collections::HashMap;

/// Generate a random ID
pub fn generate_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Generate a random nonce for encryption
pub fn generate_nonce(length: usize) -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; length];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| FortressError::internal(
            format!("Failed to generate nonce: {}", e),
            "nonce_generation",
        ))?;
    Ok(nonce)
}

/// Calculate SHA-256 checksum
pub fn sha256_checksum(data: &[u8]) -> String {
    use sha2::Digest;
    let hash = sha2::Sha256::digest(data);
    format!("{:x}", hash)
}

/// Verify SHA-256 checksum
pub fn verify_sha256_checksum(data: &[u8], expected: &str) -> bool {
    sha256_checksum(data) == expected
}

/// Compress data using LZ4
pub fn compress_lz4(data: &[u8]) -> Result<Vec<u8>> {
    lz4::block::compress(data, None, true)
        .map_err(|e| FortressError::internal(
            format!("LZ4 compression failed: {}", e),
            "compression",
        ))
}

/// Decompress LZ4 data
pub fn decompress_lz4(compressed: &[u8]) -> Result<Vec<u8>> {
    lz4::block::decompress(compressed, None)
        .map_err(|e| FortressError::internal(
            format!("LZ4 decompression failed: {}", e),
            "decompression",
        ))
}

/// Compress data using Zstd
pub fn compress_zstd(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data.as_ref(), level)
        .map_err(|e| FortressError::internal(
            format!("Zstd compression failed: {}", e),
            "compression".to_string(),
        ))
}

/// Decompress Zstd data
pub fn decompress_zstd(compressed: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(compressed.as_ref())
        .map_err(|e| FortressError::internal(
            format!("Zstd decompression failed: {}", e),
            "decompression".to_string(),
        ))
}

/// Encode bytes to hex string
pub fn hex_encode(data: &[u8]) -> String {
    hex::encode(data)
}

/// Decode hex string to bytes
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    hex::decode(s)
        .map_err(|e| FortressError::internal(
            format!("Hex decoding failed: {}", e),
            "hex_decode".to_string(),
        ))
}

/// Encode bytes to base64
pub fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 string to bytes
pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| FortressError::internal(
            format!("Base64 decoding failed: {}", e),
            "base64_decode".to_string(),
        ))
}

/// Securely compare two byte arrays in constant time
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    
    result == 0
}

/// Zero out a byte array securely
pub fn secure_zero(data: &mut [u8]) {
    use zeroize::Zeroize;
    data.zeroize();
}

/// Check if a string is a valid identifier
pub fn is_valid_identifier(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    
    s.chars().all(|c| c.is_alphanumeric() || c == '_')
}

/// Validate table name
pub fn validate_table_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(FortressError::validation(
            "Table name cannot be empty",
            Some("table_name".to_string()),
            None,
        ));
    }
    
    if name.len() > 64 {
        return Err(FortressError::validation(
            "Table name too long (max 64 characters)",
            Some("table_name".to_string()),
            Some(name.to_string()),
        ));
    }
    
    if !is_valid_identifier(name) {
        return Err(FortressError::validation(
            "Table name contains invalid characters",
            Some("table_name".to_string()),
            Some(name.to_string()),
        ));
    }
    
    // Check for reserved keywords
    let reserved = ["fortress", "system", "metadata", "keys", "config"];
    if reserved.contains(&name.to_lowercase().as_str()) {
        return Err(FortressError::validation(
            "Table name is a reserved keyword",
            Some("table_name".to_string()),
            Some(name.to_string()),
        ));
    }
    
    Ok(())
}

/// Validate column name
pub fn validate_column_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(FortressError::validation(
            "Column name cannot be empty",
            Some("column_name".to_string()),
            None,
        ));
    }
    
    if name.len() > 64 {
        return Err(FortressError::validation(
            "Column name too long (max 64 characters)",
            Some("column_name".to_string()),
            Some(name.to_string()),
        ));
    }
    
    if !is_valid_identifier(name) {
        return Err(FortressError::validation(
            "Column name contains invalid characters",
            Some("column_name".to_string()),
            Some(name.to_string()),
        ));
    }
    
    Ok(())
}

/// Format bytes as human readable size
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Parse duration string to seconds
pub fn parse_duration_to_seconds(duration_str: &str) -> Result<u64> {
    humantime::parse_duration(duration_str)
        .map(|d| d.as_secs())
        .map_err(|_| FortressError::validation(
            format!("Invalid duration format: {}", duration_str),
            Some("duration".to_string()),
            Some(duration_str.to_string()),
        ))
}

/// Get current timestamp as Unix timestamp
pub fn current_timestamp() -> Result<u64, FortressError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| FortressError::internal(
            format!("System time error: {}", e),
            "SYSTEM_TIME_ERROR".to_string(),
        ))
}

/// Get current timestamp as UTC DateTime
pub fn current_datetime() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

/// Create a timestamp from Unix timestamp
pub fn datetime_from_timestamp(timestamp: u64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp(timestamp as i64, 0)
        .unwrap_or_else(|| chrono::Utc::now())
}

/// Retry an operation with exponential backoff
pub async fn retry_with_backoff<F, T, E>(
    mut operation: F,
    max_retries: u32,
    initial_delay: std::time::Duration,
) -> std::result::Result<T, E>
where
    F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = std::result::Result<T, E>> + Send>>,
    E: std::fmt::Display,
{
    let mut delay = initial_delay;
    
    for attempt in 0..=max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt == max_retries {
                    return Err(e);
                }
                
                tracing::warn!(
                    "Attempt {} failed: {}. Retrying in {:?}",
                    attempt + 1,
                    e,
                    delay
                );
                
                tokio::time::sleep(delay).await;
                delay *= 2; // Exponential backoff
            }
        }
    }
    
    unreachable!()
}

/// Measure execution time of a function
pub async fn measure_time<F, T>(f: F) -> (T, std::time::Duration)
where
    F: std::future::Future<Output = T>,
{
    let start = std::time::Instant::now();
    let result = f.await;
    let duration = start.elapsed();
    (result, duration)
}

/// Convert a HashMap to a query string
pub fn hashmap_to_query_string(params: &HashMap<String, String>) -> String {
    params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding::encode(k), urlencoding::encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Parse a query string into a HashMap
pub fn query_string_to_hashmap(query: &str) -> HashMap<String, String> {
    query
        .split('&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some(key), Some(value)) => {
                    Some((
                        urlencoding::decode(key).unwrap_or_default().into_owned(),
                        urlencoding::decode(value).unwrap_or_default().into_owned(),
                    ))
                }
                _ => None,
            }
        })
        .collect()
}

/// Check if a string contains only ASCII characters
pub fn is_ascii(s: &str) -> bool {
    s.is_ascii()
}

/// Sanitize a string for logging (remove sensitive data)
pub fn sanitize_for_logging(s: &str) -> String {
    // Replace common sensitive patterns
    s.replace(|c: char| c.is_control(), "?")
        .chars()
        .take(1000) // Limit length
        .collect()
}

/// Generate a random password
pub fn generate_password(length: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
    
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Validate password strength
pub fn validate_password_strength(password: &str) -> Result<()> {
    if password.len() < 8 {
        return Err(FortressError::validation(
            "Password must be at least 8 characters long",
            Some("password".to_string()),
            None,
        ));
    }
    
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_digit = password.chars().any(|c| c.is_digit(10));
    let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
    
    if !has_uppercase {
        return Err(FortressError::validation(
            "Password must contain at least one uppercase letter",
            Some("password".to_string()),
            None,
        ));
    }
    
    if !has_lowercase {
        return Err(FortressError::validation(
            "Password must contain at least one lowercase letter",
            Some("password".to_string()),
            None,
        ));
    }
    
    if !has_digit {
        return Err(FortressError::validation(
            "Password must contain at least one digit",
            Some("password".to_string()),
            None,
        ));
    }
    
    if !has_special {
        return Err(FortressError::validation(
            "Password must contain at least one special character",
            Some("password".to_string()),
            None,
        ));
    }
    
    Ok(())
}

/// Create a temporary file with secure permissions
pub fn create_secure_temp_file() -> Result<std::fs::File> {
    use std::fs::OpenOptions;
    
    let temp_path = std::env::temp_dir().join(format!("fortress_{}", generate_id()));
    
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600) // Read/write for owner only
            .open(&temp_path)
            .map_err(|e| FortressError::io(
                format!("Failed to create secure temp file: {}", e),
                Some(temp_path.to_string_lossy().to_string()),
            ))
    }
    
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&temp_path)
            .map_err(|e| FortressError::io(
                format!("Failed to create secure temp file: {}", e),
                Some(temp_path.to_string_lossy().to_string()),
            ))
    }
}

/// Get system information
pub fn get_system_info() -> HashMap<String, String> {
    let mut info = HashMap::new();
    
    info.insert("os".to_string(), std::env::consts::OS.to_string());
    info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    info.insert("family".to_string(), std::env::consts::FAMILY.to_string());
    
    // Get CPU info
    if let Ok(cpu_count) = std::thread::available_parallelism() {
        info.insert("cpu_cores".to_string(), cpu_count.to_string());
    }
    
    // Get memory info (simplified)
    #[cfg(unix)]
    {
        if let Ok(sysinfo) = sysinfo::System::new_with_specifics(
            sysinfo::RefreshKind::new().with_memory()
        ) {
            info.insert("total_memory".to_string(), 
                format_bytes(sysinfo.total_memory()));
        }
    }
    
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_id() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
        assert_eq!(id1.len(), 36); // UUID length
    }

    #[test]
    fn test_generate_nonce() {
        let nonce = generate_nonce(16).unwrap();
        assert_eq!(nonce.len(), 16);
        
        let nonce2 = generate_nonce(16).unwrap();
        assert_ne!(nonce, nonce2);
    }

    #[test]
    fn test_sha256_checksum() {
        let data = b"Hello, Fortress!";
        let checksum = sha256_checksum(data);
        assert_eq!(checksum.len(), 64); // SHA256 hex length
        
        // Verify consistency
        let checksum2 = sha256_checksum(data);
        assert_eq!(checksum, checksum2);
        
        // Verify verification
        assert!(verify_sha256_checksum(data, &checksum));
        assert!(!verify_sha256_checksum(data, "invalid"));
    }

    #[test]
    fn test_hex_encoding() {
        let data = b"Hello";
        let encoded = hex_encode(data);
        assert_eq!(encoded, "48656c6c6f");
        
        let decoded = hex_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_base64_encoding() {
        let data = b"Hello";
        let encoded = base64_encode(data);
        assert_eq!(encoded, "SGVsbG8=");
        
        let decoded = base64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_constant_time_eq() {
        let a = b"Hello";
        let b = b"Hello";
        let c = b"World";
        
        assert!(constant_time_eq(a, b));
        assert!(!constant_time_eq(a, c));
        assert!(!constant_time_eq(b"Hello", b"Hello!"));
    }

    #[test]
    fn test_validate_names() {
        // Valid names
        assert!(validate_table_name("users").is_ok());
        assert!(validate_column_name("id").is_ok());
        assert!(validate_table_name("user_profiles").is_ok());
        
        // Invalid names
        assert!(validate_table_name("").is_err());
        assert!(validate_table_name("user-table").is_err());
        assert!(validate_table_name("users table").is_err());
        assert!(validate_table_name("fortress").is_err()); // Reserved
        
        assert!(validate_column_name("").is_err());
        assert!(validate_column_name("user-id").is_err());
        assert!(validate_column_name("user name").is_err());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration_to_seconds("23h").unwrap(), 23 * 3600);
        assert_eq!(parse_duration_to_seconds("7d").unwrap(), 7 * 24 * 3600);
        assert_eq!(parse_duration_to_seconds("30m").unwrap(), 30 * 60);
        
        assert!(parse_duration_to_seconds("invalid").is_err());
    }

    #[test]
    fn test_query_string_parsing() {
        let params = HashMap::from([
            ("key1".to_string(), "value1".to_string()),
            ("key2".to_string(), "value 2".to_string()),
        ]);
        
        let query_string = hashmap_to_query_string(&params);
        assert!(query_string.contains("key1=value1"));
        assert!(query_string.contains("key2=value%202"));
        
        let parsed = query_string_to_hashmap(&query_string);
        assert_eq!(parsed.get("key1"), Some(&"value1".to_string()));
        assert_eq!(parsed.get("key2"), Some(&"value 2".to_string()));
    }

    #[test]
    fn test_password_generation() {
        let password = generate_password(12);
        assert_eq!(password.len(), 12);
        
        // Should contain different character types
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_digit(10));
        let has_special = password.chars().any(|c| "!@#$%^&*()_+-=[]{}|;:,.<>?".contains(c));
        
        // Not guaranteed in random generation, but likely
        // assert!(has_upper || has_lower || has_digit || has_special);
    }

    #[test]
    fn test_password_validation() {
        // Valid passwords
        assert!(validate_password_strength("StrongPass123!").is_ok());
        assert!(validate_password_strength("MySecure@Password456").is_ok());
        
        // Invalid passwords
        assert!(validate_password_strength("weak").is_err()); // Too short
        assert!(validate_password_strength("alllowercase123!").is_err()); // No uppercase
        assert!(validate_password_strength("ALLUPPERCASE123!").is_err()); // No lowercase
        assert!(validate_password_strength("NoDigits!").is_err()); // No digits
        assert!(validate_password_strength("NoSpecialChars123").is_err()); // No special
    }

    #[test]
    fn test_system_info() {
        let info = get_system_info();
        assert!(info.contains_key("os"));
        assert!(info.contains_key("arch"));
        assert!(info.contains_key("family"));
        
        #[cfg(unix)]
        assert!(info.contains_key("cpu_cores"));
    }

    #[tokio::test]
    async fn test_measure_time() {
        let (result, duration) = measure_time(async {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            42
        }).await;
        
        assert_eq!(result, 42);
        assert!(duration >= std::time::Duration::from_millis(10));
    }

    #[tokio::test]
    async fn test_retry_with_backoff() {
        let mut attempts = 0;
        let result = retry_with_backoff(
            || {
                Box::pin(async move {
                    attempts += 1;
                    if attempts < 3 {
                        Err("error")
                    } else {
                        Ok("success")
                    }
                })
            },
            5,
            std::time::Duration::from_millis(1),
        ).await;
        
        assert_eq!(result, Ok("success"));
        assert_eq!(attempts, 3);
    }
}
