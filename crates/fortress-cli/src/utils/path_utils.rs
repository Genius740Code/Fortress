use std::path::PathBuf;

/// Normalize a path string to an absolute PathBuf
/// 
/// # Arguments
/// * `path` - The path string to normalize
/// 
/// # Returns
/// An absolute PathBuf
pub fn normalize_path(path: &str) -> PathBuf {
    let path_buf = PathBuf::from(path);
    
    // Convert to absolute path if relative
    if path_buf.is_relative() {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path_buf)
    } else {
        path_buf
    }
}

/// Ensure a directory exists, creating it if necessary
/// 
/// # Arguments
/// * `path` - The directory path to ensure exists
/// 
/// # Returns
/// Ok(()) if successful, Err(io::Error) if creation fails
pub fn ensure_dir_exists(path: &PathBuf) -> Result<(), std::io::Error> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

/// Get the default data directory for Fortress
/// 
/// # Returns
/// A PathBuf pointing to the default data directory
pub fn get_default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("fortress")
}
