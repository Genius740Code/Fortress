use std::path::PathBuf;

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

pub fn ensure_dir_exists(path: &PathBuf) -> Result<(), std::io::Error> {
    if !path.exists() {
        std::fs::create_dir_all(path)?;
    }
    Ok(())
}

pub fn get_default_data_dir() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("fortress")
}
