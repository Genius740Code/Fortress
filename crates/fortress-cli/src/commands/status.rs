use color_eyre::eyre::{eyre, Result};
use console::style;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;
use serde_json;

/// Handle the status command
///
/// Displays the current status of Fortress services including health checks,
/// performance metrics, and operational state.
///
/// # Arguments
/// * `data_dir` - Optional data directory path
///
/// # Returns
/// Result indicating success or failure
pub async fn handle_status(data_dir: Option<String>) -> Result<()> {
    println!("{}", style("Fortress Database Status").bold().cyan());
    println!();
    
    let db_path = PathBuf::from(data_dir.unwrap_or_else(|| "./fortress".to_string()));
    
    // Check database directory
    if !db_path.exists() {
        println!("{} Database not found at: {}", 
            style("✗").red(), 
            style(db_path.display()).bold()
        );
        println!("Use 'fortress create' to initialize a new database.");
        return Ok(());
    }
    
    println!("{} Database directory: {}", 
        style("✓").green(), 
        style(db_path.display()).bold()
    );
    
    // Check configuration
    let config_path = db_path.join("config").join("fortress.toml");
    if config_path.exists() {
        println!("{} Configuration: {}", 
            style("✓").green(), 
            style("Found").green()
        );
        
        // Load and display config summary
        if let Ok(config_content) = tokio::fs::read_to_string(&config_path).await {
            if let Ok(config) = toml::from_str::<crate::commands::config::ConfigSettings>(&config_content) {
                println!("  Server: {}:{}", config.server.host, config.server.port);
                println!("  Workers: {}", config.server.workers);
                println!("  Max Connections: {}", config.database.max_connections);
                println!("  Encryption: {}", config.security.encryption_algorithm);
            }
        }
    } else {
        println!("{} Configuration: {}", 
            style("✗").red(), 
            style("Missing").red()
        );
    }
    
    // Check keys
    let keys_path = db_path.join("keys");
    if keys_path.exists() {
        let mut key_count = 0;
        if let Ok(mut entries) = tokio::fs::read_dir(&keys_path).await {
            while let Ok(Some(_entry)) = entries.next_entry().await {
                key_count += 1;
            }
        }
        println!("{} Encryption keys: {} ({})", 
            style("✅").green(), 
            style("Found").green(),
            style(format!("{} keys", key_count)).bold()
        );
    } else {
        println!("{} Encryption keys: {}", 
            style("❌").red(), 
            style("Missing").red()
        );
    }
    
    // Check data directory
    let data_path = db_path.join("data");
    if data_path.exists() {
        let mut data_size = 0;
        let mut file_count = 0;
        
        if let Ok(mut entries) = tokio::fs::read_dir(&data_path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if let Ok(metadata) = entry.metadata().await {
                    data_size += metadata.len();
                    file_count += 1;
                }
            }
        }
        
        println!("{} Data storage: {} ({}, {} files)", 
            style("✅").green(), 
            style("Found").green(),
            style(format_bytes(data_size)).bold(),
            style(file_count).bold()
        );
    } else {
        println!("{} Data storage: {}", 
            style("❌").red(), 
            style("Missing").red()
        );
    }
    
    println!();
    
    // Check server status
    println!("{} Server Status:", style("🖥️").blue());
    
    match check_server_status().await {
        Ok(server_info) => {
            println!("  {} Status: {}", 
                style("✅").green(), 
                style("Running").green().bold()
            );
            println!("  Address: {}", style(&server_info.address).bold());
            println!("  PID: {}", style(server_info.pid).bold());
            println!("  Uptime: {}", style(format_duration(server_info.uptime)).bold());
            println!("  Version: {}", style(server_info.version).bold());
            
            // Get detailed server metrics
            if let Ok(metrics) = get_server_metrics(&server_info.address).await {
                println!("  📊 Performance:");
                println!("    Requests/sec: {:.2}", style(metrics.requests_per_second).bold());
                println!("    Avg Response: {}ms", style(metrics.average_response_time_ms).bold());
                println!("    Active Connections: {}", style(metrics.active_connections).bold());
                println!("    Memory Usage: {}", style(format_bytes(metrics.memory_usage_bytes)).bold());
                println!("    CPU Usage: {:.1}%", style(metrics.cpu_usage_percent).bold());
            }
        }
        Err(e) => {
            println!("  {} Status: {}", 
                style("❌").red(), 
                style("Not running").red().bold()
            );
            println!("  ℹ️  {}", e);
        }
    }
    
    println!();
    println!("📁 Database path: {}", style(db_path.display()).bold());
    
    Ok(())
}

#[derive(Debug, Clone)]
struct ServerInfo {
    pid: u32,
    address: String,
    uptime: Duration,
    version: String,
}

#[derive(Debug, Clone)]
struct ServerMetrics {
    requests_per_second: f64,
    average_response_time_ms: u64,
    active_connections: usize,
    memory_usage_bytes: u64,
    cpu_usage_percent: f64,
}

async fn check_server_status() -> Result<ServerInfo> {
    // Try to get server info from API first
    if let Ok(info) = get_server_info_from_api().await {
        return Ok(info);
    }
    
    // Fallback to process discovery
    get_server_info_from_process().await
}

async fn get_server_info_from_api() -> Result<ServerInfo> {
    let client = reqwest::Client::new();
    
    // Try common ports
    let ports = vec![8080, 8081, 3000, 8082];
    
    for port in ports {
        let url = format!("http://127.0.0.1:{}/status", port);
        
        match timeout(Duration::from_secs(2), client.get(&url).send()).await {
            Ok(Ok(response)) if response.status().is_success() => {
                let status: serde_json::Value = response.json().await
                    .map_err(|e| color_eyre::eyre::eyre!("Failed to parse status: {}", e))?;
                
                // Extract server information
                let server_data = status.get("server").ok_or_else(|| {
                    color_eyre::eyre::eyre!("Missing server information in status response")
                })?;
                
                let uptime_seconds = server_data.get("uptime_seconds")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| eyre!("Missing uptime information"))?;
                
                let version = server_data.get("version")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                
                return Ok(ServerInfo {
                    pid: get_pid_from_port(port).await.unwrap_or(0),
                    address: format!("127.0.0.1:{}", port),
                    uptime: Duration::from_secs(uptime_seconds),
                    version,
                });
            }
            _ => continue,
        }
    }
    
    Err(color_eyre::eyre::eyre!("No running Fortress server found via API"))
}

async fn get_server_info_from_process() -> Result<ServerInfo> {
    // Use ps command to find Fortress processes
    let output = Command::new("ps")
        .args(&["aux"])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run ps command: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if line.contains("fortress") && line.contains("server") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                if let Ok(pid) = parts[1].parse::<u32>() {
                    // Try to get port from command line
                    let port = extract_port_from_line(line).unwrap_or(8080);
                    
                    return Ok(ServerInfo {
                        pid,
                        address: format!("127.0.0.1:{}", port),
                        uptime: Duration::from_secs(0), // Unknown uptime from process list
                        version: "unknown".to_string(),
                    });
                }
            }
        }
    }
    
    Err(color_eyre::eyre::eyre!("No running Fortress process found"))
}

async fn get_pid_from_port(port: u16) -> Result<u32> {
    // Use lsof to find process using the port
    let output = Command::new("lsof")
        .args(&["-i", &format!(":{}", port)])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to run lsof: {}", e))?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines().skip(1) { // Skip header
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 {
            if let Ok(pid) = parts[1].parse::<u32>() {
                return Ok(pid);
            }
        }
    }
    
    Err(color_eyre::eyre::eyre!("No process found using port {}", port))
}

fn extract_port_from_line(line: &str) -> Option<u16> {
    // Look for --port or -p arguments
    let re = regex::Regex::new(r"(?:--port|-p)\s+(\d+)").ok()?;
    
    if let Some(captures) = re.captures(line) {
        if let Some(port_match) = captures.get(1) {
            return port_match.as_str().parse().ok();
        }
    }
    
    None
}

async fn get_server_metrics(address: &str) -> Result<ServerMetrics> {
    let client = reqwest::Client::new();
    let url = format!("http://{}/metrics", address);
    
    match timeout(Duration::from_secs(2), client.get(&url).send()).await {
        Ok(Ok(response)) if response.status().is_success() => {
            let metrics: serde_json::Value = response.json().await
                .map_err(|e| color_eyre::eyre::eyre!("Failed to parse metrics: {}", e))?;
            
            let metrics_data = metrics.get("metrics").ok_or_else(|| {
                color_eyre::eyre::eyre!("Missing metrics data in response")
            })?;
            
            Ok(ServerMetrics {
                requests_per_second: metrics_data.get("http_requests_per_second")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
                average_response_time_ms: metrics_data.get("http_request_duration_seconds")
                    .and_then(|v| v.as_f64())
                    .map(|v| (v * 1000.0) as u64)
                    .unwrap_or(0),
                active_connections: metrics_data.get("active_connections")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as usize,
                memory_usage_bytes: metrics_data.get("memory_usage_bytes")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
                cpu_usage_percent: metrics_data.get("cpu_usage_percent")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0),
            })
        }
        _ => Err(color_eyre::eyre::eyre!("Failed to get server metrics")),
    }
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    
    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}s", seconds)
    }
}

fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}
