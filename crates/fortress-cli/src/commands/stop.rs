use color_eyre::eyre::Result;
use console::style;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn, error};
use serde_json;

pub async fn handle_stop() -> Result<()> {
    println!("{}", style("🛑 Stopping Fortress Server").bold().cyan());
    println!();
    
    // Check if server is running
    let server_info = match get_server_info().await {
        Ok(info) => info,
        Err(e) => {
            println!("{} No running Fortress server found.", style("ℹ️").blue());
            println!("Error: {}", e);
            return Ok(());
        }
    };
    
    println!("Server Information:");
    println!("  PID: {}", style(server_info.pid).bold());
    println!("  Address: {}", style(server_info.address).bold());
    println!("  Uptime: {}", style(format_duration(server_info.uptime)).bold());
    println!("  Version: {}", style(server_info.version).bold());
    println!();
    
    // Attempt graceful shutdown first
    println!("Attempting graceful shutdown...");
    
    match graceful_shutdown(&server_info).await {
        Ok(()) => {
            println!("✓ Fortress Server stopped gracefully");
            info!("Fortress server stopped gracefully (PID: {})", server_info.pid);
            return Ok(());
        }
        Err(e) => {
            warn!("Graceful shutdown failed: {}", e);
            println!("⚠ Graceful shutdown failed: {}", e);
        }
    }
    
    // If graceful shutdown fails, try force shutdown
    println!("Attempting force shutdown...");
    
    match force_shutdown(&server_info).await {
        Ok(()) => {
            println!("✓ Fortress Server stopped forcefully");
            info!("Fortress server stopped forcefully (PID: {})", server_info.pid);
        }
        Err(e) => {
            error!("Force shutdown failed: {}", e);
            println!("✗ Force shutdown failed: {}", e);
            println!("\nYou may need to manually kill the process:");
            println!("   kill -9 {}", server_info.pid);
            return Err(e);
        }
    }
    
    Ok(())
}

#[derive(Debug, Clone)]
struct ServerInfo {
    pid: u32,
    address: String,
    uptime: Duration,
    version: String,
}

async fn get_server_info() -> Result<ServerInfo> {
    // Try to get server info from status endpoint first
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
                    .ok_or_else(|| color_eyre::eyre::eyre!("Missing uptime information"))?;
                
                let version = server_data.get("version")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                
                return Ok(ServerInfo {
                    pid: get_pid_from_port(port).await.unwrap_or(0),
                    address: format!("127.0.0.1:{}", port),
                    uptime: Duration::from_secs(uptime_seconds),
                    version: version.to_string(),
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

async fn graceful_shutdown(server_info: &ServerInfo) -> Result<()> {
    let client = reqwest::Client::new();
    let shutdown_url = format!("http://{}/shutdown", server_info.address);
    
    // Send shutdown request
    match timeout(Duration::from_secs(10), client.post(&shutdown_url).send()).await {
        Ok(Ok(response)) if response.status().is_success() => {
            // Wait for server to actually stop
            for _ in 0..30 { // Wait up to 30 seconds
                tokio::time::sleep(Duration::from_secs(1)).await;
                
                if !is_server_running(server_info).await {
                    return Ok(());
                }
            }
            
            Err(color_eyre::eyre::eyre!("Server did not stop within timeout"))
        }
        Ok(Ok(response)) => {
            Err(color_eyre::eyre::eyre!("Shutdown request failed with status: {}", response.status()))
        }
        Ok(Err(e)) => {
            Err(color_eyre::eyre::eyre!("Failed to send shutdown request: {}", e))
        }
        Err(_) => {
            Err(color_eyre::eyre::eyre!("Shutdown request timeout"))
        }
    }
}

async fn force_shutdown(server_info: &ServerInfo) -> Result<()> {
    // Send SIGTERM signal
    let output = Command::new("kill")
        .args(&["-TERM", &server_info.pid.to_string()])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to send SIGTERM: {}", e))?;
    
    if !output.status.success() {
        return Err(color_eyre::eyre::eyre!("Failed to send SIGTERM signal"));
    }
    
    // Wait for graceful termination
    for _ in 0..10 { // Wait up to 10 seconds
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        if !is_server_running(server_info).await {
            return Ok(());
        }
    }
    
    // If still running, send SIGKILL
    warn!("Server did not respond to SIGTERM, sending SIGKILL");
    
    let output = Command::new("kill")
        .args(&["-KILL", &server_info.pid.to_string()])
        .output()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to send SIGKILL: {}", e))?;
    
    if !output.status.success() {
        return Err(color_eyre::eyre::eyre!("Failed to send SIGKILL signal"));
    }
    
    // Final wait
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        if !is_server_running(server_info).await {
            return Ok(());
        }
    }
    
    Err(color_eyre::eyre::eyre!("Failed to stop server with SIGKILL"))
}

async fn is_server_running(server_info: &ServerInfo) -> bool {
    // Check if process is still running
    if let Ok(output) = Command::new("kill").args(&["-0", &server_info.pid.to_string()]).output() {
        if output.status.success() {
            return true;
        }
    }
    
    // Check if port is still in use
    if let Ok(output) = Command::new("lsof")
        .args(&["-i", &format!(":{}", server_info.address.split(':').last().unwrap_or("8080"))])
        .output() 
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        return stdout.contains(&server_info.pid.to_string());
    }
    
    false
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
