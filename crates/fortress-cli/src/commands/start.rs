use color_eyre::eyre::Result;
use console::style;
use std::path::PathBuf;
use std::net::SocketAddr;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::signal;
use tokio::sync::oneshot;
use tracing::{info, warn, error};
use tower::ServiceBuilder;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use hyper::Server;
use hyper::service::{make_service_fn, service_fn};
use crate::commands::config::{get_config_path, load_or_create_config, ConfigSettings as FortressConfig};

// Simple placeholder FortressServer for compilation
#[derive(Clone)]
struct FortressServer {
    config: FortressConfig,
}

impl FortressServer {
    fn new(config: FortressConfig) -> Self {
        Self { config }
    }
    
    // Placeholder methods for compilation
    async fn handle_request(&self, _req: hyper::Request<hyper::Body>) -> hyper::Response<hyper::Body> {
        hyper::Response::new(hyper::Body::from("Fortress Server"))
    }
    
    async fn health_check(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({"status": "healthy"}))
    }
    
    async fn get_status(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({"server": {"status": "running"}}))
    }
    
    async fn get_metrics(&self) -> Result<serde_json::Value> {
        Ok(serde_json::json!({"metrics": {"requests": 0}}))
    }
}

pub async fn handle_start(
    data_dir: Option<String>,
    port: u16,
    host: String,
) -> Result<()> {
    println!("{}", style("🚀 Starting Fortress Server").bold().cyan());
    println!();
    
    // Validate and resolve data directory
    let db_path = PathBuf::from(data_dir.unwrap_or_else(|| "./fortress".to_string()));
    
    if !db_path.exists() {
        return Err(color_eyre::eyre::eyre!(
            "Database directory not found: {}. Use 'fortress create' first.",
            db_path.display()
        ));
    }
    
    // Load configuration
    let config_path = get_config_path()?;
    let config_settings = load_or_create_config(&config_path).await?;
    
    // Override with command line arguments if provided
    let mut config_settings = config_settings;
    if port != 8080 {
        config_settings.server.port = port;
    }
    if host != "127.0.0.1" {
        config_settings.server.host = host;
    }
    
    // Validate configuration
    validate_server_config(&config_settings)?;
    
    // Create server address
    let addr_str = format!("{}:{}", config_settings.server.host, config_settings.server.port);
    let addr: SocketAddr = addr_str.parse()
        .map_err(|e| color_eyre::eyre::eyre!("Invalid address {}: {}", addr_str, e))?;
    
    info!("Starting Fortress server on {}", addr);
    info!("Data directory: {}", db_path.display());
    info!("Worker threads: {}", config_settings.server.workers);
    
    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    
    // Initialize Fortress server
    let fortress_config = create_fortress_config(&config_settings, &db_path)?;
    let fortress_server = Arc::new(FortressServer::new(fortress_config));
    
    // Start server in background
    let server_handle = start_fortress_server(
        addr, 
        fortress_server.clone(), 
        config_settings.server.workers,
        shutdown_rx
    ).await?;
    
    println!("✅ Fortress Server started successfully!");
    println!("🌐 Server URL: http://{}", addr);
    println!("📁 Data directory: {}", style(db_path.display()).bold());
    println!("🔧 Worker threads: {}", style(config_settings.server.workers).bold());
    println!("📊 Health check: http://{}/health", addr);
    println!();
    println!("Press Ctrl+C to stop the server");
    
    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("\n{}", style("🛑 Shutting down Fortress Server...").bold().yellow());
            
            // Send shutdown signal
            let _ = shutdown_tx.send(());
            
            // Wait for server to shutdown with timeout
            match tokio::time::timeout(Duration::from_secs(30), server_handle).await {
                Ok(Ok(())) => {
                    println!("✅ Fortress Server stopped gracefully");
                }
                Ok(Err(e)) => {
                    warn!("Server shutdown with error: {}", e);
                }
                Err(_) => {
                    warn!("Server shutdown timeout - forcing exit");
                }
            }
        }
        Err(e) => {
            error!("Failed to listen for shutdown signal: {}", e);
            return Err(color_eyre::eyre::eyre!("Shutdown signal error: {}", e));
        }
    }
    
    Ok(())
}

fn validate_server_config(config: &FortressConfig) -> Result<()> {
    // Validate host
    if config.server.host.is_empty() {
        return Err(color_eyre::eyre::eyre!("Server host cannot be empty"));
    }
    
    // Validate port
    if config.server.port == 0 || config.server.port > 65535 {
        return Err(color_eyre::eyre::eyre!("Server port must be between 1 and 65535"));
    }
    
    // Validate workers
    if config.server.workers == 0 || config.server.workers > 1024 {
        return Err(color_eyre::eyre::eyre!("Worker count must be between 1 and 1024"));
    }
    
    Ok(())
}

fn create_fortress_config(config_settings: &FortressConfig, db_path: &PathBuf) -> Result<FortressConfig> {
    // For now, just clone the config since we don't have a real FortressConfig from fortress_core
    Ok(config_settings.clone())
}

async fn start_fortress_server(
    addr: SocketAddr,
    fortress_server: Arc<FortressServer>,
    worker_threads: usize,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<tokio::task::JoinHandle<()>> {
    // Create simple service without complex middleware
    let service = make_service_fn(move |_conn| {
        let fortress_server = fortress_server.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                let fortress_server = fortress_server.clone();
                async move {
                    Ok::<_, Infallible>(handle_request(req, fortress_server).await)
                }
            }))
        }
    });
    
    // Create server with graceful shutdown
    let server = Server::bind(&addr).serve(service);
    let graceful = server.with_graceful_shutdown(async {
        shutdown_rx.await.ok();
    });
    
    // Set up runtime with custom worker threads
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .thread_name("fortress-worker")
        .enable_all()
        .build()
        .map_err(|e| color_eyre::eyre::eyre!("Failed to create runtime: {}", e))?;
    
    // Start server in background task
    let handle = tokio::spawn(async move {
        if let Err(e) = graceful.await {
            error!("Server error: {}", e);
        }
    });
    
    Ok(handle)
}

async fn handle_request(
    req: hyper::Request<hyper::Body>,
    fortress_server: Arc<FortressServer>,
) -> hyper::Response<hyper::Body> {
    let path = req.uri().path();
    let method = req.method();
    
    info!("{} {}", method, path);
    
    match (method.as_str(), path) {
        ("GET", "/health") => {
            handle_health_check(fortress_server).await.unwrap_or_else(|_| {
                hyper::Response::builder()
                    .status(500)
                    .body(hyper::Body::from("Internal Server Error"))
                    .unwrap()
            })
        }
        ("GET", "/status") => {
            handle_status_check(fortress_server).await.unwrap_or_else(|_| {
                hyper::Response::builder()
                    .status(500)
                    .body(hyper::Body::from("Internal Server Error"))
                    .unwrap()
            })
        }
        ("GET", "/metrics") => {
            handle_metrics(fortress_server).await.unwrap_or_else(|_| {
                hyper::Response::builder()
                    .status(500)
                    .body(hyper::Body::from("Internal Server Error"))
                    .unwrap()
            })
        }
        _ => {
            hyper::Response::builder()
                .status(404)
                .body(hyper::Body::from("Not Found"))
                .unwrap()
        }
    }
}

async fn handle_health_check(fortress_server: Arc<FortressServer>) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let health_result = fortress_server.health_check().await.unwrap_or_else(|_| {
        serde_json::json!({"status": "unhealthy"})
    });
    let is_healthy = health_result.get("status")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    
    let status = if is_healthy { "healthy" } else { "unhealthy" };
    let body = serde_json::json!({
        "status": status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    });
    
    Ok(hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("content-type", "application/json")
        .body(hyper::Body::from(body.to_string()))
        .unwrap())
}

async fn handle_status_check(fortress_server: Arc<FortressServer>) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let status_result = fortress_server.get_status().await.unwrap_or_else(|_| {
        serde_json::json!({"status": "unknown"})
    });
    
    let body = serde_json::json!({
        "server": status_result,
        "database": {
            "connected": true,
            "connections": 1,
            "max_connections": 100
        },
        "performance": {
            "requests_per_second": 0.0,
            "average_response_time_ms": 0
        }
    });
    
    Ok(hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("content-type", "application/json")
        .body(hyper::Body::from(body.to_string()))
        .unwrap())
}

async fn handle_metrics(fortress_server: Arc<FortressServer>) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let metrics_result = fortress_server.get_metrics().await.unwrap_or_else(|_| {
        serde_json::json!({"requests": 0})
    });
    
    let body = serde_json::json!({
        "metrics": metrics_result,
        "extra": {
            "http_requests_total": 0,
            "http_request_duration_seconds": 0.0,
            "active_connections": 0,
            "database_operations_total": 0,
            "encryption_operations_total": 0,
            "memory_usage_bytes": 0,
            "cpu_usage_percent": 0.0
        }
    });
    
    Ok(hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("content-type", "application/json")
        .body(hyper::Body::from(body.to_string()))
        .unwrap())
}
