extern crate napi_build;

fn main() {
    // Check if Node.js is available for NAPI build
    if std::env::var("NODE_PATH").is_err() && !nodejs_available() {
        eprintln!("Warning: Node.js not found. NAPI build may fail.");
        eprintln!("Please install Node.js and ensure it's in your PATH.");
        eprintln!("You can skip NAPI build with: cargo build --workspace --exclude fortress-cli-napi");
        std::process::exit(1);
    }
    
    // Check if fortress-cli is available
    if !fortress_cli_available() {
        eprintln!("Warning: fortress-cli not found. NAPI bindings may not work correctly.");
        eprintln!("Please build fortress-cli first: cargo build --bin fortress");
        std::process::exit(1);
    }
    
    napi_build::setup();
}

fn nodejs_available() -> bool {
    // Try to find Node.js in common locations
    let node_commands = ["node", "node.exe", "node.cmd"];
    
    for cmd in node_commands {
        if std::process::Command::new(cmd)
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
        {
            return true;
        }
    }
    
    false
}

fn fortress_cli_available() -> bool {
    // Check if fortress-cli binary exists in target directory
    let _target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    let cli_path = format!("{}/fortress{}", _target_dir, std::env::consts::EXE_SUFFIX);
    
    std::path::Path::new(&cli_path).exists()
}
