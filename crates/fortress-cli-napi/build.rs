extern crate napi_build;

fn main() {
    // Check if fortress-cli is available
    if !fortress_cli_available() {
        eprintln!("Warning: fortress-cli not found. NAPI bindings may not work correctly.");
        eprintln!("Please build fortress-cli first: cargo build --bin fortress");
        std::process::exit(1);
    }
    
    // Try to setup NAPI, but don't fail if it doesn't work
    // This allows the CLI to build even if Node.js integration has issues
    match std::panic::catch_unwind(|| {
        napi_build::setup();
    }) {
        Ok(_) => {
            eprintln!("NAPI build completed successfully");
        }
        Err(_) => {
            eprintln!("Warning: NAPI build failed, but continuing...");
            eprintln!("This may limit Node.js integration functionality");
        }
    }
}

fn fortress_cli_available() -> bool {
    // Check if fortress-cli binary exists in target directory
    let target_dir = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_string());
    
    // Get the workspace root directory (parent of fortress-cli-napi)
    let workspace_root = std::env::current_dir()
        .map(|mut path| {
            path.pop(); // Go up from fortress-cli-napi to crates
            path.pop(); // Go up from crates to workspace root
            path
        })
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    
    // Try different possible paths for the fortress binary
    let possible_paths = [
        workspace_root.join(format!("{}/debug/fortress{}", target_dir, std::env::consts::EXE_SUFFIX)),
        workspace_root.join(format!("{}/fortress{}", target_dir, std::env::consts::EXE_SUFFIX)),
        workspace_root.join(format!("target/debug/fortress{}", std::env::consts::EXE_SUFFIX)),
    ];
    
    for path in &possible_paths {
        eprintln!("Checking for fortress binary at: {}", path.display());
        if path.exists() {
            eprintln!("Found fortress binary at: {}", path.display());
            return true;
        }
    }
    
    false
}
