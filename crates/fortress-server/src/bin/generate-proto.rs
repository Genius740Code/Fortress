use std::process::Command;

fn main() {
    println!("Generating gRPC code...");
    
    let output = Command::new("cargo")
        .args(&["run", "--bin", "generate-proto"])
        .current_dir("crates/fortress-server")
        .output()
        .expect("Failed to execute command");

    if !output.status.success() {
        eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }

    println!("gRPC code generated successfully!");
}
