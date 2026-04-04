use std::process::Command;

fn main() {
    println!("Generating gRPC code...");
    
    let output = match Command::new("cargo")
        .args(&["run", "--bin", "generate-proto"])
        .current_dir("crates/fortress-server")
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            eprintln!("Failed to execute command: {}", e);
            std::process::exit(1);
        }
    };

    if !output.status.success() {
        eprintln!("Error: {}", String::from_utf8_lossy(&output.stderr));
        std::process::exit(1);
    }

    println!("gRPC code generated successfully!");
}
