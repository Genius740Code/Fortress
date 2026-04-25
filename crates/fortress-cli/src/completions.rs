use clap::{Command, Arg, ValueHint};
use clap_complete::{generate, Generator, Shell};
use crate::enhanced_error::FortressError;
use std::io;

pub fn build_cli() -> Command {
    Command::new("fortress")
        .version("1.0.2")
        .author("Genius740Code")
        .about("Enterprise security platform CLI")
        .subcommand_required(true)
        .arg_required_else_help(true)
        
        // Configuration command
        .subcommand(
            Command::new("config")
                .about("Configuration management")
                .subcommand(
                    Command::new("init")
                        .about("Initialize configuration")
                        .arg(Arg::new("interactive")
                            .long("interactive")
                            .short('i')
                            .help("Run interactive configuration wizard")
                            .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("show")
                        .about("Show current configuration")
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["toml", "json", "yaml"])
                            .default_value("toml")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate configuration")
                        .arg(Arg::new("config-file")
                            .long("config")
                            .short('c')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Configuration file to validate"))
                )
                .subcommand(
                    Command::new("test-database")
                        .about("Test database connection")
                        .arg(Arg::new("config")
                            .long("config")
                            .short('c')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Configuration file to use"))
                )
        )
        
        // Key management commands
        .subcommand(
            Command::new("key")
                .about("Key management operations")
                .subcommand_required(true)
                .subcommand(
                    Command::new("generate")
                        .about("Generate new encryption key")
                        .arg(Arg::new("algorithm")
                            .long("algorithm")
                            .short('a')
                            .value_parser(["aegis256", "chacha20", "aes256gcm", "hex64"])
                            .default_value("aegis256")
                            .help("Encryption algorithm"))
                        .arg(Arg::new("length")
                            .long("length")
                            .short('l')
                            .value_parser(["128", "256", "512", "64"])
                            .default_value("256")
                            .help("Key length in bits"))
                        .arg(Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Output file for the key"))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["hex", "base64", "binary", "raw"])
                            .default_value("hex")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("list")
                        .about("List all stored keys")
                        .arg(Arg::new("algorithm")
                            .long("algorithm")
                            .short('a')
                            .help("Filter by algorithm"))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["table", "json", "csv"])
                            .default_value("table")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("rotate")
                        .about("Rotate encryption key")
                        .arg(Arg::new("key-id")
                            .long("id")
                            .short('i')
                            .value_name("ID")
                            .help("Key ID to rotate")
                            .required(true))
                        .arg(Arg::new("force")
                            .long("force")
                            .short('f')
                            .help("Force rotation without confirmation")
                            .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("delete")
                        .about("Delete encryption key")
                        .arg(Arg::new("key-id")
                            .long("id")
                            .short('i')
                            .value_name("ID")
                            .help("Key ID to delete")
                            .required(true))
                        .arg(Arg::new("force")
                            .long("force")
                            .short('f')
                            .help("Force deletion without confirmation")
                            .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate key integrity")
                        .arg(Arg::new("key-id")
                            .long("id")
                            .short('i')
                            .value_name("ID")
                            .help("Key ID to validate")
                            .required(true))
                )
                .subcommand(
                    Command::new("export")
                        .about("Export key to file")
                        .arg(Arg::new("key-id")
                            .long("id")
                            .short('i')
                            .value_name("ID")
                            .help("Key ID to export")
                            .required(true))
                        .arg(Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Output file for the exported key")
                            .required(true))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["hex", "base64", "binary", "pem"])
                            .default_value("hex")
                            .help("Export format"))
                )
                .subcommand(
                    Command::new("import")
                        .about("Import key from file")
                        .arg(Arg::new("input")
                            .long("input")
                            .short('i')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Input file containing the key")
                            .required(true))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["hex", "base64", "binary", "pem"])
                            .default_value("hex")
                            .help("Import format"))
                        .arg(Arg::new("algorithm")
                            .long("algorithm")
                            .short('a')
                            .value_parser(["aegis256", "chacha20", "aes256gcm"])
                            .help("Algorithm for the imported key"))
                )
        )
        
        // Encryption commands
        .subcommand(
            Command::new("encrypt")
                .about("Encrypt data")
                .arg(Arg::new("input")
                    .long("input")
                    .short('i')
                    .value_name("FILE")
                    .value_hint(ValueHint::FilePath)
                    .help("Input file to encrypt")
                    .required(true))
                .arg(Arg::new("output")
                    .long("output")
                    .short('o')
                    .value_name("FILE")
                    .value_hint(ValueHint::FilePath)
                    .help("Output encrypted file"))
                .arg(Arg::new("key-id")
                    .long("key")
                    .short('k')
                    .value_name("ID")
                    .help("Key ID to use for encryption"))
                .arg(Arg::new("algorithm")
                    .long("algorithm")
                    .short('a')
                    .value_parser(["aegis256", "chacha20", "aes256gcm"])
                    .help("Override encryption algorithm"))
                .arg(Arg::new("progress")
                    .long("progress")
                    .short('p')
                    .help("Show progress bar")
                    .action(clap::ArgAction::SetTrue))
        )
        
        // Decryption commands
        .subcommand(
            Command::new("decrypt")
                .about("Decrypt data")
                .arg(Arg::new("input")
                    .long("input")
                    .short('i')
                    .value_name("FILE")
                    .value_hint(ValueHint::FilePath)
                    .help("Input file to decrypt")
                    .required(true))
                .arg(Arg::new("output")
                    .long("output")
                    .short('o')
                    .value_name("FILE")
                    .value_hint(ValueHint::FilePath)
                    .help("Output decrypted file"))
                .arg(Arg::new("key-id")
                    .long("key")
                    .short('k')
                    .value_name("ID")
                    .help("Key ID to use for decryption"))
                .arg(Arg::new("progress")
                    .long("progress")
                    .short('p')
                    .help("Show progress bar")
                    .action(clap::ArgAction::SetTrue))
        )
        
        // Server commands
        .subcommand(
            Command::new("server")
                .about("Server management")
                .subcommand(
                    Command::new("start")
                        .about("Start Fortress server")
                        .arg(Arg::new("config")
                            .long("config")
                            .short('c')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Configuration file"))
                        .arg(Arg::new("daemon")
                            .long("daemon")
                            .short('d')
                            .help("Run as daemon")
                            .action(clap::ArgAction::SetTrue))
                        .arg(Arg::new("port")
                            .long("port")
                            .short('p')
                            .value_name("PORT")
                            .help("Override port"))
                )
                .subcommand(
                    Command::new("status")
                        .about("Show server status")
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["json", "table"])
                            .default_value("table")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("stop")
                        .about("Stop Fortress server")
                        .arg(Arg::new("graceful")
                            .long("graceful")
                            .short('g')
                            .help("Graceful shutdown")
                            .action(clap::ArgAction::SetTrue))
                )
                .subcommand(
                    Command::new("restart")
                        .about("Restart Fortress server")
                        .arg(Arg::new("graceful")
                            .long("graceful")
                            .short('g')
                            .help("Graceful restart")
                            .action(clap::ArgAction::SetTrue))
                )
        )
        
        // Plugin commands
        .subcommand(
            Command::new("plugin")
                .about("Plugin management")
                .subcommand(
                    Command::new("list")
                        .about("List available plugins")
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["table", "json"])
                            .default_value("table")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("install")
                        .about("Install plugin")
                        .arg(Arg::new("url")
                            .long("url")
                            .short('u')
                            .value_name("URL")
                            .help("Plugin URL")
                            .required(true))
                        .arg(Arg::new("name")
                            .long("name")
                            .short('n')
                            .value_name("NAME")
                            .help("Plugin name"))
                )
                .subcommand(
                    Command::new("uninstall")
                        .about("Uninstall plugin")
                        .arg(Arg::new("name")
                            .long("name")
                            .short('n')
                            .value_name("NAME")
                            .help("Plugin name")
                            .required(true))
                )
                .subcommand(
                    Command::new("enable")
                        .about("Enable plugin")
                        .arg(Arg::new("name")
                            .long("name")
                            .short('n')
                            .value_name("NAME")
                            .help("Plugin name")
                            .required(true))
                )
                .subcommand(
                    Command::new("disable")
                        .about("Disable plugin")
                        .arg(Arg::new("name")
                            .long("name")
                            .short('n')
                            .value_name("NAME")
                            .help("Plugin name")
                            .required(true))
                )
        )
        
        // Compliance commands
        .subcommand(
            Command::new("compliance")
                .about("Compliance management")
                .subcommand(
                    Command::new("audit")
                        .about("Run compliance audit")
                        .arg(Arg::new("framework")
                            .long("framework")
                            .short('f')
                            .value_parser(["gdpr", "hipaa", "pci-dss", "soc2"])
                            .help("Compliance framework"))
                        .arg(Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Output report file"))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["json", "html", "pdf"])
                            .default_value("json")
                            .help("Report format"))
                )
                .subcommand(
                    Command::new("report")
                        .about("Generate compliance report")
                        .arg(Arg::new("framework")
                            .long("framework")
                            .short('f')
                            .value_parser(["gdpr", "hipaa", "pci-dss", "soc2"])
                            .help("Compliance framework")
                            .required(true))
                        .arg(Arg::new("period")
                            .long("period")
                            .short('p')
                            .value_parser(["daily", "weekly", "monthly", "quarterly", "yearly"])
                            .default_value("monthly")
                            .help("Reporting period"))
                        .arg(Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Output report file")
                            .required(true))
                )
                .subcommand(
                    Command::new("validate")
                        .about("Validate compliance status")
                        .arg(Arg::new("framework")
                            .long("framework")
                            .short('f')
                            .value_parser(["gdpr", "hipaa", "pci-dss", "soc2"])
                            .help("Compliance framework"))
                )
        )
        
        // Cluster commands
        .subcommand(
            Command::new("cluster")
                .about("Cluster management")
                .subcommand(
                    Command::new("init")
                        .about("Initialize cluster")
                        .arg(Arg::new("node-id")
                            .long("node-id")
                            .short('i')
                            .value_name("ID")
                            .help("Node ID")
                            .required(true))
                        .arg(Arg::new("seed-nodes")
                            .long("seed-nodes")
                            .short('s')
                            .value_name("NODES")
                            .help("Comma-separated list of seed nodes"))
                )
                .subcommand(
                    Command::new("join")
                        .about("Join existing cluster")
                        .arg(Arg::new("seed-node")
                            .long("seed-node")
                            .short('s')
                            .value_name("ADDRESS")
                            .help("Seed node address")
                            .required(true))
                        .arg(Arg::new("node-id")
                            .long("node-id")
                            .short('i')
                            .value_name("ID")
                            .help("Node ID")
                            .required(true))
                )
                .subcommand(
                    Command::new("status")
                        .about("Show cluster status")
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["json", "table"])
                            .default_value("table")
                            .help("Output format"))
                )
                .subcommand(
                    Command::new("nodes")
                        .about("List cluster nodes")
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["json", "table"])
                            .default_value("table")
                            .help("Output format"))
                )
        )
        
        // Utility commands
        .subcommand(
            Command::new("utils")
                .about("Utility commands")
                .subcommand(
                    Command::new("hash")
                        .about("Generate hash of data")
                        .arg(Arg::new("input")
                            .long("input")
                            .short('i')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Input file to hash"))
                        .arg(Arg::new("algorithm")
                            .long("algorithm")
                            .short('a')
                            .value_parser(["sha256", "sha512", "blake3"])
                            .default_value("sha256")
                            .help("Hash algorithm"))
                        .arg(Arg::new("data")
                            .long("data")
                            .short('d')
                            .value_name("DATA")
                            .help("Data to hash (instead of file)"))
                )
                .subcommand(
                    Command::new("encode")
                        .about("Encode data")
                        .arg(Arg::new("input")
                            .long("input")
                            .short('i')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Input file to encode"))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["hex", "base64", "base32"])
                            .default_value("base64")
                            .help("Encoding format"))
                        .arg(Arg::new("data")
                            .long("data")
                            .short('d')
                            .value_name("DATA")
                            .help("Data to encode (instead of file)"))
                )
                .subcommand(
                    Command::new("decode")
                        .about("Decode data")
                        .arg(Arg::new("input")
                            .long("input")
                            .short('i')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Input file to decode"))
                        .arg(Arg::new("format")
                            .long("format")
                            .short('f')
                            .value_parser(["hex", "base64", "base32"])
                            .default_value("base64")
                            .help("Decoding format"))
                        .arg(Arg::new("output")
                            .long("output")
                            .short('o')
                            .value_name("FILE")
                            .value_hint(ValueHint::FilePath)
                            .help("Output decoded file"))
                )
        )
        
        // Completion command
        .subcommand(
            Command::new("completions")
                .about("Generate shell completions")
                .arg(Arg::new("shell")
                    .value_parser(["bash", "zsh", "fish", "elvish", "powershell"])
                    .help("Shell type")
                    .required(true))
                .arg(Arg::new("output")
                    .long("output")
                    .short('o')
                    .value_name("FILE")
                    .value_hint(ValueHint::FilePath)
                    .help("Output file (default: stdout)"))
        )
        
        // Version command
        .subcommand(
            Command::new("version")
                .about("Show version information")
                .arg(Arg::new("detailed")
                    .long("detailed")
                    .short('d')
                    .help("Show detailed version information")
                    .action(clap::ArgAction::SetTrue))
        )
}

pub fn generate_completions<G: Generator>(shell: G, output: &mut dyn io::Write) -> Result<(), FortressError> {
    let mut cmd = build_cli();
    let name = "fortress";
    generate(shell, &mut cmd, name, output);
    Ok(())
}

// Example shell completion generation
pub fn install_completions() -> Result<(), FortressError> {
    let home_dir = dirs::home_dir()
        .ok_or_else(|| FortressError::io_error("Cannot find home directory"))?;
    
    let completions_dir = match std::env::consts::OS {
        "linux" | "macos" => {
            let dir = home_dir.join(".local").join("share").join("bash-completion").join("completions");
            std::fs::create_dir_all(&dir)
                .map_err(|e| FortressError::io_error(format!("Failed to create completions directory: {}", e)))?;
            dir
        },
        "windows" => {
            let dir = home_dir.join("AppData").join("Local").join("fortress").join("completions");
            std::fs::create_dir_all(&dir)
                .map_err(|e| FortressError::io_error(format!("Failed to create completions directory: {}", e)))?;
            dir
        },
        _ => {
            return Err(FortressError::io_error("Unsupported operating system for completions"));
        }
    };
    
    // Generate bash completions
    let bash_file = completions_dir.join("fortress");
    let mut bash_output = std::fs::File::create(&bash_file)
        .map_err(|e| FortressError::io_error(format!("Failed to create bash completion file: {}", e)))?;
    generate_completions(clap_complete::shells::Bash, &mut bash_output)?;
    
    // Generate zsh completions
    let zsh_dir = home_dir.join(".local").join("share").join("zsh").join("site-functions");
    std::fs::create_dir_all(&zsh_dir)
        .map_err(|e| FortressError::io_error(format!("Failed to create zsh completions directory: {}", e)))?;
    let zsh_file = zsh_dir.join("_fortress");
    let mut zsh_output = std::fs::File::create(&zsh_file)
        .map_err(|e| FortressError::io_error(format!("Failed to create zsh completion file: {}", e)))?;
    generate_completions(clap_complete::shells::Zsh, &mut zsh_output)?;
    
    // Generate fish completions
    let fish_dir = home_dir.join(".local").join("share").join("fish").join("completions");
    std::fs::create_dir_all(&fish_dir)
        .map_err(|e| FortressError::io_error(format!("Failed to create fish completions directory: {}", e)))?;
    let fish_file = fish_dir.join("fortress.fish");
    let mut fish_output = std::fs::File::create(&fish_file)
        .map_err(|e| FortressError::io_error(format!("Failed to create fish completion file: {}", e)))?;
    generate_completions(clap_complete::shells::Fish, &mut fish_output)?;
    
    println!("✅ Shell completions installed:");
    println!("  Bash: {}", bash_file.display());
    println!("  Zsh: {}", zsh_file.display());
    println!("  Fish: {}", fish_file.display());
    
    println!("\n📝 To enable completions:");
    match std::env::consts::OS {
        "linux" => {
            println!("  Bash: Add 'source ~/.local/share/bash-completion/completions/fortress' to ~/.bashrc");
            println!("  Zsh: Add 'fpath+=~/.local/share/zsh/site-functions' to ~/.zshrc");
            println!("  Fish: Completions are automatically loaded");
        },
        "macos" => {
            println!("  Bash: Add 'source ~/.local/share/bash-completion/completions/fortress' to ~/.bash_profile");
            println!("  Zsh: Add 'fpath+=~/.local/share/zsh/site-functions' to ~/.zshrc");
            println!("  Fish: Completions are automatically loaded");
        },
        "windows" => {
            println!("  PowerShell: Add the completions directory to your path and run:");
            println!("    Import-Module {}", completions_dir.join("fortress.ps1").display());
        },
        _ => {}
    }
    
    Ok(())
}

pub fn print_completion_script(shell: &str) -> Result<(), FortressError> {
    match shell {
        "bash" => {
            generate_completions(clap_complete::shells::Bash, &mut std::io::stdout())
        }
        "zsh" => {
            generate_completions(clap_complete::shells::Zsh, &mut std::io::stdout())
        }
        "fish" => {
            generate_completions(clap_complete::shells::Fish, &mut std::io::stdout())
        }
        "elvish" => {
            generate_completions(clap_complete::shells::Elvish, &mut std::io::stdout())
        }
        "powershell" => {
            generate_completions(clap_complete::shells::PowerShell, &mut std::io::stdout())
        }
        _ => return Err(FortressError::io_error(format!("Unsupported shell: {}", shell))),
    };
    
    Ok(())
}

// Custom completion functions for dynamic values
pub mod dynamic_completions {
    use crate::enhanced_error::FortressError;
    // use fortress_core::key_management::KeyManager; // TODO: Implement when key_management module is available
    
    pub async fn complete_key_ids() -> Result<Vec<String>, FortressError> {
        // This would integrate with the actual key manager
        // For now, return some example completions
        Ok(vec![
            "key_001".to_string(),
            "key_002".to_string(),
            "key_003".to_string(),
            "aes256_key_2024".to_string(),
            "chacha20_key_2024".to_string(),
        ])
    }
    
    pub async fn complete_algorithms() -> Vec<String> {
        vec![
            "aegis256".to_string(),
            "chacha20".to_string(),
            "aes256gcm".to_string(),
            "sha256".to_string(),
            "sha512".to_string(),
            "blake3".to_string(),
        ]
    }
    
    pub async fn complete_config_files() -> Vec<String> {
        let mut configs = Vec::new();
        
        // Add common config locations
        if let Some(home) = dirs::home_dir() {
            configs.push(home.join(".fortress").join("config.toml").to_string_lossy().to_string());
            configs.push(home.join(".config").join("fortress").join("config.toml").to_string_lossy().to_string());
        }
        
        // Add current directory config
        if let Ok(current_dir) = std::env::current_dir() {
            configs.push(current_dir.join("fortress.toml").to_string_lossy().to_string());
            configs.push(current_dir.join("config.toml").to_string_lossy().to_string());
        }
        
        // Filter to only existing files
        configs.retain(|path| std::path::Path::new(path).exists());
        
        configs
    }
    
    pub async fn complete_plugins() -> Vec<String> {
        // This would scan the plugin directory
        vec![
            "auth-plugin".to_string(),
            "crypto-plugin".to_string(),
            "audit-plugin".to_string(),
            "policy-plugin".to_string(),
        ]
    }
}
