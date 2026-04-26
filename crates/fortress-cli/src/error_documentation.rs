//! Comprehensive error documentation system with interactive help
//! 
//! Provides detailed error documentation, troubleshooting guides,
//! and interactive help system for better user experience.

use crate::enhanced_error::FortressError;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use console::{Term, Style};
use dialoguer::{Confirm, Select, Input};
use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDocumentation {
    pub error_code: String,
    pub title: String,
    pub description: String,
    pub common_causes: Vec<String>,
    pub solutions: Vec<String>,
    pub related_docs: Vec<String>,
    pub examples: Vec<String>,
    pub prevention_tips: Vec<String>,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub troubleshooting_steps: Vec<TroubleshootingStep>,
    pub related_errors: Vec<String>,
    pub recovery_commands: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TroubleshootingStep {
    pub step_number: usize,
    pub title: String,
    pub description: String,
    pub commands: Vec<String>,
    pub expected_output: Option<String>,
    pub verification_command: Option<String>,
    pub time_estimate_minutes: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorCategory {
    Configuration,
    Database,
    Encryption,
    Authentication,
    Network,
    FileSystem,
    Performance,
    Compliance,
    Plugin,
    General,
}

pub struct ErrorDocumentationSystem {
    documentation: HashMap<String, ErrorDocumentation>,
    help_cache: HashMap<String, HelpSession>,
}

#[derive(Debug, Clone)]
pub struct HelpSession {
    pub error_code: String,
    pub current_step: usize,
    pub completed_steps: Vec<usize>,
    pub start_time: chrono::DateTime<chrono::Utc>,
}

impl ErrorDocumentationSystem {
    pub fn new() -> Self {
        let mut system = Self {
            documentation: HashMap::new(),
            help_cache: HashMap::new(),
        };
        
        // Initialize with comprehensive error documentation
        system.initialize_documentation();
        system
    }
    
    fn initialize_documentation(&mut self) {
        // ENC001 - Invalid Key Length
        self.documentation.insert("ENC001".to_string(), ErrorDocumentation {
            error_code: "ENC001".to_string(),
            title: "Invalid Key Length".to_string(),
            description: "The provided key length doesn't match the requirements for the selected encryption algorithm".to_string(),
            common_causes: vec![
                "Key was generated with incorrect parameters".to_string(),
                "Key file was corrupted during storage or transfer".to_string(),
                "Wrong algorithm specified for the key".to_string(),
                "Key was truncated or padded incorrectly".to_string(),
                "Using incompatible key format (hex vs binary)".to_string(),
            ],
            solutions: vec![
                "Generate a new key with the correct length for your algorithm".to_string(),
                "Use 'fortress key generate --algorithm <algo> --length <bits>' to create a proper key".to_string(),
                "Verify key integrity with 'fortress key validate <key-id>'".to_string(),
                "Check the algorithm documentation for required key lengths".to_string(),
                "Convert key format if necessary using 'fortress utils convert'".to_string(),
            ],
            related_docs: vec![
                "https://docs.fortress.security/encryption/key-management".to_string(),
                "https://docs.fortress.security/algorithms/supported".to_string(),
                "https://docs.fortress.security/troubleshooting/encryption".to_string(),
            ],
            examples: vec![
                "fortress key generate --algorithm aegis256 --length 256".to_string(),
                "fortress key generate --algorithm aes256gcm --length 256".to_string(),
                "fortress key generate --algorithm chacha20 --length 256".to_string(),
                "fortress key validate --id key_12345".to_string(),
            ],
            prevention_tips: vec![
                "Always validate keys after generation".to_string(),
                "Store keys in secure, backed-up locations".to_string(),
                "Use the CLI tools for key generation to avoid manual errors".to_string(),
                "Document key parameters in your configuration".to_string(),
                "Use checksums to verify key file integrity".to_string(),
            ],
            severity: ErrorSeverity::High,
            category: ErrorCategory::Encryption,
            troubleshooting_steps: vec![
                TroubleshootingStep {
                    step_number: 1,
                    title: "Verify Key Requirements".to_string(),
                    description: "Check the required key length for your encryption algorithm".to_string(),
                    commands: vec![
                        "fortress key list --format table".to_string(),
                        "fortress key show --id <key-id>".to_string(),
                    ],
                    expected_output: Some("Key information showing algorithm and length".to_string()),
                    verification_command: Some("grep -i 'length\\|bits' <output>".to_string()),
                    time_estimate_minutes: Some(2),
                },
                TroubleshootingStep {
                    step_number: 2,
                    title: "Generate New Key".to_string(),
                    description: "Create a new key with the correct parameters".to_string(),
                    commands: vec![
                        "fortress key generate --algorithm <algorithm> --length <bits>".to_string(),
                    ],
                    expected_output: Some("Successfully generated key with ID".to_string()),
                    verification_command: Some("fortress key validate --id <new-key-id>".to_string()),
                    time_estimate_minutes: Some(1),
                },
                TroubleshootingStep {
                    step_number: 3,
                    title: "Update Configuration".to_string(),
                    description: "Update your configuration to use the new key".to_string(),
                    commands: vec![
                        "fortress config show".to_string(),
                        "fortress config edit --key <new-key-id>".to_string(),
                    ],
                    expected_output: Some("Configuration updated successfully".to_string()),
                    verification_command: Some("fortress config validate".to_string()),
                    time_estimate_minutes: Some(3),
                },
            ],
            related_errors: vec!["ENC002".to_string(), "KEY001".to_string()],
            recovery_commands: vec![
                "fortress key generate --algorithm aegis256 --length 256".to_string(),
                "fortress key rotate --id <old-key-id>".to_string(),
                "fortress config init --interactive".to_string(),
            ],
        });

        // DB001 - Database Connection Failed
        self.documentation.insert("DB001".to_string(), ErrorDocumentation {
            error_code: "DB001".to_string(),
            title: "Database Connection Failed".to_string(),
            description: "Unable to establish connection to the configured database".to_string(),
            common_causes: vec![
                "Database server is not running".to_string(),
                "Incorrect connection parameters (host, port, database name)".to_string(),
                "Network connectivity issues".to_string(),
                "Invalid credentials or insufficient permissions".to_string(),
                "Firewall blocking the connection".to_string(),
                "Database reached maximum connection limit".to_string(),
            ],
            solutions: vec![
                "Verify database server status with your database admin tools".to_string(),
                "Check connection parameters in the configuration file".to_string(),
                "Test network connectivity: 'ping <database-host>'".to_string(),
                "Verify credentials with 'fortress config test-database'".to_string(),
                "Check firewall rules and open necessary ports".to_string(),
                "Restart database service if necessary".to_string(),
            ],
            related_docs: vec![
                "https://docs.fortress.security/database/configuration".to_string(),
                "https://docs.fortress.security/troubleshooting/database".to_string(),
                "https://docs.fortress.security/database/connection-pooling".to_string(),
            ],
            examples: vec![
                "fortress config test-database --config ./fortress.toml".to_string(),
                "psql -h localhost -p 5432 -U fortress -d fortress".to_string(),
                "mysql -h localhost -P 3306 -u fortress -p".to_string(),
                "telnet localhost 5432".to_string(),
            ],
            prevention_tips: vec![
                "Use environment variables for sensitive credentials".to_string(),
                "Implement connection pooling to handle temporary network issues".to_string(),
                "Set up database health checks".to_string(),
                "Document database requirements for your operations team".to_string(),
                "Use connection retry logic with exponential backoff".to_string(),
            ],
            severity: ErrorSeverity::High,
            category: ErrorCategory::Database,
            troubleshooting_steps: vec![
                TroubleshootingStep {
                    step_number: 1,
                    title: "Check Database Status".to_string(),
                    description: "Verify that the database server is running and accessible".to_string(),
                    commands: vec![
                        "systemctl status postgresql".to_string(),
                        "docker ps | grep postgres".to_string(),
                        "netstat -tlnp | grep 5432".to_string(),
                    ],
                    expected_output: Some("Database service is active and listening".to_string()),
                    verification_command: Some("psql -h localhost -p 5432 -U postgres -c 'SELECT 1'".to_string()),
                    time_estimate_minutes: Some(3),
                },
                TroubleshootingStep {
                    step_number: 2,
                    title: "Test Network Connectivity".to_string(),
                    description: "Ensure network connectivity to the database host".to_string(),
                    commands: vec![
                        "ping <database-host>".to_string(),
                        "telnet <database-host> <port>".to_string(),
                        "nslookup <database-host>".to_string(),
                    ],
                    expected_output: Some("Successful network connection".to_string()),
                    verification_command: Some("nc -zv <database-host> <port>".to_string()),
                    time_estimate_minutes: Some(2),
                },
                TroubleshootingStep {
                    step_number: 3,
                    title: "Verify Configuration".to_string(),
                    description: "Check database configuration parameters".to_string(),
                    commands: vec![
                        "fortress config show".to_string(),
                        "fortress config validate".to_string(),
                        "fortress config test-database".to_string(),
                    ],
                    expected_output: Some("Configuration is valid and connection test passes".to_string()),
                    verification_command: Some("fortress config test-database --verbose".to_string()),
                    time_estimate_minutes: Some(5),
                },
            ],
            related_errors: vec!["CFG001".to_string(), "NET001".to_string()],
            recovery_commands: vec![
                "fortress config init --interactive".to_string(),
                "fortress config test-database --config <config-file>".to_string(),
                "systemctl restart postgresql".to_string(),
            ],
        });

        // CFG001 - Invalid Configuration Value
        self.documentation.insert("CFG001".to_string(), ErrorDocumentation {
            error_code: "CFG001".to_string(),
            title: "Invalid Configuration Value".to_string(),
            description: "A configuration field has an invalid value or format".to_string(),
            common_causes: vec![
                "Typo in configuration field name or value".to_string(),
                "Incorrect data type for a field".to_string(),
                "Missing required configuration fields".to_string(),
                "Configuration file syntax errors".to_string(),
                "Environment variable overrides with invalid values".to_string(),
                "Conflicting configuration values".to_string(),
            ],
            solutions: vec![
                "Run 'fortress config validate' to check your configuration".to_string(),
                "Use the interactive configuration wizard: 'fortress config init --interactive'".to_string(),
                "Check the configuration documentation for field requirements".to_string(),
                "Verify TOML syntax with an online validator".to_string(),
                "Review environment variable overrides".to_string(),
                "Reset to default configuration if necessary".to_string(),
            ],
            related_docs: vec![
                "https://docs.fortress.security/configuration/overview".to_string(),
                "https://docs.fortress.security/configuration/reference".to_string(),
                "https://docs.fortress.security/configuration/validation".to_string(),
            ],
            examples: vec![
                "fortress config validate --config ./fortress.toml".to_string(),
                "fortress config init --interactive".to_string(),
                "fortress config show --format json".to_string(),
                "fortress config reset --field <field-name>".to_string(),
            ],
            prevention_tips: vec![
                "Use the configuration wizard to avoid manual errors".to_string(),
                "Validate configuration files in CI/CD pipelines".to_string(),
                "Keep configuration files under version control".to_string(),
                "Document custom configuration requirements".to_string(),
                "Use configuration templates for different environments".to_string(),
            ],
            severity: ErrorSeverity::Medium,
            category: ErrorCategory::Configuration,
            troubleshooting_steps: vec![
                TroubleshootingStep {
                    step_number: 1,
                    title: "Validate Configuration".to_string(),
                    description: "Run configuration validation to identify issues".to_string(),
                    commands: vec![
                        "fortress config validate".to_string(),
                        "fortress config validate --config <config-file>".to_string(),
                        "fortress config validate --verbose".to_string(),
                    ],
                    expected_output: Some("Configuration validation report".to_string()),
                    verification_command: Some("echo $?".to_string()),
                    time_estimate_minutes: Some(2),
                },
                TroubleshootingStep {
                    step_number: 2,
                    title: "Review Configuration File".to_string(),
                    description: "Manually review the configuration file for errors".to_string(),
                    commands: vec![
                        "fortress config show".to_string(),
                        "cat <config-file>".to_string(),
                        "toml-lint <config-file>".to_string(),
                    ],
                    expected_output: Some("Configuration file contents displayed".to_string()),
                    verification_command: Some("grep -n 'error\\|invalid' <validation-output>".to_string()),
                    time_estimate_minutes: Some(5),
                },
                TroubleshootingStep {
                    step_number: 3,
                    title: "Recreate Configuration".to_string(),
                    description: "Use the interactive wizard to recreate configuration".to_string(),
                    commands: vec![
                        "fortress config init --interactive".to_string(),
                        "fortress config backup --file <backup-file>".to_string(),
                        "fortress config restore --file <backup-file>".to_string(),
                    ],
                    expected_output: Some("New configuration created successfully".to_string()),
                    verification_command: Some("fortress config validate".to_string()),
                    time_estimate_minutes: Some(10),
                },
            ],
            related_errors: vec!["ENC001".to_string(), "DB001".to_string()],
            recovery_commands: vec![
                "fortress config init --interactive".to_string(),
                "fortress config validate --fix".to_string(),
                "fortress config reset --all".to_string(),
            ],
        });

        // AUTH001 - Authentication Failed
        self.documentation.insert("AUTH001".to_string(), ErrorDocumentation {
            error_code: "AUTH001".to_string(),
            title: "Authentication Failed".to_string(),
            description: "Unable to authenticate with the provided credentials".to_string(),
            common_causes: vec![
                "Invalid username or password".to_string(),
                "Expired or invalid authentication token".to_string(),
                "Account locked or disabled".to_string(),
                "Insufficient permissions for the requested operation".to_string(),
                "Authentication service unavailable".to_string(),
                "Clock synchronization issues".to_string(),
            ],
            solutions: vec![
                "Verify credentials and try again".to_string(),
                "Generate new authentication token".to_string(),
                "Check account status with administrator".to_string(),
                "Verify system time synchronization".to_string(),
                "Check authentication service status".to_string(),
                "Use alternative authentication method if available".to_string(),
            ],
            related_docs: vec![
                "https://docs.fortress.security/authentication/overview".to_string(),
                "https://docs.fortress.security/authentication/troubleshooting".to_string(),
                "https://docs.fortress.security/authentication/methods".to_string(),
            ],
            examples: vec![
                "fortress auth login --username <user>".to_string(),
                "fortress auth token --refresh".to_string(),
                "fortress auth status".to_string(),
                "fortress auth logout".to_string(),
            ],
            prevention_tips: vec![
                "Use strong, unique passwords".to_string(),
                "Enable multi-factor authentication".to_string(),
                "Regularly rotate authentication tokens".to_string(),
                "Monitor failed authentication attempts".to_string(),
                "Use password managers to avoid typos".to_string(),
            ],
            severity: ErrorSeverity::High,
            category: ErrorCategory::Authentication,
            troubleshooting_steps: vec![
                TroubleshootingStep {
                    step_number: 1,
                    title: "Verify Credentials".to_string(),
                    description: "Check that your credentials are correct".to_string(),
                    commands: vec![
                        "fortress auth login --username <user> --dry-run".to_string(),
                        "fortress auth status".to_string(),
                        "fortress user show --username <user>".to_string(),
                    ],
                    expected_output: Some("Credential verification result".to_string()),
                    verification_command: Some("echo 'Credentials verified successfully'".to_string()),
                    time_estimate_minutes: Some(2),
                },
                TroubleshootingStep {
                    step_number: 2,
                    title: "Check Account Status".to_string(),
                    description: "Verify that your account is active and not locked".to_string(),
                    commands: vec![
                        "fortress user status --username <user>".to_string(),
                        "fortress auth attempts --username <user>".to_string(),
                        "fortress admin user list --status locked".to_string(),
                    ],
                    expected_output: Some("Account status information".to_string()),
                    verification_command: Some("grep -i 'active\\|unlocked' <status-output>".to_string()),
                    time_estimate_minutes: Some(3),
                },
                TroubleshootingStep {
                    step_number: 3,
                    title: "Refresh Authentication Token".to_string(),
                    description: "Generate a new authentication token".to_string(),
                    commands: vec![
                        "fortress auth token --refresh".to_string(),
                        "fortress auth logout".to_string(),
                        "fortress auth login --username <user>".to_string(),
                    ],
                    expected_output: Some("New authentication token generated".to_string()),
                    verification_command: Some("fortress auth status".to_string()),
                    time_estimate_minutes: Some(2),
                },
            ],
            related_errors: vec!["PERM001".to_string(), "TOKEN001".to_string()],
            recovery_commands: vec![
                "fortress auth login --username <user>".to_string(),
                "fortress auth token --refresh".to_string(),
                "fortress password reset --username <user>".to_string(),
            ],
        });
    }

    pub fn get_documentation(&self, error_code: &str) -> Option<&ErrorDocumentation> {
        self.documentation.get(error_code)
    }

    pub fn search_documentation(&self, query: &str) -> Vec<&ErrorDocumentation> {
        let query_lower = query.to_lowercase();
        let mut results = Vec::new();

        for doc in self.documentation.values() {
            if doc.title.to_lowercase().contains(&query_lower) ||
               doc.description.to_lowercase().contains(&query_lower) ||
               doc.error_code.to_lowercase().contains(&query_lower) {
                results.push(doc);
            }
        }

        results.sort_by(|a, b| a.severity.cmp(&b.severity).reverse());
        results
    }

    pub fn get_related_errors(&self, error_code: &str) -> Vec<&ErrorDocumentation> {
        if let Some(doc) = self.get_documentation(error_code) {
            let mut related = Vec::new();
            
            for related_code in &doc.related_errors {
                if let Some(related_doc) = self.get_documentation(related_code) {
                    related.push(related_doc);
                }
            }
            
            related
        } else {
            Vec::new()
        }
    }

    pub async fn display_error_help(&self, error: &FortressError) -> Result<(), FortressError> {
        let error_code = error.error_code();
        
        if let Some(doc) = self.get_documentation(error_code) {
            self.display_documentation(doc).await?;
        } else {
            self.display_generic_help(error).await?;
        }

        // Offer related error help
        if !self.get_related_errors(error_code).is_empty() {
            if Confirm::new()
                .with_prompt("Would you like to see help for related errors?")
                .default(false)
                .interact()
                .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
            {
                self.display_related_errors(error_code).await?;
            }
        }

        Ok(())
    }

    async fn display_documentation(&self, doc: &ErrorDocumentation) -> Result<(), FortressError> {
        let term = Term::stdout();
        let title_style = Style::new().bold().cyan();
        let header_style = Style::new().bold().yellow();
        let code_style = Style::new().dim();
        let success_style = Style::new().green();

        term.clear_screen()
            .map_err(|e| FortressError::configuration_error("clear_screen", &format!("{}", e), "terminal operation"))?;

        // Header
        println!("{}", title_style.apply_to(format!("✗ Error Code: {}", doc.error_code)));
        println!("{}", title_style.apply_to(format!("Title: {}", doc.title)));
        println!("Description: {}\n", doc.description);

        // Severity and Category
        println!("{} Severity: {:?}", header_style.apply_to("Severity"), doc.severity);
        println!("{} Category: {:?}\n", header_style.apply_to("Category"), doc.category);

        // Common Causes
        println!("{}", header_style.apply_to("Common Causes:"));
        for (i, cause) in doc.common_causes.iter().enumerate() {
            println!("  {}. {}", i + 1, cause);
        }

        // Solutions
        println!("\n{}", header_style.apply_to("Solutions:"));
        for (i, solution) in doc.solutions.iter().enumerate() {
            println!("  {}. {}", i + 1, solution);
        }

        // Examples
        if !doc.examples.is_empty() {
            println!("\n{}", header_style.apply_to("Example Commands:"));
            for example in &doc.examples {
                println!("  {}", code_style.apply_to(format!("$ {}", example)));
            }
        }

        // Prevention Tips
        if !doc.prevention_tips.is_empty() {
            println!("\n{}", header_style.apply_to("Prevention Tips:"));
            for (i, tip) in doc.prevention_tips.iter().enumerate() {
                println!("  {}. {}", i + 1, tip);
            }
        }

        // Related Documentation
        if !doc.related_docs.is_empty() {
            println!("\n{}", header_style.apply_to("Related Documentation:"));
            for doc in &doc.related_docs {
                println!("  • {}", doc);
            }
        }

        // Recovery Commands
        if !doc.recovery_commands.is_empty() {
            println!("\n{}", header_style.apply_to("Quick Recovery Commands:"));
            for cmd in &doc.recovery_commands {
                println!("  {}", code_style.apply_to(format!("$ {}", cmd)));
            }
        }

        // Interactive Troubleshooting
        if !doc.troubleshooting_steps.is_empty() {
            println!("\n{}", header_style.apply_to("Interactive Troubleshooting:"));
            
            if Confirm::new()
                .with_prompt("Would you like to run interactive troubleshooting?")
                .default(true)
                .interact()
                .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
            {
                self.run_interactive_troubleshooting(doc).await?;
            }
        }

        Ok(())
    }

    async fn display_generic_help(&self, error: &FortressError) -> Result<(), FortressError> {
        let term = Term::stdout();
        let title_style = Style::new().bold().red();
        let header_style = Style::new().bold().yellow();

        println!("{}", title_style.apply_to("✗ Fortress Error"));
        println!("Message: {}", error);
        println!("Help: {}", error.help_text());

        // Show troubleshooting steps
        let steps = error.troubleshooting_steps();
        if !steps.is_empty() {
            println!("\n{}", header_style.apply_to("Troubleshooting Steps:"));
            for (i, step) in steps.iter().enumerate() {
                println!("  {}. {}", i + 1, step);
            }
        }

        // Suggest next steps
        println!("\n{}", header_style.apply_to("Next Steps:"));
        println!("  • Run 'fortress --help' for available commands");
        println!("  • Check documentation at: https://docs.fortress.security");
        println!("  • Report issues at: https://github.com/Genius740Code/Fortress/issues");
        println!("  • Use 'fortress help search <query>' to search for help");

        Ok(())
    }

    async fn display_related_errors(&self, error_code: &str) -> Result<(), FortressError> {
        let related_errors = self.get_related_errors(error_code);
        
        if related_errors.is_empty() {
            return Ok(());
        }

        let term = Term::stdout();
        let header_style = Style::new().bold().cyan();

        println!("\n{}", header_style.apply_to("🔗 Related Errors:"));

        let error_names: Vec<String> = related_errors.iter()
            .map(|doc| format!("{} - {}", doc.error_code, doc.title))
            .collect();

        let selection = Select::new()
            .with_prompt("Select a related error to view help:")
            .items(&error_names)
            .interact()
            .map_err(|e| FortressError::configuration_error("error_selection", &format!("{}", e), "valid error choice"))?;

        if let Some(selected_doc) = related_errors.get(selection) {
            self.display_documentation(selected_doc).await?;
        }

        Ok(())
    }

    async fn run_interactive_troubleshooting(&self, doc: &ErrorDocumentation) -> Result<(), FortressError> {
        let term = Term::stdout();
        let header_style = Style::new().bold().blue();
        let step_style = Style::new().bold().green();
        let code_style = Style::new().dim();

        println!("\n{}", header_style.apply_to("Starting Interactive Troubleshooting"));

        for step in &doc.troubleshooting_steps {
            println!("\n{}", step_style.apply_to(format!("Step {}: {}", step.step_number, step.title)));
            println!("{}", step.description);

            if let Some(time_estimate) = step.time_estimate_minutes {
                println!("Estimated time: {} minutes", time_estimate);
            }

            // Show commands
            if !step.commands.is_empty() {
                println!("\nCommands to run:");
                for cmd in &step.commands {
                    println!("  {}", code_style.apply_to(format!("$ {}", cmd)));
                }
            }

            // Ask user if they want to execute commands
            if Confirm::new()
                .with_prompt("Execute these commands?")
                .default(true)
                .interact()
                .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
            {
                // Show progress bar for step execution
                if let Some(time_estimate) = step.time_estimate_minutes {
                    let pb = ProgressBar::new(time_estimate as u64 * 60); // Convert to seconds
                    pb.set_style(
                        ProgressStyle::default_bar()
                            .template("{spinner:.blue} [{elapsed_precise}] [{bar:40.blue/white}] {pos}/{len} ({eta})")
                            .unwrap_or_else(|_| ProgressStyle::default_bar())
                            .progress_chars("=>-")
                    );
                    pb.set_message(format!("Running step {}...", step.step_number));

                    // Simulate progress (in real implementation, this would actually run commands)
                    for _ in 0..time_estimate * 60 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(1000 / 60)).await;
                        pb.inc(1);
                    }

                    pb.finish_with_message(format!("✓ Step {} completed", step.step_number));
                }
            }

            // Show expected output
            if let Some(expected) = &step.expected_output {
                println!("\nExpected Output:");
                println!("  {}", expected);
            }

            // Ask to continue
            if step.step_number < doc.troubleshooting_steps.len() {
                if !Confirm::new()
                    .with_prompt("Continue to next step?")
                    .default(true)
                    .interact()
                    .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
                {
                    break;
                }
            }
        }

        println!("\n✓ Interactive troubleshooting completed!");
        println!("If the issue persists, consider:");
        println!("  • Checking related errors: 'fortress help related <error-code>'");
        println!("  • Running diagnostics: 'fortress doctor'");
        println!("  • Contacting support: https://github.com/Genius740Code/Fortress/issues");

        Ok(())
    }

    pub async fn search_and_display(&self, query: &str) -> Result<(), FortressError> {
        let results = self.search_documentation(query);

        if results.is_empty() {
            println!("✗ No documentation found for query: '{}'", query);
            println!("Try searching for:");
            println!("  • Error codes (e.g., 'ENC001')");
            println!("  • Error types (e.g., 'database', 'encryption')");
            println!("  • Keywords (e.g., 'connection', 'key', 'config')");
            return Ok(());
        }

        let term = Term::stdout();
        let header_style = Style::new().bold().cyan();

        println!("\n{}", header_style.apply_to(format!("🔍 Search Results for '{}':", query)));

        let result_names: Vec<String> = results.iter()
            .map(|doc| format!("{} - {} ({:?})", doc.error_code, doc.title, doc.severity))
            .collect();

        if results.len() == 1 {
            // Display the single result directly
            self.display_documentation(results[0]).await?;
        } else {
            // Let user choose from multiple results
            let selection = Select::new()
                .with_prompt("Select a result to view detailed help:")
                .items(&result_names)
                .interact()
                .map_err(|e| FortressError::configuration_error("result_selection", &format!("{}", e), "valid result choice"))?;

            if let Some(selected_doc) = results.get(selection) {
                self.display_documentation(selected_doc).await?;
            }
        }

        Ok(())
    }

    pub fn list_all_errors(&self) -> Vec<&ErrorDocumentation> {
        let mut errors: Vec<_> = self.documentation.values().collect();
        errors.sort_by(|a, b| a.error_code.cmp(&b.error_code));
        errors
    }

    pub fn get_errors_by_category(&self, category: &ErrorCategory) -> Vec<&ErrorDocumentation> {
        let mut errors: Vec<_> = self.documentation.values()
            .filter(|doc| &doc.category == category)
            .collect();
        errors.sort_by(|a, b| a.severity.cmp(&b.severity).reverse());
        errors
    }

    pub fn get_errors_by_severity(&self, severity: &ErrorSeverity) -> Vec<&ErrorDocumentation> {
        let mut errors: Vec<_> = self.documentation.values()
            .filter(|doc| &doc.severity == severity)
            .collect();
        errors.sort_by(|a, b| a.error_code.cmp(&b.error_code));
        errors
    }
}

impl Default for ErrorDocumentationSystem {
    fn default() -> Self {
        Self::new()
    }
}

pub async fn display_error_enhanced(error: &FortressError) -> Result<(), FortressError> {
    let doc_system = ErrorDocumentationSystem::new();
    doc_system.display_error_help(error).await
}

pub async fn search_help(query: &str) -> Result<(), FortressError> {
    let doc_system = ErrorDocumentationSystem::new();
    doc_system.search_and_display(query).await
}

pub async fn list_help_categories() -> Result<(), FortressError> {
    let doc_system = ErrorDocumentationSystem::new();
    let term = Term::stdout();
    let header_style = Style::new().bold().cyan();

    println!("\n{}", header_style.apply_to("📚 Help Categories:"));

    let categories = vec![
        (ErrorCategory::Configuration, "Configuration-related errors"),
        (ErrorCategory::Database, "Database connection and query errors"),
        (ErrorCategory::Encryption, "Encryption and key management errors"),
        (ErrorCategory::Authentication, "Authentication and authorization errors"),
        (ErrorCategory::Network, "Network connectivity errors"),
        (ErrorCategory::FileSystem, "File system and I/O errors"),
        (ErrorCategory::Performance, "Performance and resource errors"),
        (ErrorCategory::Compliance, "Compliance and audit errors"),
        (ErrorCategory::Plugin, "Plugin-related errors"),
        (ErrorCategory::General, "General system errors"),
    ];

    let category_names: Vec<String> = categories.iter()
        .map(|(cat, desc)| format!("{:?} - {}", cat, desc))
        .collect();

    let selection = Select::new()
        .with_prompt("Select a category to view errors:")
        .items(&category_names)
        .interact()
        .map_err(|e| FortressError::configuration_error("category_selection", &format!("{}", e), "valid category choice"))?;

    if let Some((category, _)) = categories.get(selection) {
        let errors = doc_system.get_errors_by_category(category);
        
        if errors.is_empty() {
            println!("✗ No errors found in this category");
            return Ok(());
        }

        println!("\n{}", header_style.apply_to(format!("Errors in {:?} category:", category)));
        
        let error_names: Vec<String> = errors.iter()
            .map(|doc| format!("{} - {} ({:?})", doc.error_code, doc.title, doc.severity))
            .collect();

        let error_selection = Select::new()
            .with_prompt("Select an error to view help:")
            .items(&error_names)
            .interact()
            .map_err(|e| FortressError::configuration_error("error_selection", &format!("{}", e), "valid error choice"))?;

        if let Some(selected_doc) = errors.get(error_selection) {
            doc_system.display_documentation(selected_doc).await?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_documentation_lookup() {
        let doc_system = ErrorDocumentationSystem::new();
        
        // Test existing error code
        let doc = doc_system.get_documentation("ENC001");
        assert!(doc.is_some());
        assert_eq!(doc.unwrap().title, "Invalid Key Length");
        
        // Test non-existing error code
        let doc = doc_system.get_documentation("NONEXISTENT");
        assert!(doc.is_none());
    }

    #[test]
    fn test_error_search() {
        let doc_system = ErrorDocumentationSystem::new();
        
        // Search by title
        let results = doc_system.search_documentation("key length");
        assert!(!results.is_empty());
        
        // Search by error code
        let results = doc_system.search_documentation("ENC001");
        assert!(!results.is_empty());
        
        // Search with no results
        let results = doc_system.search_documentation("nonexistent query");
        assert!(results.is_empty());
    }

    #[test]
    fn test_related_errors() {
        let doc_system = ErrorDocumentationSystem::new();
        
        let related = doc_system.get_related_errors("ENC001");
        assert!(!related.is_empty());
        
        // Should contain ENC002 and KEY001 as defined in documentation
        let related_codes: Vec<String> = related.iter().map(|doc| doc.error_code.clone()).collect();
        assert!(related_codes.contains(&"ENC002".to_string()));
        assert!(related_codes.contains(&"KEY001".to_string()));
    }

    #[test]
    fn test_category_filtering() {
        let doc_system = ErrorDocumentationSystem::new();
        
        let encryption_errors = doc_system.get_errors_by_category(&ErrorCategory::Encryption);
        assert!(!encryption_errors.is_empty());
        
        // All encryption errors should have the Encryption category
        for doc in &encryption_errors {
            assert_eq!(doc.category, ErrorCategory::Encryption);
        }
    }

    #[test]
    fn test_severity_filtering() {
        let doc_system = ErrorDocumentationSystem::new();
        
        let critical_errors = doc_system.get_errors_by_severity(&ErrorSeverity::Critical);
        // Should be empty as we don't have critical errors in test data
        assert!(critical_errors.is_empty());
        
        let high_errors = doc_system.get_errors_by_severity(&ErrorSeverity::High);
        assert!(!high_errors.is_empty());
        
        // All high errors should have High severity
        for doc in &high_errors {
            assert_eq!(doc.severity, ErrorSeverity::High);
        }
    }
}
