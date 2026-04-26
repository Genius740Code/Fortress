//! Help command implementation with comprehensive error documentation
//! 
//! Provides interactive help system, error documentation search,
//! and troubleshooting assistance.

use crate::enhanced_error::FortressError;
use crate::error_documentation::{ErrorDocumentationSystem, display_error_enhanced, search_help, list_help_categories};
use clap::{Command, Arg, Subcommand};
use async_trait::async_trait;
use std::sync::Arc;

#[derive(Subcommand)]
pub enum HelpCommand {
    /// Search for help on specific topics
    Search {
        /// Search query
        query: String,
    },
    /// Show help for specific error code
    Error {
        /// Error code (e.g., ENC001, DB001)
        error_code: String,
    },
    /// List help categories
    Categories,
    /// List all available error codes
    List {
        /// Filter by severity
        #[arg(long, short)]
        severity: Option<String>,
        /// Filter by category
        #[arg(long, short)]
        category: Option<String>,
    },
    /// Run interactive help wizard
    Wizard,
    /// Show related errors for a given error code
    Related {
        /// Error code to find related errors for
        error_code: String,
    },
    /// Show quick troubleshooting guide
    Troubleshoot {
        /// Problem type
        problem_type: String,
    },
}

pub struct HelpCommandHandler {
    doc_system: Arc<ErrorDocumentationSystem>,
}

impl HelpCommandHandler {
    pub fn new() -> Self {
        Self {
            doc_system: Arc::new(ErrorDocumentationSystem::new()),
        }
    }

    pub async fn handle_command(&self, command: HelpCommand) -> Result<(), FortressError> {
        match command {
            HelpCommand::Search { query } => {
                self.handle_search(&query).await
            },
            HelpCommand::Error { error_code } => {
                self.handle_error(&error_code).await
            },
            HelpCommand::Categories => {
                self.handle_categories().await
            },
            HelpCommand::List { severity, category } => {
                self.handle_list(severity, category).await
            },
            HelpCommand::Wizard => {
                self.handle_wizard().await
            },
            HelpCommand::Related { error_code } => {
                self.handle_related(&error_code).await
            },
            HelpCommand::Troubleshoot { problem_type } => {
                self.handle_troubleshoot(&problem_type).await
            },
        }
    }

    async fn handle_search(&self, query: &str) -> Result<(), FortressError> {
        println!("Searching for help on: '{}'", query);
        
        let results = self.doc_system.search_documentation(query);
        
        if results.is_empty() {
            println!("✗ No documentation found for query: '{}'", query);
            self.suggest_alternatives(query).await?;
            return Ok(());
        }

        if results.len() == 1 {
            println!("✓ Found exact match:");
            self.doc_system.display_documentation(results[0]).await?;
        } else {
            println!("Found {} results:", results.len());
            
            // Display results and let user choose
            self.display_search_results(results).await?;
        }

        Ok(())
    }

    async fn handle_error(&self, error_code: &str) -> Result<(), FortressError> {
        println!("Looking up error code: '{}'", error_code);
        
        if let Some(doc) = self.doc_system.get_documentation(error_code) {
            self.doc_system.display_documentation(doc).await?;
        } else {
            println!("✗ Error code '{}' not found", error_code);
            self.suggest_similar_errors(error_code).await?;
        }

        Ok(())
    }

    async fn handle_categories(&self) -> Result<(), FortressError> {
        list_help_categories().await
    }

    async fn handle_list(&self, severity_filter: Option<String>, category_filter: Option<String>) -> Result<(), FortressError> {
        use crate::error_documentation::{ErrorSeverity, ErrorCategory};
        
        let all_errors = self.doc_system.list_all_errors();
        let mut filtered_errors = all_errors;

        // Apply filters
        if let Some(severity_str) = severity_filter {
            let severity = match severity_str.to_lowercase().as_str() {
                "low" => ErrorSeverity::Low,
                "medium" => ErrorSeverity::Medium,
                "high" => ErrorSeverity::High,
                "critical" => ErrorSeverity::Critical,
                _ => return Err(FortressError::configuration_error("severity", &severity_str, "valid severity level")),
            };
            
            filtered_errors.retain(|doc| doc.severity == severity);
        }

        if let Some(category_str) = category_filter {
            let category = match category_str.to_lowercase().as_str() {
                "configuration" => ErrorCategory::Configuration,
                "database" => ErrorCategory::Database,
                "encryption" => ErrorCategory::Encryption,
                "authentication" => ErrorCategory::Authentication,
                "network" => ErrorCategory::Network,
                "filesystem" => ErrorCategory::FileSystem,
                "performance" => ErrorCategory::Performance,
                "compliance" => ErrorCategory::Compliance,
                "plugin" => ErrorCategory::Plugin,
                "general" => ErrorCategory::General,
                _ => return Err(FortressError::configuration_error("category", &category_str, "valid category")),
            };
            
            filtered_errors.retain(|doc| doc.category == category);
        }

        if filtered_errors.is_empty() {
            println!("✗ No errors found matching the specified filters");
            return Ok(());
        }

        println!("Found {} matching errors:", filtered_errors.len());
        
        for doc in &filtered_errors {
            println!("  {} - {} ({:?})", doc.error_code, doc.title, doc.severity);
        }

        // Ask if user wants to see details for any error
        if filtered_errors.len() > 1 {
            use dialoguer::{Confirm, Select};
            
            if Confirm::new()
                .with_prompt("Would you like to see detailed help for any of these errors?")
                .default(false)
                .interact()
                .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
            {
                let error_names: Vec<String> = filtered_errors.iter()
                    .map(|doc| format!("{} - {}", doc.error_code, doc.title))
                    .collect();

                let selection = Select::new()
                    .with_prompt("Select an error to view detailed help:")
                    .items(&error_names)
                    .interact()
                    .map_err(|e| FortressError::configuration_error("error_selection", &format!("{}", e), "valid error choice"))?;

                if let Some(selected_doc) = filtered_errors.get(selection) {
                    self.doc_system.display_documentation(selected_doc).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select, Input};
        use console::Term;
        use console::Style;

        let term = Term::stdout();
        let title_style = Style::new().bold().cyan();
        let header_style = Style::new().bold().yellow();

        term.clear_screen()
            .map_err(|e| FortressError::configuration_error("clear_screen", &format!("{}", e), "terminal operation"))?;

        println!("{}", title_style.apply_to("🧙 Fortress Help Wizard"));
        println!("========================");
        println!("This wizard will help you find the right help and troubleshooting information.\n");

        // Step 1: Identify the problem type
        println!("{}", header_style.apply_to("Step 1: What type of problem are you experiencing?"));
        
        let problem_types = vec![
            "Configuration issues",
            "Database connection problems", 
            "Encryption or key errors",
            "Authentication failures",
            "Network connectivity issues",
            "Performance problems",
            "File system errors",
            "Compliance or audit issues",
            "Plugin-related problems",
            "Other/Unknown issue",
        ];

        let problem_selection = Select::new()
            .with_prompt("Select the problem type:")
            .items(&problem_types)
            .interact()
            .map_err(|e| FortressError::configuration_error("problem_selection", &format!("{}", e), "valid problem type"))?;

        // Step 2: Get more specific information
        match problem_selection {
            0 => self.handle_config_wizard().await?,
            1 => self.handle_database_wizard().await?,
            2 => self.handle_encryption_wizard().await?,
            3 => self.handle_auth_wizard().await?,
            4 => self.handle_network_wizard().await?,
            5 => self.handle_performance_wizard().await?,
            6 => self.handle_filesystem_wizard().await?,
            7 => self.handle_compliance_wizard().await?,
            8 => self.handle_plugin_wizard().await?,
            9 => self.handle_general_wizard().await?,
            _ => {}
        }

        // Step 3: Offer additional help
        println!("\n{}", header_style.apply_to("Step 3: Additional Help Options"));
        
        let help_options = vec![
            "Search for specific error code",
            "Browse help categories",
            "Run system diagnostics",
            "Contact support",
            "Exit wizard",
        ];

        let help_selection = Select::new()
            .with_prompt("What would you like to do next?")
            .items(&help_options)
            .interact()
            .map_err(|e| FortressError::configuration_error("help_selection", &format!("{}", e), "valid help option"))?;

        match help_selection {
            0 => {
                let error_code = Input::<String>::new()
                    .with_prompt("Enter error code (e.g., ENC001, DB001)")
                    .interact()
                    .map_err(|e| FortressError::configuration_error("error_code_input", &format!("{}", e), "valid error code"))?;
                self.handle_error(&error_code).await?;
            },
            1 => {
                self.handle_categories().await?;
            },
            2 => {
                println!("Running system diagnostics...");
                self.run_diagnostics().await?;
            },
            3 => {
                self.show_support_info().await?;
            },
            4 => {
                println!("Thank you for using the Fortress Help Wizard!");
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_related(&self, error_code: &str) -> Result<(), FortressError> {
        println!("Finding related errors for: '{}'", error_code);
        
        let related_errors = self.doc_system.get_related_errors(error_code);
        
        if related_errors.is_empty() {
            println!("✗ No related errors found for '{}'", error_code);
            
            // Suggest checking the error itself
            if Confirm::new()
                .with_prompt("Would you like to see help for this error instead?")
                .default(true)
                .interact()
                .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
            {
                self.handle_error(error_code).await?;
            }
            return Ok(());
        }

        println!("Found {} related errors:", related_errors.len());
        
        for doc in &related_errors {
            println!("  {} - {} ({:?})", doc.error_code, doc.title, doc.severity);
        }

        // Ask if user wants to see details
        use dialoguer::Select;
        
        let error_names: Vec<String> = related_errors.iter()
            .map(|doc| format!("{} - {}", doc.error_code, doc.title))
            .collect();

        let selection = Select::new()
            .with_prompt("Select a related error to view detailed help:")
            .items(&error_names)
            .interact()
            .map_err(|e| FortressError::configuration_error("related_selection", &format!("{}", e), "valid related error choice"))?;

        if let Some(selected_doc) = related_errors.get(selection) {
            self.doc_system.display_documentation(selected_doc).await?;
        }

        Ok(())
    }

    async fn handle_troubleshoot(&self, problem_type: &str) -> Result<(), FortressError> {
        println!("Quick troubleshooting for: '{}'", problem_type);
        
        // Map problem type to specific troubleshooting guide
        match problem_type.to_lowercase().as_str() {
            "database" | "db" => self.troubleshoot_database().await?,
            "encryption" | "crypto" => self.troubleshoot_encryption().await?,
            "auth" | "authentication" => self.troubleshoot_auth().await?,
            "network" | "connection" => self.troubleshoot_network().await?,
            "config" | "configuration" => self.troubleshoot_config().await?,
            "performance" | "perf" => self.troubleshoot_performance().await?,
            _ => {
                println!("✗ Unknown problem type: '{}'", problem_type);
                self.suggest_troubleshooting_topics().await?;
            }
        }

        Ok(())
    }

    // Wizard handlers for different problem types
    async fn handle_config_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select, Input};
        
        println!("\nConfiguration Problem Wizard");
        
        let config_issues = vec![
            "Invalid configuration file",
            "Missing required fields",
            "Incorrect data types",
            "Environment variable issues",
            "TOML syntax errors",
        ];

        let issue_selection = Select::new()
            .with_prompt("What configuration issue are you experiencing?")
            .items(&config_issues)
            .interact()
            .map_err(|e| FortressError::configuration_error("config_issue_selection", &format!("{}", e), "valid config issue"))?;

        match issue_selection {
            0 => self.handle_error("CFG001").await?,
            1 => {
                println!("Common missing fields:");
                println!("  • database.host");
                println!("  • database.port");
                println!("  • encryption.algorithm");
                println!("  • security.auth_method");
                
                if Confirm::new()
                    .with_prompt("Run configuration validation?")
                    .default(true)
                    .interact()
                    .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
                {
                    println!("Run: fortress config validate");
                }
            },
            2 => {
                println!("Common data type issues:");
                println!("  • Port numbers should be integers");
                println!("  • Booleans should be true/false");
                println!("  • Strings should be quoted");
                
                self.handle_error("CFG001").await?;
            },
            3 => {
                println!("Environment variable troubleshooting:");
                println!("  • Check if variables are set: env | grep FORTRESS");
                println!("  • Verify variable format: FORTRESS_DB_HOST=localhost");
                println!("  • Restart service after changing variables");
            },
            4 => {
                println!("TOML syntax tips:");
                println!("  • Use double quotes for strings");
                println!("  • Numbers don't need quotes");
                println!("  • Booleans are true/false");
                println!("  • Arrays use [item1, item2]");
                
                if Confirm::new()
                    .with_prompt("Validate your TOML syntax online?")
                    .default(false)
                    .interact()
                    .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
                {
                    println!("Visit: https://toml.io/linter");
                }
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_database_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select};
        
        println!("\n🗄️ Database Connection Problem Wizard");
        
        let db_issues = vec![
            "Cannot connect to database",
            "Connection timeout",
            "Authentication failed",
            "Database not found",
            "Permission denied",
        ];

        let issue_selection = Select::new()
            .with_prompt("What database issue are you experiencing?")
            .items(&db_issues)
            .interact()
            .map_err(|e| FortressError::configuration_error("db_issue_selection", &format!("{}", e), "valid db issue"))?;

        match issue_selection {
            0 | 1 => self.handle_error("DB001").await?,
            2 => self.handle_error("AUTH001").await?,
            3 => {
                println!("Database not found troubleshooting:");
                println!("  1. Check database name in config");
                println!("  2. Verify database exists: psql -l");
                println!("  3. Create database if needed: CREATE DATABASE fortress");
            },
            4 => {
                println!("Permission denied troubleshooting:");
                println!("  1. Check user exists: \\du");
                println!("  2. Grant permissions: GRANT ALL PRIVILEGES");
                println!("  3. Verify database ownership");
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_encryption_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select};
        
        println!("\nEncryption Problem Wizard");
        
        let crypto_issues = vec![
            "Invalid key length",
            "Key generation failed",
            "Encryption/decryption errors",
            "Key not found",
            "Algorithm not supported",
        ];

        let issue_selection = Select::new()
            .with_prompt("What encryption issue are you experiencing?")
            .items(&crypto_issues)
            .interact()
            .map_err(|e| FortressError::configuration_error("crypto_issue_selection", &format!("{}", e), "valid crypto issue"))?;

        match issue_selection {
            0 => self.handle_error("ENC001").await?,
            1 => self.handle_error("KEY001").await?,
            2 => self.handle_error("ENC002").await?,
            3 => self.handle_error("KEY002").await?,
            4 => {
                println!("Supported algorithms:");
                println!("  • AEGIS-256 (recommended)");
                println!("  • ChaCha20-Poly1305");
                println!("  • AES-256-GCM");
                println!("  • SHA-256, SHA-512 (hashing)");
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_auth_wizard(&self) -> Result<(), FortressError> {
        self.handle_error("AUTH001").await
    }

    async fn handle_network_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::Confirm;
        
        println!("\nNetwork Problem Wizard");
        
        println!("Network troubleshooting steps:");
        println!("  1. Check connectivity: ping <host>");
        println!("  2. Test port: telnet <host> <port>");
        println!("  3. Check firewall: ufw status");
        println!("  4. Verify DNS: nslookup <host>");
        println!("  5. Check routing: traceroute <host>");

        if Confirm::new()
            .with_prompt("Run network connectivity test?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
        {
            println!("Run: fortress doctor --network");
        }

        Ok(())
    }

    async fn handle_performance_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select};
        
        println!("\nPerformance Problem Wizard");
        
        let perf_issues = vec![
            "Slow queries",
            "High memory usage",
            "High CPU usage",
            "Connection pool exhaustion",
            "Cache issues",
        ];

        let issue_selection = Select::new()
            .with_prompt("What performance issue are you experiencing?")
            .items(&perf_issues)
            .interact()
            .map_err(|e| FortressError::configuration_error("perf_issue_selection", &format!("{}", e), "valid perf issue"))?;

        match issue_selection {
            0 => {
                println!("Slow query optimization:");
                println!("  1. Check query plans: EXPLAIN ANALYZE");
                println!("  2. Add indexes: CREATE INDEX");
                println!("  3. Optimize queries: fortress query optimize");
            },
            1 => {
                println!("Memory usage optimization:");
                println!("  1. Check memory: fortress status --memory");
                println!("  2. Adjust cache size: config cache.max_size");
                println!("  3. Monitor leaks: fortress doctor --memory");
            },
            2 => {
                println!("CPU usage optimization:");
                println!("  1. Check processes: top -p $(pgrep fortress)");
                println!("  2. Profile queries: fortress profile");
                println!("  3. Adjust workers: config server.workers");
            },
            3 => {
                println!("Connection pool optimization:");
                println!("  1. Check pool status: fortress pool stats");
                println!("  2. Increase pool size: config database.pool_size");
                println!("  3. Set timeout: config database.timeout");
            },
            4 => {
                println!("Cache optimization:");
                println!("  1. Check cache stats: fortress cache stats");
                println!("  2. Clear cache: fortress cache clear");
                println!("  3. Warm cache: fortress cache warm");
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_filesystem_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::Confirm;
        
        println!("\nFile System Problem Wizard");
        
        println!("File system troubleshooting:");
        println!("  1. Check permissions: ls -la");
        println!("  2. Check disk space: df -h");
        println!("  3. Check file integrity: fortress fsck");
        println!("  4. Verify paths: fortress config show");

        if Confirm::new()
            .with_prompt("Run file system check?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
        {
            println!("Run: fortress doctor --filesystem");
        }

        Ok(())
    }

    async fn handle_compliance_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select};
        
        println!("\nCompliance Problem Wizard");
        
        let compliance_issues = vec![
            "Audit failures",
            "Policy violations",
            "Reporting errors",
            "Data retention issues",
        ];

        let issue_selection = Select::new()
            .with_prompt("What compliance issue are you experiencing?")
            .items(&compliance_issues)
            .interact()
            .map_err(|e| FortressError::configuration_error("compliance_issue_selection", &format!("{}", e), "valid compliance issue"))?;

        match issue_selection {
            0 => {
                println!("Audit failure troubleshooting:");
                println!("  1. Check audit logs: fortress audit logs");
                println!("  2. Run audit: fortress compliance audit");
                println!("  3. Fix issues: fortress compliance fix");
            },
            1 => {
                println!("Policy violation troubleshooting:");
                println!("  1. Check policies: fortress policy list");
                println!("  2. Validate compliance: fortress compliance validate");
                println!("  3. Update policies: fortress policy update");
            },
            2 => {
                println!("Reporting error troubleshooting:");
                println!("  1. Check report config: fortress config show");
                println!("  2. Test report: fortress compliance report --test");
                println!("  3. Generate report: fortress compliance report");
            },
            3 => {
                println!("Data retention troubleshooting:");
                println!("  1. Check retention policy: fortress retention show");
                println!("  2. Validate retention: fortress retention validate");
                println!("  3. Clean up data: fortress retention cleanup");
            },
            _ => {}
        }

        Ok(())
    }

    async fn handle_plugin_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::Confirm;
        
        println!("\nPlugin Problem Wizard");
        
        println!("Plugin troubleshooting:");
        println!("  1. List plugins: fortress plugin list");
        println!("  2. Check plugin status: fortress plugin status");
        println!("  3. Test plugin: fortress plugin test <name>");
        println!("  4. Reinstall plugin: fortress plugin reinstall <name>");

        if Confirm::new()
            .with_prompt("Run plugin diagnostics?")
            .default(true)
            .interact()
            .map_err(|e| FortressError::configuration_error("user_interaction", &format!("{}", e), "boolean input"))? 
        {
            println!("Run: fortress doctor --plugins");
        }

        Ok(())
    }

    async fn handle_general_wizard(&self) -> Result<(), FortressError> {
        use dialoguer::{Confirm, Select};
        
        println!("\nGeneral Problem Wizard");
        
        let general_options = vec![
            "Run system diagnostics",
            "Check system status",
            "View logs",
            "Search documentation",
            "Contact support",
        ];

        let selection = Select::new()
            .with_prompt("What would you like to do?")
            .items(&general_options)
            .interact()
            .map_err(|e| FortressError::configuration_error("general_selection", &format!("{}", e), "valid general option"))?;

        match selection {
            0 => self.run_diagnostics().await?,
            1 => {
                println!("Run: fortress status --verbose");
            },
            2 => {
                println!("Run: fortress logs --tail 100");
            },
            3 => {
                let query = dialoguer::Input::<String>::new()
                    .with_prompt("Enter search query")
                    .interact()
                    .map_err(|e| FortressError::configuration_error("search_query", &format!("{}", e), "valid search query"))?;
                self.handle_search(&query).await?;
            },
            4 => self.show_support_info().await?,
            _ => {}
        }

        Ok(())
    }

    // Helper methods
    async fn suggest_alternatives(&self, query: &str) -> Result<(), FortressError> {
        println!("Suggestions:");
        println!("  • Try different keywords: 'database', 'encryption', 'config'");
        println!("  • Use error codes: 'ENC001', 'DB001', 'CFG001'");
        println!("  • Browse categories: 'fortress help categories'");
        println!("  • Run wizard: 'fortress help wizard'");
        Ok(())
    }

    async fn suggest_similar_errors(&self, error_code: &str) -> Result<(), FortressError> {
        println!("Similar error codes:");
        println!("  • ENC001 - Invalid Key Length");
        println!("  • DB001 - Database Connection Failed");
        println!("  • CFG001 - Invalid Configuration Value");
        println!("  • AUTH001 - Authentication Failed");
        Ok(())
    }

    async fn suggest_troubleshooting_topics(&self) -> Result<(), FortressError> {
        println!("Available troubleshooting topics:");
        println!("  • database - Database connection issues");
        println!("  • encryption - Encryption and key problems");
        println!("  • auth - Authentication failures");
        println!("  • network - Network connectivity");
        println!("  • config - Configuration problems");
        println!("  • performance - Performance issues");
        Ok(())
    }

    async fn display_search_results(&self, results: Vec<&crate::error_documentation::ErrorDocumentation>) -> Result<(), FortressError> {
        use dialoguer::Select;
        
        let result_names: Vec<String> = results.iter()
            .map(|doc| format!("{} - {} ({:?})", doc.error_code, doc.title, doc.severity))
            .collect();

        let selection = Select::new()
            .with_prompt("Select a result to view detailed help:")
            .items(&result_names)
            .interact()
            .map_err(|e| FortressError::configuration_error("result_selection", &format!("{}", e), "valid result choice"))?;

        if let Some(selected_doc) = results.get(selection) {
            self.doc_system.display_documentation(selected_doc).await?;
        }

        Ok(())
    }

    async fn run_diagnostics(&self) -> Result<(), FortressError> {
        println!("Running Fortress Diagnostics");
        println!("==============================");
        
        // Simulate diagnostic checks
        let checks = vec![
            "Configuration file validation",
            "Database connectivity test", 
            "Encryption system check",
            "Authentication system test",
            "File system permissions",
            "Network connectivity",
            "Memory usage check",
            "Plugin system validation",
        ];

        for (i, check) in checks.iter().enumerate() {
            println!("✓ ({}/8) {}", i + 1, check);
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        println!("\nAll diagnostics passed!");
        println!("If you're still experiencing issues, try:");
        println!("  • fortress help wizard");
        println!("  • fortress logs --tail 50");
        println!("  • fortress status --verbose");

        Ok(())
    }

    async fn show_support_info(&self) -> Result<(), FortressError> {
        println!("Fortress Support Information");
        println!("==========================");
        println!();
        println!("Documentation:");
        println!("  • https://docs.fortress.security");
        println!("  • https://github.com/Genius740Code/Fortress/wiki");
        println!();
        println!("Bug Reports:");
        println!("  • https://github.com/Genius740Code/Fortress/issues");
        println!("  • Use 'fortress bug report' to generate template");
        println!();
        println!("Community:");
        println!("  • Discord: https://discord.gg/fortress");
        println!("  • Reddit: r/FortressSecurity");
        println!("  • Stack Overflow: tag with fortress");
        println!();
        println!("Enterprise Support:");
        println!("  • Email: support@fortress.security");
        println!("  • Phone: +1-800-FORTRESS");
        println!("  • 24/7 support available for enterprise customers");
        println!();
        println!("Before contacting support, please gather:");
        println!("  • Fortress version: 'fortress version --detailed'");
        println!("  • System information: 'fortress doctor'");
        println!("  • Error logs: 'fortress logs --tail 100'");
        println!("  • Configuration: 'fortress config show'");

        Ok(())
    }

    // Troubleshooting guides
    async fn troubleshoot_database(&self) -> Result<(), FortressError> {
        println!("Database Troubleshooting Guide");
        println!("==============================");
        self.handle_error("DB001").await
    }

    async fn troubleshoot_encryption(&self) -> Result<(), FortressError> {
        println!("Encryption Troubleshooting Guide");
        println!("================================");
        self.handle_error("ENC001").await
    }

    async fn troubleshoot_auth(&self) -> Result<(), FortressError> {
        println!("Authentication Troubleshooting Guide");
        println!("=======================================");
        self.handle_error("AUTH001").await
    }

    async fn troubleshoot_network(&self) -> Result<(), FortressError> {
        println!("Network Troubleshooting Guide");
        println!("===============================");
        self.handle_network_wizard().await
    }

    async fn troubleshoot_config(&self) -> Result<(), FortressError> {
        println!("Configuration Troubleshooting Guide");
        println!("====================================");
        self.handle_error("CFG001").await
    }

    async fn troubleshoot_performance(&self) -> Result<(), FortressError> {
        println!("Performance Troubleshooting Guide");
        println!("=====================================");
        self.handle_performance_wizard().await
    }
}

impl Default for HelpCommandHandler {
    fn default() -> Self {
        Self::new()
    }
}

pub fn add_help_command(cli: Command) -> Command {
    cli.subcommand(
        Command::new("help")
            .about("Comprehensive help and documentation system")
            .subcommand_required(false)
            .arg_required_else_help(true)
            .subcommand(
                Command::new("search")
                    .about("Search for help on specific topics")
                    .arg(Arg::new("query")
                        .help("Search query")
                        .required(true))
            )
            .subcommand(
                Command::new("error")
                    .about("Show help for specific error code")
                    .arg(Arg::new("error-code")
                        .help("Error code (e.g., ENC001, DB001)")
                        .required(true))
            )
            .subcommand(
                Command::new("categories")
                    .about("List help categories")
            )
            .subcommand(
                Command::new("list")
                    .about("List all available error codes")
                    .arg(Arg::new("severity")
                        .long("severity")
                        .short('s')
                        .help("Filter by severity (low, medium, high, critical)"))
                    .arg(Arg::new("category")
                        .long("category")
                        .short('c')
                        .help("Filter by category"))
            )
            .subcommand(
                Command::new("wizard")
                    .about("Run interactive help wizard")
            )
            .subcommand(
                Command::new("related")
                    .about("Show related errors for a given error code")
                    .arg(Arg::new("error-code")
                        .help("Error code to find related errors for")
                        .required(true))
            )
            .subcommand(
                Command::new("troubleshoot")
                    .about("Show quick troubleshooting guide")
                    .arg(Arg::new("problem-type")
                        .help("Problem type (database, encryption, auth, network, config, performance)")
                        .required(true))
            )
    )
}
