use crate::enhanced_error::FortressError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub severity: String,
    pub category: String,
}

impl ErrorDocumentation {
    pub fn for_error_code(code: &str) -> Option<Self> {
        match code {
            "ENC001" => Some(Self {
                error_code: "ENC001".to_string(),
                title: "Invalid Key Length".to_string(),
                description: "The provided key length doesn't match the requirements for the selected encryption algorithm".to_string(),
                common_causes: vec![
                    "Key was generated with incorrect parameters".to_string(),
                    "Key file was corrupted during storage or transfer".to_string(),
                    "Wrong algorithm specified for the key".to_string(),
                    "Key was truncated or padded incorrectly".to_string(),
                ],
                solutions: vec![
                    "Generate a new key with the correct length for your algorithm".to_string(),
                    "Use 'fortress key generate --algorithm <algo> --length <bits>' to create a proper key".to_string(),
                    "Verify key integrity with 'fortress key validate <key-id>'".to_string(),
                    "Check the algorithm documentation for required key lengths".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/encryption/key-management".to_string(),
                    "https://docs.fortress.security/algorithms/supported".to_string(),
                ],
                examples: vec![
                    "fortress key generate --algorithm aegis256 --length 256".to_string(),
                    "fortress key generate --algorithm aes256gcm --length 256".to_string(),
                    "fortress key generate --algorithm chacha20 --length 256".to_string(),
                ],
                prevention_tips: vec![
                    "Always validate keys after generation".to_string(),
                    "Store keys in secure, backed-up locations".to_string(),
                    "Use the CLI tools for key generation to avoid manual errors".to_string(),
                    "Document key parameters in your configuration".to_string(),
                ],
                severity: "High".to_string(),
                category: "Encryption".to_string(),
            }),
            
            "DB001" => Some(Self {
                error_code: "DB001".to_string(),
                title: "Database Connection Failed".to_string(),
                description: "Unable to establish connection to the configured database".to_string(),
                common_causes: vec![
                    "Database server is not running".to_string(),
                    "Incorrect connection parameters (host, port, database name)".to_string(),
                    "Network connectivity issues".to_string(),
                    "Invalid credentials or insufficient permissions".to_string(),
                    "Firewall blocking the connection".to_string(),
                ],
                solutions: vec![
                    "Verify database server status with your database admin tools".to_string(),
                    "Check connection parameters in the configuration file".to_string(),
                    "Test network connectivity: 'ping <database-host>'".to_string(),
                    "Verify credentials with 'fortress config test-database'".to_string(),
                    "Check firewall rules and open necessary ports".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/database/configuration".to_string(),
                    "https://docs.fortress.security/troubleshooting/database".to_string(),
                ],
                examples: vec![
                    "fortress config test-database --config ./fortress.toml".to_string(),
                    "psql -h localhost -p 5432 -U fortress -d fortress".to_string(),
                ],
                prevention_tips: vec![
                    "Use environment variables for sensitive credentials".to_string(),
                    "Implement connection pooling to handle temporary network issues".to_string(),
                    "Set up database health checks".to_string(),
                    "Document database requirements for your operations team".to_string(),
                ],
                severity: "High".to_string(),
                category: "Database".to_string(),
            }),
            
            "CFG001" => Some(Self {
                error_code: "CFG001".to_string(),
                title: "Invalid Configuration Value".to_string(),
                description: "A configuration field has an invalid value or format".to_string(),
                common_causes: vec![
                    "Typo in configuration field name or value".to_string(),
                    "Incorrect data type for a field".to_string(),
                    "Missing required configuration fields".to_string(),
                    "Configuration file syntax errors".to_string(),
                    "Environment variable overrides with invalid values".to_string(),
                ],
                solutions: vec![
                    "Run 'fortress config validate' to check your configuration".to_string(),
                    "Use the interactive configuration wizard: 'fortress config init --interactive'".to_string(),
                    "Check the configuration documentation for field requirements".to_string(),
                    "Verify TOML syntax with an online validator".to_string(),
                    "Review environment variable overrides".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/configuration/overview".to_string(),
                    "https://docs.fortress.security/configuration/reference".to_string(),
                ],
                examples: vec![
                    "fortress config validate --config ./fortress.toml".to_string(),
                    "fortress config init --interactive".to_string(),
                    "fortress config show --format json".to_string(),
                ],
                prevention_tips: vec![
                    "Use the configuration wizard to avoid manual errors".to_string(),
                    "Validate configuration files in CI/CD pipelines".to_string(),
                    "Keep configuration files under version control".to_string(),
                    "Document custom configuration requirements".to_string(),
                ],
                severity: "Medium".to_string(),
                category: "Configuration".to_string(),
            }),
            
            "AUTH001" => Some(Self {
                error_code: "AUTH001".to_string(),
                title: "Authentication Failed".to_string(),
                description: "Unable to authenticate the user with the provided credentials".to_string(),
                common_causes: vec![
                    "Invalid username or password".to_string(),
                    "Expired authentication token".to_string(),
                    "Incorrect authentication method".to_string(),
                    "Account locked or disabled".to_string(),
                    "Multi-factor authentication required but not provided".to_string(),
                ],
                solutions: vec![
                    "Verify your username and password are correct".to_string(),
                    "Generate a new token if yours has expired".to_string(),
                    "Check if your account is active and not locked".to_string(),
                    "Complete MFA setup if required".to_string(),
                    "Contact your administrator if you continue to have issues".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/authentication/overview".to_string(),
                    "https://docs.fortress.security/authentication/troubleshooting".to_string(),
                ],
                examples: vec![
                    "fortress login --username admin --password secret".to_string(),
                    "fortress auth token --refresh".to_string(),
                    "fortress auth status".to_string(),
                ],
                prevention_tips: vec![
                    "Use strong, unique passwords".to_string(),
                    "Enable multi-factor authentication when available".to_string(),
                    "Regularly rotate your authentication tokens".to_string(),
                    "Use password managers to avoid typos".to_string(),
                ],
                severity: "High".to_string(),
                category: "Authentication".to_string(),
            }),
            
            "KEY001" => Some(Self {
                error_code: "KEY001".to_string(),
                title: "Key Management Error".to_string(),
                description: "An error occurred during a key management operation".to_string(),
                common_causes: vec![
                    "Key ID does not exist".to_string(),
                    "Insufficient permissions for key operation".to_string(),
                    "Key is corrupted or invalid".to_string(),
                    "Key rotation conflicts with ongoing operations".to_string(),
                    "HSM provider is not available".to_string(),
                ],
                solutions: vec![
                    "Verify the key ID exists with 'fortress key list'".to_string(),
                    "Check your permissions for the requested operation".to_string(),
                    "Validate key integrity with 'fortress key validate <key-id>'".to_string(),
                    "Wait for ongoing operations to complete before rotating".to_string(),
                    "Check HSM provider status and connectivity".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/keys/management".to_string(),
                    "https://docs.fortress.security/keys/troubleshooting".to_string(),
                ],
                examples: vec![
                    "fortress key list --format table".to_string(),
                    "fortress key validate --id key_001".to_string(),
                    "fortress key rotate --id key_001".to_string(),
                ],
                prevention_tips: vec![
                    "Keep an inventory of all keys and their purposes".to_string(),
                    "Regularly validate key integrity".to_string(),
                    "Document key rotation schedules".to_string(),
                    "Implement proper access controls for key operations".to_string(),
                ],
                severity: "High".to_string(),
                category: "Key Management".to_string(),
            }),
            
            "NET001" => Some(Self {
                error_code: "NET001".to_string(),
                title: "Network Operation Failed".to_string(),
                description: "A network operation could not be completed successfully".to_string(),
                common_causes: vec![
                    "No internet connectivity".to_string(),
                    "Invalid URL or endpoint".to_string(),
                    "DNS resolution failed".to_string(),
                    "Connection timeout".to_string(),
                    "SSL/TLS certificate issues".to_string(),
                ],
                solutions: vec![
                    "Check your internet connection with 'ping google.com'".to_string(),
                    "Verify the URL is correct and accessible".to_string(),
                    "Check DNS settings and try alternative DNS servers".to_string(),
                    "Increase timeout values for slow connections".to_string(),
                    "Verify SSL certificates are valid and trusted".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/networking/configuration".to_string(),
                    "https://docs.fortress.security/networking/troubleshooting".to_string(),
                ],
                examples: vec![
                    "curl -I https://api.fortress.security".to_string(),
                    "nslookup api.fortress.security".to_string(),
                    "traceroute api.fortress.security".to_string(),
                ],
                prevention_tips: vec![
                    "Implement retry logic for transient network failures".to_string(),
                    "Use reliable DNS servers".to_string(),
                    "Monitor network connectivity and performance".to_string(),
                    "Keep SSL certificates up to date".to_string(),
                ],
                severity: "Medium".to_string(),
                category: "Networking".to_string(),
            }),
            
            "PLUGIN001" => Some(Self {
                error_code: "PLUGIN001".to_string(),
                title: "Plugin Operation Failed".to_string(),
                description: "An error occurred while executing a plugin operation".to_string(),
                common_causes: vec![
                    "Plugin is not installed".to_string(),
                    "Plugin is disabled".to_string(),
                    "Plugin version is incompatible".to_string(),
                    "Plugin configuration is invalid".to_string(),
                    "Plugin execution timeout".to_string(),
                ],
                solutions: vec![
                    "Install the plugin with 'fortress plugin install <url>'".to_string(),
                    "Enable the plugin with 'fortress plugin enable <name>'".to_string(),
                    "Check plugin compatibility with your Fortress version".to_string(),
                    "Validate plugin configuration".to_string(),
                    "Increase plugin timeout if operations are slow".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/plugins/development".to_string(),
                    "https://docs.fortress.security/plugins/troubleshooting".to_string(),
                ],
                examples: vec![
                    "fortress plugin list --format table".to_string(),
                    "fortress plugin install --url https://example.com/plugin.wasm".to_string(),
                    "fortress plugin enable --name auth-plugin".to_string(),
                ],
                prevention_tips: vec![
                    "Test plugins in a development environment first".to_string(),
                    "Keep plugins updated to compatible versions".to_string(),
                    "Monitor plugin performance and resource usage".to_string(),
                    "Document plugin configurations and dependencies".to_string(),
                ],
                severity: "Medium".to_string(),
                category: "Plugins".to_string(),
            }),
            
            "COMP001" => Some(Self {
                error_code: "COMP001".to_string(),
                title: "Compliance Check Failed".to_string(),
                description: "A compliance check did not meet the required standards".to_string(),
                common_causes: vec![
                    "Missing security controls".to_string(),
                    "Incorrect configuration for compliance requirements".to_string(),
                    "Outdated policies or procedures".to_string(),
                    "Insufficient audit logging".to_string(),
                    "Data retention policy violations".to_string(),
                ],
                solutions: vec![
                    "Review the compliance requirements for your framework".to_string(),
                    "Update configuration to meet all required controls".to_string(),
                    "Implement missing security controls".to_string(),
                    "Enable comprehensive audit logging".to_string(),
                    "Configure proper data retention policies".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/compliance/gdpr".to_string(),
                    "https://docs.fortress.security/compliance/hipaa".to_string(),
                    "https://docs.fortress.security/compliance/pci-dss".to_string(),
                ],
                examples: vec![
                    "fortress compliance audit --framework gdpr".to_string(),
                    "fortress compliance validate --framework hipaa".to_string(),
                    "fortress compliance report --framework pci-dss --output report.json".to_string(),
                ],
                prevention_tips: vec![
                    "Regularly run compliance audits".to_string(),
                    "Keep security policies up to date".to_string(),
                    "Document all compliance procedures".to_string(),
                    "Train staff on compliance requirements".to_string(),
                ],
                severity: "High".to_string(),
                category: "Compliance".to_string(),
            }),
            
            "CLUSTER001" => Some(Self {
                error_code: "CLUSTER001".to_string(),
                title: "Cluster Operation Failed".to_string(),
                description: "An error occurred during a cluster operation".to_string(),
                common_causes: vec![
                    "Node is not reachable".to_string(),
                    "Cluster configuration mismatch".to_string(),
                    "Network partition between nodes".to_string(),
                    "Insufficient quorum for operation".to_string(),
                    "Raft consensus algorithm failure".to_string(),
                ],
                solutions: vec![
                    "Check network connectivity between cluster nodes".to_string(),
                    "Verify cluster configuration is consistent across all nodes".to_string(),
                    "Ensure sufficient nodes are available for quorum".to_string(),
                    "Check Raft log consistency".to_string(),
                    "Restart failed nodes if necessary".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/clustering/overview".to_string(),
                    "https://docs.fortress.security/clustering/troubleshooting".to_string(),
                ],
                examples: vec![
                    "fortress cluster status --format json".to_string(),
                    "fortress cluster nodes --format table".to_string(),
                    "fortress cluster init --node-id node1".to_string(),
                ],
                prevention_tips: vec![
                    "Monitor cluster health continuously".to_string(),
                    "Implement automated failover mechanisms".to_string(),
                    "Keep cluster configurations in sync".to_string(),
                    "Test cluster recovery procedures regularly".to_string(),
                ],
                severity: "High".to_string(),
                category: "Clustering".to_string(),
            }),
            
            "VALID001" => Some(Self {
                error_code: "VALID001".to_string(),
                title: "Validation Error".to_string(),
                description: "Input validation failed due to constraint violation".to_string(),
                common_causes: vec![
                    "Invalid input format".to_string(),
                    "Value outside allowed range".to_string(),
                    "Missing required fields".to_string(),
                    "Invalid characters in input".to_string(),
                    "Constraint violation".to_string(),
                ],
                solutions: vec![
                    "Check the input format requirements".to_string(),
                    "Ensure values are within allowed ranges".to_string(),
                    "Provide all required fields".to_string(),
                    "Use only allowed characters".to_string(),
                    "Review the specific constraint that was violated".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/validation/overview".to_string(),
                    "https://docs.fortress.security/validation/constraints".to_string(),
                ],
                examples: vec![
                    "fortress utils validate --input data.json".to_string(),
                    "fortress config validate".to_string(),
                    "fortress key validate --id key_001".to_string(),
                ],
                prevention_tips: vec![
                    "Validate input early in your workflow".to_string(),
                    "Use schema validation for structured data".to_string(),
                    "Provide clear error messages for validation failures".to_string(),
                    "Document all validation rules and constraints".to_string(),
                ],
                severity: "Low".to_string(),
                category: "Validation".to_string(),
            }),
            
            "PERM001" => Some(Self {
                error_code: "PERM001".to_string(),
                title: "Permission Denied".to_string(),
                description: "Insufficient permissions to perform the requested operation".to_string(),
                common_causes: vec![
                    "User lacks required role".to_string(),
                    "Resource access not granted".to_string(),
                    "Operation not allowed for user role".to_string(),
                    "RBAC policy denies access".to_string(),
                    "ABAC policy conditions not met".to_string(),
                ],
                solutions: vec![
                    "Contact your administrator for required permissions".to_string(),
                    "Check your current roles and permissions".to_string(),
                    "Verify resource access policies".to_string(),
                    "Review RBAC/ABAC policy rules".to_string(),
                    "Request additional permissions if needed".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/security/rbac".to_string(),
                    "https://docs.fortress.security/security/abac".to_string(),
                ],
                examples: vec![
                    "fortress auth whoami".to_string(),
                    "fortress auth permissions --resource database".to_string(),
                    "fortress auth roles --user admin".to_string(),
                ],
                prevention_tips: vec![
                    "Follow principle of least privilege".to_string(),
                    "Regularly review and audit permissions".to_string(),
                    "Document permission requirements".to_string(),
                    "Use role-based access control where possible".to_string(),
                ],
                severity: "Medium".to_string(),
                category: "Security".to_string(),
            }),
            
            "TIMEOUT001" => Some(Self {
                error_code: "TIMEOUT001".to_string(),
                title: "Operation Timeout".to_string(),
                description: "Operation did not complete within the allocated time".to_string(),
                common_causes: vec![
                    "Network latency".to_string(),
                    "High system load".to_string(),
                    "Large dataset processing".to_string(),
                    "Resource contention".to_string(),
                    "Timeout value too low".to_string(),
                ],
                solutions: vec![
                    "Increase timeout values for slow operations".to_string(),
                    "Optimize the operation for better performance".to_string(),
                    "Check system resource utilization".to_string(),
                    "Process data in smaller batches".to_string(),
                    "Improve network connectivity".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/performance/optimization".to_string(),
                    "https://docs.fortress.security/configuration/timeouts".to_string(),
                ],
                examples: vec![
                    "fortress config set --timeout 300".to_string(),
                    "fortress encrypt --input large_file.dat --timeout 600".to_string(),
                    "fortress server status --detailed".to_string(),
                ],
                prevention_tips: vec![
                    "Set appropriate timeout values for your environment".to_string(),
                    "Monitor operation performance regularly".to_string(),
                    "Implement progress tracking for long operations".to_string(),
                    "Use asynchronous operations where possible".to_string(),
                ],
                severity: "Medium".to_string(),
                category: "Performance".to_string(),
            }),
            
            "RATE001" => Some(Self {
                error_code: "RATE001".to_string(),
                title: "Rate Limit Exceeded".to_string(),
                description: "Too many requests were made within the time window".to_string(),
                common_causes: vec![
                    "High request frequency".to_string(),
                    "Concurrent operations".to_string(),
                    "Automated scripts making too many requests".to_string(),
                    "Rate limit threshold too low".to_string(),
                    "Load testing or stress testing".to_string(),
                ],
                solutions: vec![
                    "Reduce request frequency".to_string(),
                    "Implement exponential backoff retry logic".to_string(),
                    "Use batch operations instead of individual requests".to_string(),
                    "Increase rate limit if appropriate".to_string(),
                    "Optimize your application logic".to_string(),
                ],
                related_docs: vec![
                    "https://docs.fortress.security/api/rate-limiting".to_string(),
                    "https://docs.fortress.security/performance/best-practices".to_string(),
                ],
                examples: vec![
                    "fortress config set --rate-limit 1000".to_string(),
                    "fortress api status --rate-limits".to_string(),
                    "fortress encrypt --batch --input files/".to_string(),
                ],
                prevention_tips: vec![
                    "Implement client-side rate limiting".to_string(),
                    "Use connection pooling for database operations".to_string(),
                    "Cache frequently accessed data".to_string(),
                    "Monitor your request patterns".to_string(),
                ],
                severity: "Low".to_string(),
                category: "API".to_string(),
            }),
            
            _ => None,
        }
    }

    pub fn format_for_display(&self) -> String {
        let mut output = String::new();

        output.push_str(&format!("✗ Error Code: {}\n", self.error_code));
        output.push_str(&format!("Title: {}\n", self.title));
        output.push_str(&format!("Description: {}\n", self.description));
        output.push_str(&format!("Severity: {}\n", self.severity));
        output.push_str(&format!("Category: {}\n\n", self.category));

        output.push_str("Common Causes:\n");
        for (i, cause) in self.common_causes.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", i + 1, cause));
        }

        output.push_str("\nSolutions:\n");
        for (i, solution) in self.solutions.iter().enumerate() {
            output.push_str(&format!("  {}. {}\n", i + 1, solution));
        }

        if !self.examples.is_empty() {
            output.push_str("\nExample Commands:\n");
            for example in &self.examples {
                output.push_str(&format!("  $ {}\n", example));
            }
        }

        if !self.prevention_tips.is_empty() {
            output.push_str("\nPrevention Tips:\n");
            for (i, tip) in self.prevention_tips.iter().enumerate() {
                output.push_str(&format!("  {}. {}\n", i + 1, tip));
            }
        }

        if !self.related_docs.is_empty() {
            output.push_str("\nRelated Documentation:\n");
            for doc in &self.related_docs {
                output.push_str(&format!("  • {}\n", doc));
            }
        }

        output
    }

    pub fn format_short(&self) -> String {
        format!(
            "🔴 {} ({}): {} - {}",
            self.error_code, self.severity, self.title, self.description
        )
    }
}

pub struct ErrorDocumentationRegistry {
    docs: HashMap<String, ErrorDocumentation>,
}

impl ErrorDocumentationRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            docs: HashMap::new(),
        };

        // Pre-load common error documentation
        let common_codes = vec![
            "ENC001",
            "DB001",
            "CFG001",
            "AUTH001",
            "KEY001",
            "NET001",
            "PLUGIN001",
            "COMP001",
            "CLUSTER001",
            "VALID001",
            "PERM001",
            "TIMEOUT001",
            "RATE001",
        ];

        for code in common_codes {
            if let Some(doc) = ErrorDocumentation::for_error_code(code) {
                registry.docs.insert(code.to_string(), doc);
            }
        }

        registry
    }

    pub fn get(&self, error_code: &str) -> Option<&ErrorDocumentation> {
        self.docs.get(error_code)
    }

    pub fn get_or_load(&mut self, error_code: &str) -> Option<&ErrorDocumentation> {
        if !self.docs.contains_key(error_code) {
            if let Some(doc) = ErrorDocumentation::for_error_code(error_code) {
                self.docs.insert(error_code.to_string(), doc);
            }
        }
        self.docs.get(error_code)
    }

    pub fn list_by_category(&self, category: &str) -> Vec<&ErrorDocumentation> {
        self.docs
            .values()
            .filter(|doc| doc.category == category)
            .collect()
    }

    pub fn list_by_severity(&self, severity: &str) -> Vec<&ErrorDocumentation> {
        self.docs
            .values()
            .filter(|doc| doc.severity == severity)
            .collect()
    }

    pub fn all_categories(&self) -> Vec<String> {
        let mut categories: Vec<String> = self
            .docs
            .values()
            .map(|doc| doc.category.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        categories.sort();
        categories
    }

    pub fn search(&self, query: &str) -> Vec<&ErrorDocumentation> {
        let query_lower = query.to_lowercase();
        self.docs
            .values()
            .filter(|doc| {
                doc.title.to_lowercase().contains(&query_lower)
                    || doc.description.to_lowercase().contains(&query_lower)
                    || doc.error_code.to_lowercase().contains(&query_lower)
                    || doc.category.to_lowercase().contains(&query_lower)
            })
            .collect()
    }
}

impl Default for ErrorDocumentationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Enhanced error display for CLI
pub fn display_error_enhanced(error: &FortressError) {
    let error_code = error.error_code();

    println!("✗ Fortress Error: {}", error);
    println!("Error Code: {}", error_code);
    println!("Severity: {}", error.severity());
    println!("Help: {}", error.help_text());

    // Show troubleshooting steps
    let steps = error.troubleshooting_steps();
    if !steps.is_empty() {
        println!("\nTroubleshooting Steps:");
        for (i, step) in steps.iter().enumerate() {
            println!("  {}. {}", i + 1, step);
        }
    }

    // Show detailed documentation if available
    if let Some(doc) = ErrorDocumentation::for_error_code(error_code) {
        println!("\n{}", doc.format_for_display());
    }

    // Suggest next steps
    println!("\nNext Steps:");
    println!("  • Run 'fortress --help' for available commands");
    println!("  • Check documentation at: https://docs.fortress.security");
    println!("  • Report issues at: https://github.com/Genius740Code/Fortress/issues");

    // Show recoverability
    if error.is_recoverable() {
        println!("  ✓ This error is recoverable - try the suggested solutions above");
    } else {
        println!("  ⚠ This error requires administrative intervention");
    }
}

pub fn display_error_compact(error: &FortressError) {
    let error_code = error.error_code();

    if let Some(doc) = ErrorDocumentation::for_error_code(error_code) {
        println!("{}", doc.format_short());
    } else {
        println!("🔴 {} ({}): {}", error_code, error.severity(), error);
    }
}

pub fn display_error_json(error: &FortressError) -> Result<(), serde_json::Error> {
    let error_json = serde_json::json!({
        "error": {
            "code": error.error_code(),
            "message": error.to_string(),
            "severity": error.severity().to_string(),
            "help_text": error.help_text(),
            "troubleshooting_steps": error.troubleshooting_steps(),
            "recoverable": error.is_recoverable()
        }
    });

    println!("{}", serde_json::to_string_pretty(&error_json)?);
    Ok(())
}
