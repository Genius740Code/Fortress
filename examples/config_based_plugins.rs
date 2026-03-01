//! Configuration-Based Plugin System
//! 
//! This demonstrates an even easier way to create plugins using configuration files
//! and automatic code generation. Users can define plugins in JSON/YAML and
//! the system will generate the plugin code automatically.

use fortress_core::prelude::*;
use fortress_core::plugin::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

/// Plugin definition from configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigPlugin {
    pub name: String,
    pub id: String,
    pub description: String,
    pub version: String,
    pub author: Option<String>,
    pub capabilities: Vec<String>,
    pub actions: HashMap<String, ConfigAction>,
    pub config_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigAction {
    pub description: String,
    pub handler_type: HandlerType,
    pub parameters: HashMap<String, ConfigParameter>,
    pub script: Option<String>, // For script-based actions
    pub api_endpoint: Option<String>, // For API-based actions
    pub transformation: Option<String>, // For data transformation
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HandlerType {
    Script,
    Api,
    Transform,
    Rust,
    JavaScript,
    Python,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigParameter {
    #[serde(rename = "type")]
    pub param_type: String,
    pub required: Option<bool>,
    pub default: Option<serde_json::Value>,
    pub description: Option<String>,
}

/// Generated plugin from configuration
pub struct GeneratedPlugin {
    metadata: PluginMetadata,
    config: ConfigPlugin,
}

impl GeneratedPlugin {
    pub fn from_config(config: ConfigPlugin) -> Result<Self> {
        let capabilities = config.capabilities
            .into_iter()
            .map(|cap| {
                match cap.as_str() {
                    "sign_transaction" => PluginCapability::SignTransaction,
                    "verify_signature" => PluginCapability::VerifySignature,
                    "generate_key" => PluginCapability::GenerateKey,
                    "encrypt" => PluginCapability::Encrypt,
                    "decrypt" => PluginCapability::Decrypt,
                    "hash" => PluginCapability::Hash,
                    "api_integration" => PluginCapability::ApiIntegration,
                    "secret_management" => PluginCapability::SecretManagement,
                    custom => PluginCapability::Custom(custom.to_string()),
                }
            })
            .collect();

        let metadata = PluginMetadata {
            id: config.id.clone(),
            name: config.name.clone(),
            version: config.version.clone(),
            description: config.description.clone(),
            author: config.author.unwrap_or_else(|| "Generated Plugin".to_string()),
            capabilities,
            config_schema: config.config_schema.clone(),
        };

        Ok(Self {
            metadata,
            config,
        })
    }

    pub fn load_from_file(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| FortressError::plugin(format!("Failed to read plugin config: {}", e)))?;
        
        let config: ConfigPlugin = serde_json::from_str(&content)
            .map_err(|e| FortressError::plugin(format!("Failed to parse plugin config: {}", e)))?;
        
        Self::from_config(config)
    }

    async fn execute_script_action(&self, script: &str, input: &PluginInput) -> Result<serde_json::Value> {
        // This is a simplified script executor
        // In a real implementation, you'd use a proper scripting engine
        
        if script.contains("return") {
            // Simple return statement extraction
            if let Some(start) = script.find("return") {
                let after_return = &script[start + 6..];
                if let Some(end) = after_return.find(';') {
                    let expression = after_return[..end].trim();
                    
                    // Handle simple expressions
                    if expression.contains("+") {
                        let parts: Vec<&str> = expression.split('+').collect();
                        if parts.len() == 2 {
                            let a = self.extract_number(parts[0].trim(), input)?;
                            let b = self.extract_number(parts[1].trim(), input)?;
                            return Ok(serde_json::json!(a + b));
                        }
                    }
                    
                    if expression.contains("*") {
                        let parts: Vec<&str> = expression.split('*').collect();
                        if parts.len() == 2 {
                            let a = self.extract_number(parts[0].trim(), input)?;
                            let b = self.extract_number(parts[1].trim(), input)?;
                            return Ok(serde_json::json!(a * b));
                        }
                    }
                }
            }
        }
        
        // Default: return input data as-is
        Ok(input.data.clone())
    }

    fn extract_number(&self, expr: &str, input: &PluginInput) -> Result<f64> {
        let expr = expr.trim();
        
        // Try to parse as number directly
        if let Ok(num) = expr.parse::<f64>() {
            return Ok(num);
        }
        
        // Try to extract from input data
        if expr.starts_with("input.") {
            let path = &expr[6..];
            if let Some(value) = input.data.pointer(path) {
                return value.as_f64()
                    .ok_or_else(|| FortressError::plugin("Expected numeric value"));
            }
        }
        
        Err(FortressError::plugin(format!("Cannot extract number from: {}", expr)))
    }

    async fn execute_api_action(&self, endpoint: &str, input: &PluginInput) -> Result<serde_json::Value> {
        let client = reqwest::Client::new();
        
        // Build URL from endpoint template
        let url = self.replace_placeholders(endpoint, input);
        
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| FortressError::plugin(format!("API call failed: {}", e)))?;

        let data: serde_json::Value = response
            .json()
            .await
            .map_err(|e| FortressError::plugin(format!("Failed to parse API response: {}", e)))?;

        Ok(data)
    }

    fn replace_placeholders(&self, template: &str, input: &PluginInput) -> String {
        let mut result = template.to_string();
        
        // Replace {input.field} placeholders
        if let Some(data_str) = input.data.as_str() {
            result = result.replace("{input}", data_str);
        }
        
        // Replace parameter placeholders
        for (key, value) in &input.parameters {
            let placeholder = format!("{{{}}}", key);
            if let Some(value_str) = value.as_str() {
                result = result.replace(&placeholder, value_str);
            }
        }
        
        result
    }
}

#[async_trait]
impl Plugin for GeneratedPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        println!("Initializing generated plugin: {}", self.config.name);
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        let start_time = std::time::Instant::now();
        
        let action_config = self.config.actions.get(&input.action)
            .ok_or_else(|| FortressError::plugin(format!("Unknown action: {}", input.action)))?;

        let result = match &action_config.handler_type {
            HandlerType::Script => {
                if let Some(script) = &action_config.script {
                    self.execute_script_action(script, &input).await
                } else {
                    Err(FortressError::plugin("Script action missing script"))
                }
            }
            HandlerType::Api => {
                if let Some(endpoint) = &action_config.api_endpoint {
                    self.execute_api_action(endpoint, &input).await
                } else {
                    Err(FortressError::plugin("API action missing endpoint"))
                }
            }
            HandlerType::Transform => {
                // Simple data transformation
                if let Some(transformation) = &action_config.transformation {
                    self.apply_transformation(transformation, &input)
                } else {
                    Err(FortressError::plugin("Transform action missing transformation"))
                }
            }
            _ => Err(FortressError::plugin("Handler type not implemented")),
        };

        let execution_time = start_time.elapsed().as_millis() as u64;
        
        match result {
            Ok(data) => Ok(PluginResult {
                success: true,
                data: Some(data),
                error: None,
                metrics: PluginMetrics {
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0,
                    custom_metrics: HashMap::new(),
                },
            }),
            Err(e) => Ok(PluginResult {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metrics: PluginMetrics {
                    execution_time_ms: execution_time,
                    memory_usage_bytes: 0,
                    custom_metrics: HashMap::new(),
                },
            }),
        }
    }

    async fn cleanup(&self) -> Result<()> {
        println!("Cleaning up generated plugin: {}", self.config.name);
        Ok(())
    }

    fn validate_config(&self, config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Validate against the plugin's config schema if present
        if let Some(schema) = &self.config.config_schema {
            // Simple validation - in a real implementation, use json-schema validation
            if schema.get("required").is_some() {
                for required_field in schema["required"].as_array().unwrap_or(&serde_json::json::([])) {
                    if let Some(field_name) = required_field.as_str() {
                        if !config.contains_key(field_name) {
                            return Err(FortressError::plugin(format!(
                                "Missing required field: {}", field_name
                            )));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn health_check(&self) -> Result<PluginHealth> {
        Ok(PluginHealth {
            healthy: true,
            message: format!("Generated plugin '{}' is healthy", self.config.name),
            last_check: chrono::Utc::now(),
        })
    }
}

impl GeneratedPlugin {
    fn apply_transformation(&self, transformation: &str, input: &PluginInput) -> Result<serde_json::Value> {
        match transformation {
            "uppercase" => {
                if let Some(text) = input.data.as_str() {
                    Ok(serde_json::json!(text.to_uppercase()))
                } else {
                    Err(FortressError::plugin("Expected string input for uppercase transformation"))
                }
            }
            "lowercase" => {
                if let Some(text) = input.data.as_str() {
                    Ok(serde_json::json!(text.to_lowercase()))
                } else {
                    Err(FortressError::plugin("Expected string input for lowercase transformation"))
                }
            }
            "reverse" => {
                if let Some(text) = input.data.as_str() {
                    Ok(serde_json::json!(text.chars().rev().collect::<String>()))
                } else {
                    Err(FortressError::plugin("Expected string input for reverse transformation"))
                }
            }
            "length" => {
                if let Some(text) = input.data.as_str() {
                    Ok(serde_json::json!(text.len()))
                } else {
                    Err(FortressError::plugin("Expected string input for length transformation"))
                }
            }
            _ => Err(FortressError::plugin(format!("Unknown transformation: {}", transformation))),
        }
    }
}

// ============================================================================
// PLUGIN GENERATOR
// ============================================================================

pub struct PluginGenerator;

impl PluginGenerator {
    pub fn generate_rust_code(config: &ConfigPlugin) -> Result<String> {
        let mut code = String::new();
        
        // Add imports
        code.push_str("use fortress_core::prelude::*;\n");
        code.push_str("use fortress_core::plugin::*;\n");
        code.push_str("use async_trait::async_trait;\n");
        code.push_str("use serde::{Deserialize, Serialize};\n");
        code.push_str("use std::collections::HashMap;\n\n");
        
        // Add struct definition
        code.push_str(&format!("pub struct {} {{\n", config.name.replace(' ', "")));
        code.push_str("    metadata: PluginMetadata,\n");
        code.push_str("}\n\n");
        
        // Add impl block
        code.push_str(&format!("impl {} {{\n", config.name.replace(' ', "")));
        code.push_str("    pub fn new() -> Self {\n");
        code.push_str("        Self {\n");
        code.push_str("            metadata: PluginMetadata {\n");
        code.push_str(&format!("                id: \"{}\".to_string(),\n", config.id));
        code.push_str(&format!("                name: \"{}\".to_string(),\n", config.name));
        code.push_str(&format!("                version: \"{}\".to_string(),\n", config.version));
        code.push_str(&format!("                description: \"{}\".to_string(),\n", config.description));
        code.push_str(&format!("                author: \"{}\".to_string(),\n", 
            config.author.as_deref().unwrap_or("Generated Plugin")));
        code.push_str("                capabilities: vec![\n");
        
        for cap in &config.capabilities {
            code.push_str(&format!("                    PluginCapability::Custom(\"{}\".to_string()),\n", cap));
        }
        
        code.push_str("                ],\n");
        code.push_str("                config_schema: None,\n");
        code.push_str("            },\n");
        code.push_str("        }\n");
        code.push_str("    }\n");
        code.push_str("}\n\n");
        
        // Add Plugin trait implementation
        code.push_str("#[async_trait]\n");
        code.push_str(&format!("impl Plugin for {} {{\n", config.name.replace(' ', "")));
        code.push_str("    fn metadata(&self) -> &PluginMetadata {\n");
        code.push_str("        &self.metadata\n");
        code.push_str("    }\n\n");
        
        code.push_str("    async fn initialize(&self, _context: PluginContext) -> Result<()> {\n");
        code.push_str("        Ok(())\n");
        code.push_str("    }\n\n");
        
        code.push_str("    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {\n");
        code.push_str("        let start_time = std::time::Instant::now();\n\n");
        
        for (action_name, action_config) in &config.actions {
            code.push_str(&format!("        if input.action == \"{}\" {{\n", action_name));
            
            match &action_config.handler_type {
                HandlerType::Script => {
                    if let Some(script) = &action_config.script {
                        code.push_str("            // Script: ");
                        code.push_str(script);
                        code.push_str("\n");
                        code.push_str("            return Ok(PluginResult {\n");
                        code.push_str("                success: true,\n");
                        code.push_str("                data: Some(input.data.clone()),\n");
                        code.push_str("                error: None,\n");
                        code.push_str("                metrics: PluginMetrics {\n");
                        code.push_str("                    execution_time_ms: start_time.elapsed().as_millis() as u64,\n");
                        code.push_str("                    memory_usage_bytes: 0,\n");
                        code.push_str("                    custom_metrics: HashMap::new(),\n");
                        code.push_str("                },\n");
                        code.push_str("            });\n");
                    }
                }
                HandlerType::Api => {
                    if let Some(endpoint) = &action_config.api_endpoint {
                        code.push_str("            // API call to: ");
                        code.push_str(endpoint);
                        code.push_str("\n");
                        code.push_str("            // Implementation would make HTTP request here\n");
                    }
                }
                _ => {
                    code.push_str("            // Handler type not implemented\n");
                }
            }
            
            code.push_str("        }\n\n");
        }
        
        code.push_str("        Err(FortressError::plugin(format!(\"Unknown action: {}\", input.action))\n");
        code.push_str("    }\n\n");
        
        code.push_str("    async fn cleanup(&self) -> Result<()> {\n");
        code.push_str("        Ok(())\n");
        code.push_str("    }\n\n");
        
        code.push_str("    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {\n");
        code.push_str("        Ok(())\n");
        code.push_str("    }\n\n");
        
        code.push_str("    async fn health_check(&self) -> Result<PluginHealth> {\n");
        code.push_str("        Ok(PluginHealth {\n");
        code.push_str("            healthy: true,\n");
        code.push_str("            message: \"Plugin is healthy\".to_string(),\n");
        code.push_str("            last_check: chrono::Utc::now(),\n");
        code.push_str("        })\n");
        code.push_str("    }\n");
        code.push_str("}\n");
        
        Ok(code)
    }
}

// ============================================================================
// EXAMPLE CONFIGURATION FILES
// ============================================================================

pub fn create_example_configs() -> Result<()> {
    // Example 1: Simple calculator plugin
    let calc_config = ConfigPlugin {
        name: "Simple Calculator".to_string(),
        id: "simple-calculator".to_string(),
        description: "Basic mathematical operations".to_string(),
        version: "1.0.0".to_string(),
        author: Some("Fortress Team".to_string()),
        capabilities: vec!["custom".to_string()],
        actions: {
            let mut actions = HashMap::new();
            actions.insert("add".to_string(), ConfigAction {
                description: "Add two numbers".to_string(),
                handler_type: HandlerType::Script,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("a".to_string(), ConfigParameter {
                        param_type: "number".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("First number".to_string()),
                    });
                    params.insert("b".to_string(), ConfigParameter {
                        param_type: "number".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("Second number".to_string()),
                    });
                    params
                },
                script: Some("return input.a + input.b;".to_string()),
                api_endpoint: None,
                transformation: None,
            });
            actions.insert("multiply".to_string(), ConfigAction {
                description: "Multiply two numbers".to_string(),
                handler_type: HandlerType::Script,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("a".to_string(), ConfigParameter {
                        param_type: "number".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("First number".to_string()),
                    });
                    params.insert("b".to_string(), ConfigParameter {
                        param_type: "number".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("Second number".to_string()),
                    });
                    params
                },
                script: Some("return input.a * input.b;".to_string()),
                api_endpoint: None,
                transformation: None,
            });
            actions
        },
        config_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "precision": {
                    "type": "integer",
                    "default": 2,
                    "description": "Decimal precision for calculations"
                }
            }
        })),
    };

    // Example 2: Text processing plugin
    let text_config = ConfigPlugin {
        name: "Text Processor".to_string(),
        id: "text-processor".to_string(),
        description: "Text transformation utilities".to_string(),
        version: "1.0.0".to_string(),
        author: Some("Fortress Team".to_string()),
        capabilities: vec!["custom".to_string()],
        actions: {
            let mut actions = HashMap::new();
            actions.insert("uppercase".to_string(), ConfigAction {
                description: "Convert text to uppercase".to_string(),
                handler_type: HandlerType::Transform,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("text".to_string(), ConfigParameter {
                        param_type: "string".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("Text to transform".to_string()),
                    });
                    params
                },
                script: None,
                api_endpoint: None,
                transformation: Some("uppercase".to_string()),
            });
            actions.insert("reverse".to_string(), ConfigAction {
                description: "Reverse text".to_string(),
                handler_type: HandlerType::Transform,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("text".to_string(), ConfigParameter {
                        param_type: "string".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("Text to reverse".to_string()),
                    });
                    params
                },
                script: None,
                api_endpoint: None,
                transformation: Some("reverse".to_string()),
            });
            actions
        },
        config_schema: None,
    };

    // Example 3: API integration plugin
    let api_config = ConfigPlugin {
        name: "Weather API".to_string(),
        id: "weather-api".to_string(),
        description: "Get weather information from external API".to_string(),
        version: "1.0.0".to_string(),
        author: Some("Fortress Team".to_string()),
        capabilities: vec!["api_integration".to_string()],
        actions: {
            let mut actions = HashMap::new();
            actions.insert("get_weather".to_string(), ConfigAction {
                description: "Get current weather for a city".to_string(),
                handler_type: HandlerType::Api,
                parameters: {
                    let mut params = HashMap::new();
                    params.insert("city".to_string(), ConfigParameter {
                        param_type: "string".to_string(),
                        required: Some(true),
                        default: None,
                        description: Some("City name".to_string()),
                    });
                    params
                },
                script: None,
                api_endpoint: Some("https://api.openweathermap.org/data/2.5/weather?q={city}&appid={api_key}".to_string()),
                transformation: None,
            });
            actions
        },
        config_schema: Some(serde_json::json!({
            "type": "object",
            "properties": {
                "api_key": {
                    "type": "string",
                    "description": "OpenWeatherMap API key"
                }
            },
            "required": ["api_key"]
        })),
    };

    // Write example configurations
    fs::write("calculator_plugin.json", serde_json::to_string_pretty(&calc_config)?)?;
    fs::write("text_processor_plugin.json", serde_json::to_string_pretty(&text_config)?)?;
    fs::write("weather_api_plugin.json", serde_json::to_string_pretty(&api_config)?)?;

    println!("Example plugin configurations created:");
    println!("- calculator_plugin.json");
    println!("- text_processor_plugin.json");
    println!("- weather_api_plugin.json");

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // Create example configurations
    create_example_configs()?;

    // Load and test a plugin from configuration
    println!("\nLoading calculator plugin from configuration...");
    let calc_plugin = GeneratedPlugin::load_from_file("calculator_plugin.json")?;
    
    let plugin_manager = PluginManager::new();
    let plugin = Arc::new(calc_plugin);
    let config = HashMap::new();
    
    plugin_manager.load_plugin(plugin, config).await?;

    // Test the plugin
    let result = plugin_manager.execute_plugin(
        "simple-calculator",
        PluginInput {
            action: "add".to_string(),
            data: serde_json::json!({"a": 10, "b": 5}),
            parameters: HashMap::new(),
        }
    ).await?;

    println!("Calculator result: {}", serde_json::to_string_pretty(&result)?);

    Ok(())
}
