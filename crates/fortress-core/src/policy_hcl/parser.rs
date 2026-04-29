//! HCL policy parser
//!
//! This module provides functionality to parse HCL (HashiCorp Configuration Language)
//! policy files and convert them into structured ParsedPolicy objects.

use std::collections::HashMap;
use serde_json::Value;
use regex::Regex;

use crate::error::{FortressError, Result};
use super::types::{
    ParsedPolicy, PolicyConstraint, ConstraintOperator, ParameterType,
    PolicyCompilationError, PolicyErrorType, PolicyValidationResult,
};

/// HCL policy parser
pub struct HclPolicyParser {
    /// Cache of compiled regex patterns
    regex_cache: HashMap<String, Regex>,
}

impl HclPolicyParser {
    /// Create a new HCL policy parser
    pub fn new() -> Self {
        Self {
            regex_cache: HashMap::new(),
        }
    }

    /// Parse HCL policy string
    pub fn parse(&mut self, hcl_content: &str) -> Result<ParsedPolicy> {
        let mut policy = ParsedPolicy::new(
            "unnamed".to_string(),
            "*".to_string(),
        );

        // Parse HCL content line by line
        let lines: Vec<&str> = hcl_content.lines().collect();
        let mut current_block = String::new();
        let mut in_block = false;

        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // Check for block start/end
            if trimmed.ends_with('{') {
                current_block = trimmed.trim_end_matches('{').trim().to_string();
                in_block = true;
                continue;
            }

            if trimmed == "}" && in_block {
                in_block = false;
                current_block.clear();
                continue;
            }

            // Parse based on current block
            if in_block {
                self.parse_block_content(&mut policy, &current_block, trimmed, line_num + 1)?;
            } else {
                self.parse_top_level(&mut policy, trimmed, line_num + 1)?;
            }
        }

        // Validate the parsed policy
        self.validate_policy(&policy)?;

        Ok(policy)
    }

    /// Parse top-level policy attributes
    fn parse_top_level(&mut self, policy: &mut ParsedPolicy, line: &str, line_num: usize) -> Result<()> {
        if let Some((key, value)) = self.split_assignment(line) {
            match key.trim() {
                "name" => {
                    policy.name = self.parse_string_value(value)?;
                }
                "path" => {
                    policy.path = self.parse_string_value(value)?;
                }
                "capabilities" => {
                    policy.capabilities = self.parse_string_array(value)?;
                }
                "min_ttl" => {
                    policy.min_ttl = Some(self.parse_duration_value(value)?);
                }
                "max_ttl" => {
                    policy.max_ttl = Some(self.parse_duration_value(value)?);
                }
                _ => {
                    // Add to metadata
                    policy.metadata.insert(key.to_string(), value.to_string());
                }
            }
        } else {
            return Err(FortressError::policy(format!(
                "Invalid top-level assignment at line {}: {}",
                line_num, line
            )));
        }

        Ok(())
    }

    /// Parse block content
    fn parse_block_content(&mut self, policy: &mut ParsedPolicy, block_name: &str, line: &str, line_num: usize) -> Result<()> {
        match block_name {
            "parameters" => {
                self.parse_parameters_block(policy, line, line_num)?;
            }
            "constraints" => {
                self.parse_constraints_block(policy, line, line_num)?;
            }
            _ => {
                // Unknown block, add to metadata
                policy.metadata.insert(format!("{}:{}", block_name, line_num), line.to_string());
            }
        }

        Ok(())
    }

    /// Parse parameters block
    fn parse_parameters_block(&mut self, policy: &mut ParsedPolicy, line: &str, line_num: usize) -> Result<()> {
        if let Some((param_name, param_def)) = self.split_assignment(line) {
            let parts: Vec<&str> = param_def.split_whitespace().collect();
            
            if parts.is_empty() {
                return Err(FortressError::policy(format!(
                    "Invalid parameter definition at line {}: {}",
                    line_num, line
                )));
            }

            // Parse parameter type
            let param_type = match parts[0] {
                "string" => ParameterType::String,
                "number" => ParameterType::Number,
                "boolean" => ParameterType::Boolean,
                "array" => ParameterType::Array,
                "object" => ParameterType::Object,
                "time" => ParameterType::Time,
                "duration" => ParameterType::Duration,
                _ => {
                    return Err(FortressError::policy(format!(
                        "Unknown parameter type '{}' at line {}",
                        parts[0], line_num
                    )));
                }
            };

            // Check if parameter is required
            let is_required = parts.iter().any(|&part| part == "required");

            if is_required {
                policy.required_parameters.insert(param_name.to_string(), param_type);
            }

            // Parse allowed values if present
            if let Some(allowed_start) = param_def.find('[') {
                if let Some(allowed_end) = param_def.find(']') {
                    let allowed_str = &param_def[allowed_start + 1..allowed_end];
                    let allowed_values = self.parse_string_array(allowed_str)?;
                    policy.allowed_parameters.insert(param_name.to_string(), allowed_values);
                }
            }
        }

        Ok(())
    }

    /// Parse constraints block
    fn parse_constraints_block(&mut self, policy: &mut ParsedPolicy, line: &str, line_num: usize) -> Result<()> {
        if let Some((field, constraint_def)) = self.split_assignment(line) {
            let parts: Vec<&str> = constraint_def.split_whitespace().collect();
            
            if parts.len() < 2 {
                return Err(FortressError::policy(format!(
                    "Invalid constraint definition at line {}: {}",
                    line_num, line
                )));
            }

            let operator = match parts[0] {
                "==" => ConstraintOperator::Equals,
                "!=" => ConstraintOperator::NotEquals,
                "contains" => ConstraintOperator::Contains,
                "!contains" => ConstraintOperator::NotContains,
                ">" => ConstraintOperator::GreaterThan,
                "<" => ConstraintOperator::LessThan,
                ">=" => ConstraintOperator::GreaterThanOrEqual,
                "<=" => ConstraintOperator::LessThanOrEqual,
                "in" => ConstraintOperator::In,
                "!in" => ConstraintOperator::NotIn,
                "matches" => ConstraintOperator::Matches,
                "!matches" => ConstraintOperator::NotMatches,
                "starts_with" => ConstraintOperator::StartsWith,
                "ends_with" => ConstraintOperator::EndsWith,
                _ => {
                    return Err(FortressError::policy(format!(
                        "Unknown constraint operator '{}' at line {}",
                        parts[0], line_num
                    )));
                }
            };

            // Parse constraint value
            let value_str = parts[1..].join(" ");
            let value = self.parse_constraint_value(&value_str, &operator)?;

            let constraint = PolicyConstraint {
                field: field.to_string(),
                operator,
                value,
                description: None,
            };

            policy.add_constraint(constraint);
        }

        Ok(())
    }

    /// Split assignment into key and value
    fn split_assignment<'a>(&self, line: &'a str) -> Option<(&'a str, &'a str)> {
        if let Some(eq_pos) = line.find('=') {
            let key = &line[..eq_pos].trim();
            let value = &line[eq_pos + 1..].trim();
            Some((key, value))
        } else {
            None
        }
    }

    /// Parse string value
    fn parse_string_value(&self, value: &str) -> Result<String> {
        let value = value.trim();
        
        if value.starts_with('"') && value.ends_with('"') {
            Ok(value[1..value.len() - 1].to_string())
        } else if value.starts_with('\'') && value.ends_with('\'') {
            Ok(value[1..value.len() - 1].to_string())
        } else {
            Ok(value.to_string())
        }
    }

    /// Parse string array
    fn parse_string_array(&self, value: &str) -> Result<Vec<String>> {
        let value = value.trim();
        
        if value.starts_with('[') && value.ends_with(']') {
            let inner = &value[1..value.len() - 1].trim();
            
            if inner.is_empty() {
                return Ok(Vec::new());
            }

            let elements: Vec<&str> = inner.split(',').collect();
            let mut result = Vec::new();

            for element in elements {
                let element = element.trim();
                if !element.is_empty() {
                    result.push(self.parse_string_value(element)?);
                }
            }

            Ok(result)
        } else {
            // Single value, treat as single-element array
            Ok(vec![self.parse_string_value(value)?])
        }
    }

    /// Parse duration value (in seconds)
    fn parse_duration_value(&self, value: &str) -> Result<i64> {
        let value = value.trim();
        
        // Remove quotes if present
        let value = if value.starts_with('"') && value.ends_with('"') {
            &value[1..value.len() - 1]
        } else {
            value
        };

        // Parse duration format (e.g., "1h", "30m", "3600s")
        let num_part: String = value.chars().take_while(|c| c.is_numeric() || *c == '-').collect();
        if num_part.parse::<i64>().is_ok() {
            if let Some(time_unit) = value.chars().skip(num_part.len()).next() {
                let num: i64 = num_part.parse()
                    .map_err(|_| FortressError::policy(format!("Invalid duration number: {}", num_part)))?;

                let seconds = match time_unit {
                    's' => num,
                    'm' => num * 60,
                    'h' => num * 3600,
                    'd' => num * 86400,
                    _ => {
                        // Assume it's already in seconds
                        value.parse()
                            .map_err(|_| FortressError::policy(format!("Invalid duration: {}", value)))?
                    }
                };

                return Ok(seconds);
            }
        }

        // Try to parse as plain number of seconds
        value.parse()
            .map_err(|_| FortressError::policy(format!("Invalid duration format: {}", value)))
    }

    /// Parse constraint value
    fn parse_constraint_value(&self, value_str: &str, operator: &ConstraintOperator) -> Result<Value> {
        let value_str = value_str.trim();

        match operator {
            ConstraintOperator::In | ConstraintOperator::NotIn => {
                // Parse as array
                let values = self.parse_string_array(value_str)?;
                Ok(Value::Array(values.into_iter().map(Value::String).collect()))
            }
            ConstraintOperator::Matches | ConstraintOperator::NotMatches => {
                // Parse as regex string
                let regex_str = self.parse_string_value(value_str)?;
                Ok(Value::String(regex_str))
            }
            _ => {
                // Try to parse as different types
                if value_str.starts_with('"') || value_str.starts_with('\'') {
                    // String value
                    Ok(Value::String(self.parse_string_value(value_str)?))
                } else if value_str == "true" || value_str == "false" {
                    // Boolean value
                    Ok(Value::Bool(value_str == "true"))
                } else if value_str.contains('.') || value_str.parse::<i64>().is_ok() {
                    // Number value
                    if let Ok(int_val) = value_str.parse::<i64>() {
                        Ok(Value::Number(int_val.into()))
                    } else if let Ok(float_val) = value_str.parse::<f64>() {
                        Ok(Value::Number(serde_json::Number::from_f64(float_val).unwrap()))
                    } else {
                        Err(FortressError::policy(format!("Invalid number: {}", value_str)))
                    }
                } else {
                    // Default to string
                    Ok(Value::String(value_str.to_string()))
                }
            }
        }
    }

    /// Validate parsed policy
    fn validate_policy(&self, policy: &ParsedPolicy) -> Result<()> {
        let mut errors = Vec::new();

        // Check required fields
        if policy.name.is_empty() {
            errors.push(PolicyCompilationError {
                message: "Policy name is required".to_string(),
                line: None,
                column: None,
                error_type: PolicyErrorType::Semantic,
            });
        }

        if policy.path.is_empty() {
            errors.push(PolicyCompilationError {
                message: "Policy path is required".to_string(),
                line: None,
                column: None,
                error_type: PolicyErrorType::Semantic,
            });
        }

        // Validate path pattern
        if !self.is_valid_path_pattern(&policy.path) {
            errors.push(PolicyCompilationError {
                message: format!("Invalid path pattern: {}", policy.path),
                line: None,
                column: None,
                error_type: PolicyErrorType::Semantic,
            });
        }

        // Validate TTL values
        if let (Some(min_ttl), Some(max_ttl)) = (policy.min_ttl, policy.max_ttl) {
            if min_ttl > max_ttl {
                errors.push(PolicyCompilationError {
                    message: "min_ttl cannot be greater than max_ttl".to_string(),
                    line: None,
                    column: None,
                    error_type: PolicyErrorType::Semantic,
                });
            }
        }

        // Validate constraints
        for constraint in &policy.constraints {
            if self.validate_constraint(constraint).is_err() {
                errors.push(PolicyCompilationError {
                    message: format!("Invalid constraint: {}", constraint.field),
                    line: None,
                    column: None,
                    error_type: PolicyErrorType::Semantic,
                });
            }
        }

        if !errors.is_empty() {
            return Err(FortressError::policy(format!(
                "Policy validation failed: {} errors",
                errors.len()
            )));
        }

        Ok(())
    }

    /// Check if path pattern is valid
    fn is_valid_path_pattern(&self, path: &str) -> bool {
        if path == "*" {
            return true;
        }

        // Basic validation - could be enhanced with proper regex
        !path.is_empty() && !path.contains("..")
    }

    /// Validate individual constraint
    fn validate_constraint(&self, constraint: &PolicyConstraint) -> Result<()> {
        // Check if field name is valid
        if constraint.field.is_empty() {
            return Err(FortressError::policy("Constraint field cannot be empty"));
        }

        // Check if value is appropriate for operator
        match constraint.operator {
            ConstraintOperator::In | ConstraintOperator::NotIn => {
                if !constraint.value.is_array() {
                    return Err(FortressError::policy("In/NotIn operators require array values"));
                }
            }
            ConstraintOperator::Matches | ConstraintOperator::NotMatches => {
                if !constraint.value.is_string() {
                    return Err(FortressError::policy("Matches operators require string values"));
                }
                
                // Test if regex is valid
                if let Value::String(regex_str) = &constraint.value {
                    Regex::new(regex_str).map_err(|_| {
                        FortressError::policy(format!("Invalid regex: {}", regex_str))
                    })?;
                }
            }
            _ => {
                // Other operators accept most value types
            }
        }

        Ok(())
    }

    /// Validate policy syntax
    pub fn validate_syntax(&self, hcl_content: &str) -> PolicyValidationResult {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();
        let mut brace_count = 0;

        let lines: Vec<&str> = hcl_content.lines().collect();
        
        for (line_num, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            
            // Skip comments and empty lines
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
                continue;
            }

            // Check for balanced braces
            if trimmed.ends_with('{') {
                brace_count += 1;
            } else if trimmed == "}" {
                brace_count -= 1;
                if brace_count < 0 {
                    errors.push(PolicyCompilationError {
                        message: "Unmatched closing brace".to_string(),
                        line: Some(line_num as u32 + 1),
                        column: Some(1),
                        error_type: PolicyErrorType::Syntax,
                    });
                }
            }

            // Check for basic syntax errors
            if !trimmed.contains('=') && !trimmed.ends_with('{') && trimmed != "}" {
                if !trimmed.starts_with('#') && !trimmed.starts_with("//") {
                    warnings.push(format!("Line {} may contain invalid syntax: {}", line_num + 1, line));
                }
            }
        }

        if brace_count != 0 {
            errors.push(PolicyCompilationError {
                message: format!("Unmatched opening braces: {}", brace_count),
                line: None,
                column: None,
                error_type: PolicyErrorType::Syntax,
            });
        }

        if errors.is_empty() {
            PolicyValidationResult::valid()
        } else {
            PolicyValidationResult::invalid(errors)
        }
    }
}

impl Default for HclPolicyParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_parse_simple_policy() {
        let mut parser = HclPolicyParser::new();
        let hcl_content = r#"
name = "test-policy"
path = "secret/*"
capabilities = ["read", "list"]
min_ttl = 3600
max_ttl = 86400
"#;

        let policy = parser.parse(hcl_content).unwrap();
        
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.path, "secret/*");
        assert_eq!(policy.capabilities, vec!["read", "list"]);
        assert_eq!(policy.min_ttl, Some(3600));
        assert_eq!(policy.max_ttl, Some(86400));
    }

    #[test]
    fn test_parse_policy_with_parameters() {
        let mut parser = HclPolicyParser::new();
        let hcl_content = r#"
name = "test-policy"
path = "secret/*"

parameters {
    key = string required ["key1", "key2", "key3"]
    ttl = duration required
    optional_param = number
}
"#;

        let policy = parser.parse(hcl_content).unwrap();
        
        assert!(policy.required_parameters.contains_key("key"));
        assert!(policy.required_parameters.contains_key("ttl"));
        assert!(!policy.required_parameters.contains_key("optional_param"));
        
        assert!(policy.allowed_parameters.contains_key("key"));
        let allowed_keys = policy.allowed_parameters.get("key").unwrap();
        assert_eq!(allowed_keys, &vec!["key1", "key2", "key3"]);
    }

    #[test]
    fn test_parse_policy_with_constraints() {
        let mut parser = HclPolicyParser::new();
        let hcl_content = r#"
name = "test-policy"
path = "secret/*"

constraints {
    ip_address == "192.168.1.1"
    hour >= 9
    hour <= 17
    user_agent matches "Mozilla.*"
    environment in ["production", "staging"]
}
"#;

        let policy = parser.parse(hcl_content).unwrap();
        
        assert_eq!(policy.constraints.len(), 5);
        
        // Check specific constraints
        let ip_constraint = policy.constraints.iter()
            .find(|c| c.field == "ip_address")
            .unwrap();
        assert_eq!(ip_constraint.operator, ConstraintOperator::Equals);
        
        let hour_constraint = policy.constraints.iter()
            .find(|c| c.field == "hour")
            .unwrap();
        assert_eq!(hour_constraint.operator, ConstraintOperator::GreaterThanOrEqual);
    }

    #[test]
    fn test_parse_duration_values() {
        let mut parser = HclPolicyParser::new();
        
        assert_eq!(parser.parse_duration_value("3600").unwrap(), 3600);
        assert_eq!(parser.parse_duration_value("1h").unwrap(), 3600);
        assert_eq!(parser.parse_duration_value("30m").unwrap(), 1800);
        assert_eq!(parser.parse_duration_value("2d").unwrap(), 172800);
        assert_eq!(parser.parse_duration_value("\"1h\"").unwrap(), 3600);
    }

    #[test]
    fn test_parse_string_arrays() {
        let mut parser = HclPolicyParser::new();
        
        let array = parser.parse_string_array("[\"read\", \"write\", \"list\"]").unwrap();
        assert_eq!(array, vec!["read", "write", "list"]);
        
        let single = parser.parse_string_array("\"read\"").unwrap();
        assert_eq!(single, vec!["read"]);
        
        let empty = parser.parse_string_array("[]").unwrap();
        assert_eq!(empty, Vec::<String>::new());
    }

    #[test]
    fn test_validate_syntax() {
        let parser = HclPolicyParser::new();
        
        let valid_hcl = r#"
name = "test"
path = "secret/*"
"#;
        
        let result = parser.validate_syntax(valid_hcl);
        assert!(result.valid);
        assert!(result.errors.is_empty());
        
        let invalid_hcl = r#"
name = "test"
path = "secret/*"
{
"#;
        
        let result = parser.validate_syntax(invalid_hcl);
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }

    #[test]
    fn test_path_matching() {
        let policy = ParsedPolicy::new("test".to_string(), "secret/*".to_string());
        
        assert!(policy.matches_path("secret/data"));
        assert!(policy.matches_path("secret/metadata"));
        assert!(!policy.matches_path("public/data"));
        
        let wildcard_policy = ParsedPolicy::new("test".to_string(), "*".to_string());
        assert!(wildcard_policy.matches_path("any/path"));
        
        let exact_policy = ParsedPolicy::new("test".to_string(), "secret/data".to_string());
        assert!(exact_policy.matches_path("secret/data"));
        assert!(!exact_policy.matches_path("secret/metadata"));
    }

    #[test]
    fn test_constraint_operators() {
        let mut parser = HclPolicyParser::new();
        
        // Test string constraint
        let result = parser.parse_constraint_value("\"test\"", &ConstraintOperator::Equals).unwrap();
        assert_eq!(result, Value::String("test".to_string()));
        
        // Test boolean constraint
        let result = parser.parse_constraint_value("true", &ConstraintOperator::Equals).unwrap();
        assert_eq!(result, Value::Bool(true));
        
        // Test number constraint
        let result = parser.parse_constraint_value("42", &ConstraintOperator::Equals).unwrap();
        assert_eq!(result, Value::Number(42.into()));
        
        // Test array constraint
        let result = parser.parse_constraint_value("[\"a\", \"b\"]", &ConstraintOperator::In).unwrap();
        assert_eq!(result, Value::Array(vec![Value::String("a".to_string()), Value::String("b".to_string())]));
    }

    #[test]
    fn test_policy_validation() {
        let mut parser = HclPolicyParser::new();
        
        // Valid policy
        let valid_policy = ParsedPolicy::new("test".to_string(), "secret/*".to_string());
        assert!(parser.validate_policy(&valid_policy).is_ok());
        
        // Invalid policy (empty name)
        let invalid_policy = ParsedPolicy::new("".to_string(), "secret/*".to_string());
        assert!(parser.validate_policy(&invalid_policy).is_err());
        
        // Invalid policy (empty path)
        let invalid_policy = ParsedPolicy::new("test".to_string(), "".to_string());
        assert!(parser.validate_policy(&invalid_policy).is_err());
    }

    #[test]
    fn test_complex_policy() {
        let mut parser = HclPolicyParser::new();
        let hcl_content = r#"
name = "complex-policy"
path = "secret/data/*"

capabilities = ["read", "write", "delete", "list"]

min_ttl = 300
max_ttl = 7200

parameters {
    environment = string required ["production", "staging", "development"]
    data_type = string required
    ttl = duration
}

constraints {
    ip_address == "192.168.1.0/24"
    hour >= 8
    hour <= 18
    day >= 1
    day <= 5
    user_agent matches "Mozilla/5.0.*"
    environment in ["production", "staging"]
    data_type contains "sensitive"
}

metadata {
    description = "Complex policy for sensitive data"
    version = "1.0"
    owner = "security-team"
}
"#;

        let policy = parser.parse(hcl_content).unwrap();
        
        assert_eq!(policy.name, "complex-policy");
        assert_eq!(policy.path, "secret/data/*");
        assert_eq!(policy.capabilities, vec!["read", "write", "delete", "list"]);
        assert_eq!(policy.min_ttl, Some(300));
        assert_eq!(policy.max_ttl, Some(7200));
        assert_eq!(policy.required_parameters.len(), 2);
        assert_eq!(policy.constraints.len(), 7);
        
        // Check metadata
        assert_eq!(policy.metadata.get("description"), Some(&"Complex policy for sensitive data".to_string()));
        assert_eq!(policy.metadata.get("version"), Some(&"1.0".to_string()));
    }
}
