//! Built-in policy functions
//!
//! This module provides built-in functions that can be used in HCL policies
//! for advanced access control and validation.

use chrono::{Datelike, Timelike, Utc};
use serde_json::Value;
use std::net::IpAddr;

use crate::error::{FortressError, Result};
use crate::policy_hcl::types::{ParameterType, PolicyContext, PolicyFunction};

/// Time function - returns current timestamp
pub struct TimeFunction;

impl PolicyFunction for TimeFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("time() function takes no arguments"));
        }

        let now = Utc::now();
        Ok(Value::Number(now.timestamp().into()))
    }

    fn name(&self) -> &str {
        "time"
    }

    fn description(&self) -> &str {
        "Returns current Unix timestamp"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Identity function - returns entity ID from token
pub struct IdentityFunction;

impl PolicyFunction for IdentityFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy(
                "identity() function takes no arguments",
            ));
        }

        Ok(Value::String(context.token.token.id.clone()))
    }

    fn name(&self) -> &str {
        "identity"
    }

    fn description(&self) -> &str {
        "Returns the entity ID from the token"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// IP function - returns client IP address
pub struct IpFunction;

impl PolicyFunction for IpFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("ip() function takes no arguments"));
        }

        let ip = context
            .ip_address
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        Ok(Value::String(ip))
    }

    fn name(&self) -> &str {
        "ip"
    }

    fn description(&self) -> &str {
        "Returns the client IP address"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Hour function - returns current hour (0-23)
pub struct HourFunction;

impl PolicyFunction for HourFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("hour() function takes no arguments"));
        }

        let hour = Utc::now().hour();
        Ok(Value::Number(hour.into()))
    }

    fn name(&self) -> &str {
        "hour"
    }

    fn description(&self) -> &str {
        "Returns the current hour (0-23)"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Day function - returns current day of week (0-6, 0 = Sunday)
pub struct DayFunction;

impl PolicyFunction for DayFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("day() function takes no arguments"));
        }

        let day = Utc::now().weekday().num_days_from_sunday();
        Ok(Value::Number(day.into()))
    }

    fn name(&self) -> &str {
        "day"
    }

    fn description(&self) -> &str {
        "Returns the current day of week (0-6, 0 = Sunday)"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Month function - returns current month (1-12)
pub struct MonthFunction;

impl PolicyFunction for MonthFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("month() function takes no arguments"));
        }

        let month = Utc::now().month();
        Ok(Value::Number(month.into()))
    }

    fn name(&self) -> &str {
        "month"
    }

    fn description(&self) -> &str {
        "Returns the current month (1-12)"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Year function - returns current year
pub struct YearFunction;

impl PolicyFunction for YearFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("year() function takes no arguments"));
        }

        let year = Utc::now().year();
        Ok(Value::Number(year.into()))
    }

    fn name(&self) -> &str {
        "year"
    }

    fn description(&self) -> &str {
        "Returns the current year"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Role function - checks if entity has specified role
pub struct RoleFunction;

impl PolicyFunction for RoleFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if args.len() != 1 {
            return Err(FortressError::policy(
                "role() function takes exactly one argument",
            ));
        }

        let role_name = match &args[0] {
            Value::String(s) => s,
            _ => return Err(FortressError::policy("role() argument must be a string")),
        };

        // For now, check if the role is in the token's policies
        // In a real implementation, this would query the role store
        let has_role = context
            .token
            .token
            .has_role(&crate::token::TokenRole::Custom(role_name.clone()));
        Ok(Value::Bool(has_role))
    }

    fn name(&self) -> &str {
        "role"
    }

    fn description(&self) -> &str {
        "Checks if the entity has the specified role"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String]
    }
}

/// Policy function - checks if token has specified policy
pub struct PolicyCheckFunction;

impl PolicyFunction for PolicyCheckFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if args.len() != 1 {
            return Err(FortressError::policy(
                "policy() function takes exactly one argument",
            ));
        }

        let policy_name = match &args[0] {
            Value::String(s) => s,
            _ => return Err(FortressError::policy("policy() argument must be a string")),
        };

        let has_policy = context.token.token.has_policy(policy_name);
        Ok(Value::Bool(has_policy))
    }

    fn name(&self) -> &str {
        "policy"
    }

    fn description(&self) -> &str {
        "Checks if the token has the specified policy"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String]
    }
}

/// Path function - returns the request path
pub struct PathFunction;

impl PolicyFunction for PathFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy("path() function takes no arguments"));
        }

        Ok(Value::String(context.path.clone()))
    }

    fn name(&self) -> &str {
        "path"
    }

    fn description(&self) -> &str {
        "Returns the request path"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Operation function - returns the request operation
pub struct OperationFunction;

impl PolicyFunction for OperationFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy(
                "operation() function takes no arguments",
            ));
        }

        Ok(Value::String(context.operation.clone()))
    }

    fn name(&self) -> &str {
        "operation"
    }

    fn description(&self) -> &str {
        "Returns the request operation"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Method function - returns the request method
pub struct MethodFunction;

impl PolicyFunction for MethodFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy(
                "method() function takes no arguments",
            ));
        }

        let method = context
            .method
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        Ok(Value::String(method))
    }

    fn name(&self) -> &str {
        "method"
    }

    fn description(&self) -> &str {
        "Returns the request method"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// UserAgent function - returns the user agent
pub struct UserAgentFunction;

impl PolicyFunction for UserAgentFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if !args.is_empty() {
            return Err(FortressError::policy(
                "useragent() function takes no arguments",
            ));
        }

        let user_agent = context
            .user_agent
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        Ok(Value::String(user_agent))
    }

    fn name(&self) -> &str {
        "useragent"
    }

    fn description(&self) -> &str {
        "Returns the user agent string"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![]
    }
}

/// Environment function - returns environment variable
pub struct EnvironmentFunction;

impl PolicyFunction for EnvironmentFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if args.len() != 1 {
            return Err(FortressError::policy(
                "environment() function takes exactly one argument",
            ));
        }

        let var_name = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "environment() argument must be a string",
                ))
            }
        };

        let value = context
            .get_environment(var_name)
            .cloned()
            .unwrap_or_else(|| "".to_string());
        Ok(Value::String(value))
    }

    fn name(&self) -> &str {
        "environment"
    }

    fn description(&self) -> &str {
        "Returns the value of an environment variable"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String]
    }
}

/// Header function - returns request header value
pub struct HeaderFunction;

impl PolicyFunction for HeaderFunction {
    fn evaluate(&self, args: &[Value], context: &PolicyContext) -> Result<Value> {
        if args.len() != 1 {
            return Err(FortressError::policy(
                "header() function takes exactly one argument",
            ));
        }

        let header_name = match &args[0] {
            Value::String(s) => s,
            _ => return Err(FortressError::policy("header() argument must be a string")),
        };

        let value = context
            .get_header(header_name)
            .cloned()
            .unwrap_or_else(|| "".to_string());
        Ok(Value::String(value))
    }

    fn name(&self) -> &str {
        "header"
    }

    fn description(&self) -> &str {
        "Returns the value of a request header"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String]
    }
}

/// IsPrivateIP function - checks if IP address is private
pub struct IsPrivateIPFunction;

impl PolicyFunction for IsPrivateIPFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if args.len() != 1 {
            return Err(FortressError::policy(
                "is_private_ip() function takes exactly one argument",
            ));
        }

        let ip_str = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "is_private_ip() argument must be a string",
                ))
            }
        };

        let is_private = match ip_str.parse::<IpAddr>() {
            Ok(ip) => is_private_ip(ip),
            Err(_) => false,
        };

        Ok(Value::Bool(is_private))
    }

    fn name(&self) -> &str {
        "is_private_ip"
    }

    fn description(&self) -> &str {
        "Checks if an IP address is in a private range"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String]
    }
}

/// Helper function to check if an IP address is private
fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local(),
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unicast_link_local() || (ipv6.segments()[0] == 0xfc00)
            // Unique local address
        }
    }
}

/// Contains function - checks if a string contains another
pub struct ContainsFunction;

impl PolicyFunction for ContainsFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if args.len() != 2 {
            return Err(FortressError::policy(
                "contains() function takes exactly two arguments",
            ));
        }

        let haystack = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "contains() first argument must be a string",
                ))
            }
        };

        let needle = match &args[1] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "contains() second argument must be a string",
                ))
            }
        };

        let contains = haystack.contains(needle);
        Ok(Value::Bool(contains))
    }

    fn name(&self) -> &str {
        "contains"
    }

    fn description(&self) -> &str {
        "Checks if a string contains another string"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String, ParameterType::String]
    }
}

/// StartsWith function - checks if a string starts with another
pub struct StartsWithFunction;

impl PolicyFunction for StartsWithFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if args.len() != 2 {
            return Err(FortressError::policy(
                "starts_with() function takes exactly two arguments",
            ));
        }

        let haystack = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "starts_with() first argument must be a string",
                ))
            }
        };

        let needle = match &args[1] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "starts_with() second argument must be a string",
                ))
            }
        };

        let starts_with = haystack.starts_with(needle);
        Ok(Value::Bool(starts_with))
    }

    fn name(&self) -> &str {
        "starts_with"
    }

    fn description(&self) -> &str {
        "Checks if a string starts with another string"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String, ParameterType::String]
    }
}

/// EndsWith function - checks if a string ends with another
pub struct EndsWithFunction;

impl PolicyFunction for EndsWithFunction {
    fn evaluate(&self, args: &[Value], _context: &PolicyContext) -> Result<Value> {
        if args.len() != 2 {
            return Err(FortressError::policy(
                "ends_with() function takes exactly two arguments",
            ));
        }

        let haystack = match &args[0] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "ends_with() first argument must be a string",
                ))
            }
        };

        let needle = match &args[1] {
            Value::String(s) => s,
            _ => {
                return Err(FortressError::policy(
                    "ends_with() second argument must be a string",
                ))
            }
        };

        let ends_with = haystack.ends_with(needle);
        Ok(Value::Bool(ends_with))
    }

    fn name(&self) -> &str {
        "ends_with"
    }

    fn description(&self) -> &str {
        "Checks if a string ends with another string"
    }

    fn parameter_types(&self) -> Vec<ParameterType> {
        vec![ParameterType::String, ParameterType::String]
    }
}

/// Register all built-in functions
pub fn register_builtin_functions(
) -> std::collections::HashMap<String, Box<dyn crate::policy_hcl::types::PolicyFunction>> {
    let mut registry: std::collections::HashMap<
        String,
        Box<dyn crate::policy_hcl::types::PolicyFunction>,
    > = std::collections::HashMap::new();

    // Time and date functions
    registry.insert("time".to_string(), Box::new(TimeFunction));
    registry.insert("hour".to_string(), Box::new(HourFunction));
    registry.insert("day".to_string(), Box::new(DayFunction));
    registry.insert("month".to_string(), Box::new(MonthFunction));
    registry.insert("year".to_string(), Box::new(YearFunction));

    // Identity and access functions
    registry.insert("identity".to_string(), Box::new(IdentityFunction));
    registry.insert("ip".to_string(), Box::new(IpFunction));
    registry.insert("role".to_string(), Box::new(RoleFunction));
    registry.insert("policy".to_string(), Box::new(PolicyCheckFunction));

    // Request context functions
    registry.insert("path".to_string(), Box::new(PathFunction));
    registry.insert("operation".to_string(), Box::new(OperationFunction));
    registry.insert("method".to_string(), Box::new(MethodFunction));
    registry.insert("useragent".to_string(), Box::new(UserAgentFunction));
    registry.insert("environment".to_string(), Box::new(EnvironmentFunction));
    registry.insert("header".to_string(), Box::new(HeaderFunction));

    // Utility functions
    registry.insert("is_private_ip".to_string(), Box::new(IsPrivateIPFunction));
    registry.insert("contains".to_string(), Box::new(ContainsFunction));
    registry.insert("starts_with".to_string(), Box::new(StartsWithFunction));
    registry.insert("ends_with".to_string(), Box::new(EndsWithFunction));

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::{TokenRole, TokenType};

    fn create_test_context() -> PolicyContext {
        let token = crate::token::Token::new(
            TokenType::User,
            TokenRole::Admin,
            vec!["default".to_string()],
            chrono::Duration::hours(1),
            "user123".to_string(),
        );

        let token_info = crate::token::TokenInfo {
            token: token.clone(),
            display_name: "Test Token".to_string(),
            description: None,
            usage_stats: Default::default(),
            creation_context: Default::default(),
        };

        let mut context =
            PolicyContext::new(token_info, "secret/data".to_string(), "read".to_string());
        context.ip_address = Some("192.168.1.1".to_string());
        context.user_agent = Some("Mozilla/5.0".to_string());
        context.add_environment("ENV".to_string(), "production".to_string());
        context.add_header("X-Request-ID".to_string(), "req-123".to_string());

        context
    }

    #[test]
    fn test_time_function() {
        let func = TimeFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::Number(timestamp) = result {
            assert!(timestamp.as_i64().unwrap() > 0);
        } else {
            panic!("Expected number result");
        }
    }

    #[test]
    fn test_identity_function() {
        let func = IdentityFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::String(entity_id) = result {
            assert_eq!(entity_id, "user123");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_ip_function() {
        let func = IpFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::String(ip) = result {
            assert_eq!(ip, "192.168.1.1");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_hour_function() {
        let func = HourFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::Number(hour) = result {
            let hour_val = hour.as_i64().unwrap();
            assert!(hour_val >= 0 && hour_val <= 23);
        } else {
            panic!("Expected number result");
        }
    }

    #[test]
    fn test_role_function() {
        let func = RoleFunction;
        let context = create_test_context();

        // Test with existing role
        let result = func
            .evaluate(&[Value::String("admin".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with non-existing role
        let result = func
            .evaluate(&[Value::String("auditor".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_policy_function() {
        let func = super::RoleFunction;
        let context = create_test_context();

        // Test with existing policy
        let result = func
            .evaluate(&[Value::String("admin".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with non-existing policy
        let result = func
            .evaluate(&[Value::String("restricted".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_path_function() {
        let func = PathFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::String(path) = result {
            assert_eq!(path, "secret/data");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_operation_function() {
        let func = OperationFunction;
        let context = create_test_context();

        let result = func.evaluate(&[], &context).unwrap();
        if let Value::String(operation) = result {
            assert_eq!(operation, "read");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_environment_function() {
        let func = EnvironmentFunction;
        let context = create_test_context();

        // Test with existing environment variable
        let result = func
            .evaluate(&[Value::String("ENV".to_string())], &context)
            .unwrap();
        if let Value::String(value) = result {
            assert_eq!(value, "production");
        } else {
            panic!("Expected string result");
        }

        // Test with non-existing environment variable
        let result = func
            .evaluate(&[Value::String("NONEXISTENT".to_string())], &context)
            .unwrap();
        if let Value::String(value) = result {
            assert_eq!(value, "");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_header_function() {
        let func = HeaderFunction;
        let context = create_test_context();

        // Test with existing header
        let result = func
            .evaluate(&[Value::String("X-Request-ID".to_string())], &context)
            .unwrap();
        if let Value::String(value) = result {
            assert_eq!(value, "req-123");
        } else {
            panic!("Expected string result");
        }

        // Test with non-existing header
        let result = func
            .evaluate(&[Value::String("X-Nonexistent".to_string())], &context)
            .unwrap();
        if let Value::String(value) = result {
            assert_eq!(value, "");
        } else {
            panic!("Expected string result");
        }
    }

    #[test]
    fn test_is_private_ip_function() {
        let func = IsPrivateIPFunction;
        let context = create_test_context();

        // Test with private IP
        let result = func
            .evaluate(&[Value::String("192.168.1.1".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with public IP
        let result = func
            .evaluate(&[Value::String("8.8.8.8".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(false));

        // Test with invalid IP
        let result = func
            .evaluate(&[Value::String("invalid".to_string())], &context)
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_contains_function() {
        let func = ContainsFunction;
        let context = create_test_context();

        // Test with contained string
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("world".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with non-contained string
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("universe".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_starts_with_function() {
        let func = StartsWithFunction;
        let context = create_test_context();

        // Test with matching prefix
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("hello".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with non-matching prefix
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("world".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_ends_with_function() {
        let func = EndsWithFunction;
        let context = create_test_context();

        // Test with matching suffix
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("world".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(true));

        // Test with non-matching suffix
        let result = func
            .evaluate(
                &[
                    Value::String("hello world".to_string()),
                    Value::String("hello".to_string()),
                ],
                &context,
            )
            .unwrap();
        assert_eq!(result, Value::Bool(false));
    }

    #[test]
    fn test_function_parameter_validation() {
        let func = TimeFunction;
        let context = create_test_context();

        // Test with too many arguments
        let result = func.evaluate(&[Value::String("test".to_string())], &context);
        assert!(result.is_err());

        // Test with string argument for time function
        let func = RoleFunction;
        let result = func.evaluate(&[Value::Number(serde_json::Number::from(42))], &context);
        assert!(result.is_err());
    }

    #[test]
    fn test_register_builtin_functions() {
        let registry = register_builtin_functions();

        // Check that all expected functions are registered
        let expected_functions = vec![
            "time",
            "hour",
            "day",
            "month",
            "year",
            "identity",
            "ip",
            "role",
            "policy",
            "path",
            "operation",
            "method",
            "useragent",
            "environment",
            "header",
            "is_private_ip",
            "contains",
            "starts_with",
            "ends_with",
        ];

        for func_name in expected_functions {
            assert!(
                registry.contains_key(func_name),
                "Missing function: {}",
                func_name
            );
        }

        // Check that registered functions have correct names
        for (name, func) in registry.iter() {
            assert_eq!(name, func.name());
        }
    }
}
