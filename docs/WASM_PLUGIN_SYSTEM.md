# WebAssembly Plugin System

Fortress features a comprehensive WebAssembly (WASM) plugin system that makes it the most extensible security platform in its class. The WASM plugin system allows developers to create custom policy evaluators and authentication providers that run in a secure, sandboxed environment.

## Overview

The WASM plugin system provides:

- **Custom Policy Evaluators**: Implement sophisticated access control logic beyond standard RBAC/ABAC
- **Custom Authentication Providers**: Support for any authentication method including biometrics, hardware tokens, and custom protocols
- **Secure Sandboxing**: All plugins run in isolated WASM environments with strict security controls
- **High Performance**: Near-native execution speed with minimal overhead
- **Hot-Reloading**: Update plugins without restarting Fortress
- **Multi-Language Support**: Write plugins in Rust, C++, AssemblyScript, or any WASM-compatible language

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Fortress Core                           │
├─────────────────────────────────────────────────────────────┤
│  WASM Plugin Manager                                        │
│  ├── Policy Evaluator Registry                              │
│  ├── Auth Provider Registry                                 │
│  └── Plugin Loader & Manager                               │
├─────────────────────────────────────────────────────────────┤
│  WASM Runtime                                               │
│  ├── Host Functions (fortress_*)                            │
│  ├── Memory Management                                      │
│  ├── Security Controls                                      │
│  └── Performance Monitoring                                 │
├─────────────────────────────────────────────────────────────┤
│  WASM Plugins                                               │
│  ├── Policy Evaluators                                      │
│  ├── Authentication Providers                              │
│  ├── Encryption Providers                                   │
│  └── Storage Providers                                      │
└─────────────────────────────────────────────────────────────┘
```

## Policy Evaluators

### Features

- **RBAC + ABAC**: Combine role-based and attribute-based access control
- **Time-Based Access**: Restrict access based on business hours or custom schedules
- **Geolocation Rules**: Allow/deny access based on geographic location
- **Threat Intelligence Integration**: Automatically adjust policies based on threat data
- **Resource-Specific Rules**: Fine-grained control over individual resources
- **Policy Caching**: Intelligent caching for high-performance evaluation

### Example Policy Evaluation

```rust
use fortress::{WasmPluginManager, PolicyContext, PolicyResult};

// Create policy context
let context = PolicyContext {
    request_id: "req-123".to_string(),
    user: UserContext {
        user_id: "alice".to_string(),
        roles: vec!["developer".to_string()],
        attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("department".to_string(), serde_json::Value::String("engineering".to_string()));
            attrs.insert("clearance".to_string(), serde_json::Value::String("confidential".to_string()));
            attrs
        },
        auth_method: "mfa".to_string(),
        session_id: Some("sess-456".to_string()),
        clearance_level: Some("confidential".to_string()),
    },
    resource: ResourceContext {
        resource_id: "doc-789".to_string(),
        resource_type: "document".to_string(),
        attributes: {
            let mut attrs = HashMap::new();
            attrs.insert("classification".to_string(), serde_json::Value::String("confidential".to_string()));
            attrs.insert("project".to_string(), serde_json::Value::String("secret-project".to_string()));
            attrs
        },
        owner: Some("bob".to_string()),
        classification: Some("confidential".to_string()),
        tags: vec!["engineering".to_string(), "confidential".to_string()],
    },
    action: "read".to_string(),
    request: RequestContext {
        source_ip: "192.168.1.100".to_string(),
        user_agent: Some("Mozilla/5.0".to_string()),
        headers: HashMap::new(),
        parameters: HashMap::new(),
        method: "GET".to_string(),
        path: "/api/documents/789".to_string(),
    },
    environment: EnvironmentContext {
        current_time: chrono::Utc::now(),
        timezone: "UTC".to_string(),
        geolocation: Some(GeoLocation {
            country: "US".to_string(),
            region: Some("CA".to_string()),
            city: Some("San Francisco".to_string()),
            latitude: Some(37.7749),
            longitude: Some(-122.4194),
        }),
        device: Some(DeviceContext {
            device_type: "desktop".to_string(),
            os: "Windows".to_string(),
            browser: Some("Chrome".to_string()),
            fingerprint: Some("fp-abc123".to_string()),
            trusted: true,
        }),
        network: NetworkContext {
            network_type: "corporate".to_string(),
            security_level: "high".to_string(),
            vpn_info: None,
        },
        threat_intelligence: ThreatIntelligence {
            ip_reputation_score: 95.0,
            malicious_indicators: vec![],
            risk_level: "low".to_string(),
            last_updated: chrono::Utc::now(),
        },
    },
    timestamp: chrono::Utc::now(),
};

// Evaluate policy
let manager = WasmPluginManager::default();
let result = manager.evaluate_policy("custom-rbac", context).await?;

match result.allow {
    true => println!("Access granted: {}", result.reason),
    false => println!("Access denied: {}", result.reason),
}
```

## Authentication Providers

### Features

- **Multi-Factor Authentication**: Support for TOTP, SMS, email, hardware tokens
- **Risk-Based Authentication**: Adjust requirements based on risk assessment
- **Device Trust**: Evaluate device security posture and trust level
- **Biometric Support**: Fingerprint, face, iris, voice recognition
- **OAuth/OpenID Connect**: Integration with external identity providers
- **Certificate-Based Authentication**: X.509 certificate validation
- **Session Management**: Secure session creation, validation, and revocation

### Example Authentication

```rust
use fortress::{WasmPluginManager, AuthContext, AuthResult};

// Create authentication context
let context = AuthContext {
    request_id: "auth-123".to_string(),
    auth_method: "password".to_string(),
    credentials: AuthCredentials::Password {
        username: "alice".to_string(),
        password: "secure_password".to_string(),
    },
    request: AuthRequestContext {
        source_ip: "192.168.1.100".to_string(),
        user_agent: Some("Mozilla/5.0".to_string()),
        headers: HashMap::new(),
        method: "POST".to_string(),
        path: "/login".to_string(),
    },
    client: ClientContext {
        client_id: "web-app".to_string(),
        client_type: "web".to_string(),
        device: AuthDeviceContext {
            device_type: "desktop".to_string(),
            os: "Windows".to_string(),
            trusted: true,
            security_score: 85,
        },
        network: AuthNetworkContext {
            network_type: "corporate".to_string(),
            secure: true,
        },
        geolocation: Some(AuthGeoLocation {
            country: "US".to_string(),
            city: Some("San Francisco".to_string()),
        }),
    },
    environment: AuthEnvironmentContext {
        current_time: chrono::Utc::now(),
        threat_intelligence: AuthThreatIntelligence {
            ip_reputation_score: 95.0,
            risk_level: "low".to_string(),
        },
    },
    timestamp: chrono::Utc::now(),
};

// Authenticate
let manager = WasmPluginManager::default();
let result = manager.authenticate("custom-auth", context).await?;

match result.success {
    true => {
        println!("Authentication successful");
        if let Some(session) = result.session {
            println!("Session created: {}", session.session_id);
        }
    },
    false => {
        println!("Authentication failed: {:?}", result.reason);
        for step in &result.next_steps {
            println!("Next step: {} - {}", step.step_type, step.description);
        }
    }
}
```

## Creating Custom Plugins

### Policy Evaluator Plugin

Create a new Rust project:

```bash
cargo new --lib my-policy-plugin
cd my-policy-plugin
```

Add to `Cargo.toml`:

```toml
[lib]
crate-type = ["cdylib"]

[dependencies]
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
chrono = { version = "0.4", features = ["serde"] }
```

Implement the plugin in `src/lib.rs`:

```rust
use serde::{Deserialize, Serialize};

// External functions provided by Fortress host
extern "C" {
    fn fortress_log(ptr: *const u8, len: usize);
    fn fortress_policy_evaluate_user_role(user_ptr: *const u8, user_len: usize, 
                                          role_ptr: *const u8, role_len: usize) -> i32;
    fn fortress_policy_check_resource_access(user_ptr: *const u8, user_len: usize,
                                           resource_ptr: *const u8, resource_len: usize,
                                           action_ptr: *const u8, action_len: usize) -> i32;
}

#[derive(Debug, Deserialize)]
struct PolicyContext {
    user: UserContext,
    resource: ResourceContext,
    action: String,
    // ... other fields
}

#[no_mangle]
pub extern "C" fn evaluate_policy(context_ptr: *const u8, context_len: usize) -> i32 {
    // Parse context
    let context_data = unsafe { std::slice::from_raw_parts(context_ptr, context_len) };
    let context: PolicyContext = serde_json::from_slice(context_data).unwrap();
    
    // Implement custom policy logic
    let allowed = evaluate_custom_policy(&context);
    
    // Return result
    let result = PolicyResult {
        allow: allowed,
        reason: if allowed { "Custom policy allowed".to_string() } 
                else { "Custom policy denied".to_string() },
        // ... other fields
    };
    
    let result_json = serde_json::to_string(&result).unwrap();
    result_json.len() as i32
}

fn evaluate_custom_policy(context: &PolicyContext) -> bool {
    // Your custom policy logic here
    context.user.roles.contains(&"admin".to_string()) ||
    context.resource.owner.as_ref() == Some(&context.user.user_id)
}
```

Build the plugin:

```bash
rustup target add wasm32-unknown-unknown
cargo build --release --target wasm32-unknown-unknown
```

### Authentication Provider Plugin

Similar structure for auth plugins:

```rust
#[no_mangle]
pub extern "C" fn authenticate(context_ptr: *const u8, context_len: usize) -> i32 {
    let context_data = unsafe { std::slice::from_raw_parts(context_ptr, context_len) };
    let context: AuthContext = serde_json::from_slice(context_data).unwrap();
    
    let result = match context.credentials {
        AuthCredentials::Password { username, password } => {
            authenticate_password(&username, &password)
        },
        AuthCredentials::Token { token, .. } => {
            authenticate_token(&token)
        },
        // ... other credential types
    };
    
    let result_json = serde_json::to_string(&result).unwrap();
    result_json.len() as i32
}
```

## Host Functions

Fortress provides secure host functions that plugins can call:

### Basic Functions
- `fortress_log(ptr, len)` - Log messages
- `fortress_get_config(key_ptr, key_len, value_ptr, value_len)` - Get configuration
- `fortress_get_timestamp()` - Get current timestamp

### Policy Evaluation Functions
- `fortress_policy_evaluate_user_role(user, role)` - Check user role
- `fortress_policy_check_resource_access(user, resource, action)` - Check resource access
- `fortress_policy_check_time_based_access(start_hour, end_hour)` - Time-based access
- `fortress_policy_check_geolocation_access(country)` - Geolocation access

### Authentication Functions
- `fortress_auth_verify_password(username, password)` - Verify password
- `fortress_auth_validate_token(token)` - Validate token
- `fortress_auth_create_session(username, session_buffer)` - Create session
- `fortress_auth_verify_mfa(code)` - Verify MFA code

## Security Features

### Sandboxing
- Memory isolation between plugins
- No direct filesystem access
- Limited network access (controlled by host)
- Resource limits (CPU, memory, execution time)

### Validation
- Plugin signature verification (optional)
- Capability validation
- Size limits
- Timeout protection

### Monitoring
- Performance metrics collection
- Resource usage tracking
- Error logging and reporting
- Health checks

## Performance

### Benchmarks
- **Policy Evaluation**: < 1ms average for simple policies
- **Authentication**: < 5ms average for password verification
- **Memory Overhead**: < 10MB per plugin
- **Startup Time**: < 100ms for plugin loading

### Optimization
- Policy result caching (5-15 minute TTL)
- Connection pooling for external services
- Lazy loading of plugins
- Binary size optimization

## Configuration

```yaml
wasm_plugin_manager:
  max_plugins: 100
  plugin_directories:
    - "./plugins"
    - "/etc/fortress/plugins"
  auto_load: true
  enable_hot_reload: false
  
  validation:
    require_signature: false
    allowed_capabilities:
      - "policy_evaluation"
      - "authentication"
      - "encryption"
    max_plugin_size: 10485760  # 10MB
    plugin_timeout_ms: 5000
```

## Examples

See the example plugins in the `examples/` directory:

- `examples/wasm-policy-plugin/` - Comprehensive policy evaluator with RBAC + ABAC
- `examples/wasm-auth-plugin/` - Multi-factor authentication provider

Build examples:

```bash
cd examples/wasm-policy-plugin
chmod +x build.sh
./build.sh
```

## Best Practices

### Performance
- Cache frequently accessed data
- Minimize memory allocations
- Use efficient data structures
- Avoid blocking operations

### Security
- Validate all inputs
- Use secure random number generation
- Implement proper error handling
- Follow principle of least privilege

### Maintainability
- Document plugin interfaces
- Use semantic versioning
- Provide comprehensive tests
- Include usage examples

## Troubleshooting

### Common Issues

1. **Plugin Loading Fails**
   - Check WASM file format
   - Verify plugin exports required functions
   - Check file permissions

2. **Performance Issues**
   - Monitor plugin metrics
   - Check for memory leaks
   - Optimize hot paths

3. **Security Violations**
   - Review plugin capabilities
   - Check resource usage
   - Validate input handling

### Debugging

Enable debug logging:

```rust
use log::debug;

// In plugin
debug!("Evaluating policy for user: {}", user_id);
```

Monitor plugin performance:

```rust
let manager = WasmPluginManager::default();
let stats = manager.get_stats().await;
println!("Loaded plugins: {}", stats.total_plugins);
```

## Future Enhancements

- **Plugin Marketplace**: Centralized repository for sharing plugins
- **Visual Policy Builder**: GUI for creating policy plugins
- **Advanced Analytics**: ML-powered policy optimization
- **Cross-Language Support**: More language bindings
- **Distributed Plugins**: Load balancing across multiple instances

The WASM plugin system makes Fortress the most extensible and customizable security platform available, allowing organizations to implement exactly the security policies and authentication methods they need without modifying the core system.
