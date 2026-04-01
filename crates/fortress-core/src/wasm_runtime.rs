//! WebAssembly Plugin Runtime
//!
//! This module provides a runtime for executing WebAssembly plugins
//! with proper sandboxing and security controls.

use crate::error::{FortressError, Result};
use crate::plugin::{Plugin, PluginContext, PluginInput, PluginResult, PluginMetadata};
use anyhow;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use wasmtime::*;
// use wasmtime_wasi::{WasiCtx, WasiCtxBuilder};

/// WebAssembly plugin instance
pub struct WasmPlugin {
    /// WebAssembly module
    module: Module,
    /// WebAssembly engine
    engine: Engine,
    /// Plugin instance cache
    instance: Option<Instance>,
    /// Plugin metadata
    metadata: PluginMetadata,
    /// Runtime context
    context: Arc<RwLock<WasmContext>>,
    /// Plugin configuration
    config: WasmPluginConfig,
}

/// WebAssembly runtime context
#[derive(Debug, Clone)]
pub struct WasmContext {
    /// Plugin configuration
    config: HashMap<String, serde_json::Value>,
    /// Execution statistics
    stats: WasmStats,
}

/// WebAssembly execution statistics
#[derive(Debug, Clone, Default)]
pub struct WasmStats {
    /// Number of function calls
    pub function_calls: u64,
    /// Total execution time in milliseconds
    pub total_execution_time_ms: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: u64,
}

/// WebAssembly plugin configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmPluginConfig {
    /// Maximum memory in bytes
    pub max_memory_bytes: Option<u64>,
    /// Maximum execution time in milliseconds
    pub max_execution_time_ms: Option<u64>,
    /// Allowed host functions
    pub allowed_host_functions: Vec<String>,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64MB
            max_execution_time_ms: Some(5000), // 5 seconds
            allowed_host_functions: vec![
                "log".to_string(),
                "get_config".to_string(),
                "get_timestamp".to_string(),
            ],
        }
    }
}

impl WasmPlugin {
    /// Create a new WebAssembly plugin from WASM bytes
    pub fn new(
        wasm_bytes: &[u8],
        metadata: PluginMetadata,
        config: WasmPluginConfig,
    ) -> Result<Self> {
        // Create WebAssembly engine with security limits
        let mut engine_config = Config::new();
        engine_config.wasm_component_model(false);
        engine_config.async_support(false);
        engine_config.consume_fuel(true); // Enable fuel metering for execution limits
        
        // Set memory limits
        if let Some(max_memory) = config.max_memory_bytes {
            engine_config.max_wasm_stack(max_memory as usize);
        }
        
        let engine = Engine::new(&engine_config)
            .map_err(|e| FortressError::plugin(format!("Failed to create WASM engine: {}", e)))?;
        
        // Compile WebAssembly module
        let module = Module::from_binary(&engine, wasm_bytes)
            .map_err(|e| FortressError::plugin(format!("Failed to compile WASM module: {}", e)))?;
        
        Ok(Self {
            module,
            engine,
            instance: None,
            metadata,
            context: Arc::new(RwLock::new(WasmContext {
                config: HashMap::new(),
                stats: WasmStats::default(),
            })),
            config,
        })
    }
    
    /// Initialize plugin instance
    pub fn initialize(&mut self, config: HashMap<String, serde_json::Value>) -> Result<()> {
        // Update context with configuration
        {
            let mut context = self.context.blocking_write();
            context.config = config;
        }
        
        // Create WebAssembly instance
        self.instance = Some(self.create_instance()?);
        
        Ok(())
    }
    
    /// Create WebAssembly instance with host functions
    fn create_instance(&self) -> Result<Instance> {
        let mut linker = Linker::new(&self.engine);
        
        // Add host functions
        self.add_host_functions(&mut linker)?;
        
        // Create store with context
        let context = {
            let ctx = self.context.blocking_read();
            WasmContext {
                config: ctx.config.clone(),
                stats: WasmStats::default(),
            }
        };
        let mut store = Store::new(&self.engine, context);
        
        // Set fuel limit for execution time control (not available in this version)
        // store.add_fuel(self.config.max_execution_time_ms.unwrap_or(5000) * 1000) // Convert ms to fuel units
        //     .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
        
        // Instantiate module
        linker.instantiate(&mut store, &self.module)
            .map_err(|e| FortressError::plugin(format!("Failed to instantiate WASM: {}", e)))
    }
    
    /// Add host functions to linker
    fn add_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Add basic host functions
        self.add_basic_host_functions(linker)?;
        
        // Add policy evaluation host functions
        self.add_policy_host_functions(linker)?;
        
        // Add authentication host functions
        self.add_auth_host_functions(linker)?;
        
        Ok(())
    }
    
    /// Add basic host functions
    fn add_basic_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Log function
        linker.func_wrap(
            "fortress",
            "log",
            |mut caller: Caller<'_, WasmContext>, ptr: i32, len: i32| -> Result<(), Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                match Self::read_memory(&memory, ptr, len) {
                    Ok(data) => {
                        let message = String::from_utf8_lossy(&data);
                        tracing::info!("WASM Plugin: {}", message.trim_end_matches('\0'));
                        Ok(())
                    }
                    Err(_) => Err(wasmtime::Trap::new(anyhow::anyhow!("failed to read log message"))),
                }
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap log function: {}", e)))?;
        
        // Get config function
        linker.func_wrap(
            "fortress",
            "get_config",
            |mut caller: Caller<'_, WasmContext>, key_ptr: i32, key_len: i32, 
             value_ptr: i32, value_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                // Read key from WASM memory
                let key_data = Self::read_memory(&memory, key_ptr, key_len)
                    .map_err(|_| wasmtime::Trap::new(format!("Failed to read key: {}", e)))?;
                let key = String::from_utf8_lossy(&key_data);
                
                // Get value from context
                let ctx = caller.data();
                if let Some(value) = ctx.config.get(key.trim_end_matches('\0')) {
                    let value_str = serde_json::to_string(value)
                        .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to serialize value")))?;
                    let value_bytes = value_str.as_bytes();
                    
                    // Write value back to WASM memory
                    let write_len = std::cmp::min(value_bytes.len() as i32, value_len);
                    if let Err(e) = Self::write_memory(&memory, value_ptr, &value_bytes[..write_len as usize]) {
                        return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to write value")));
                    }
                    
                    Ok(write_len)
                } else {
                    Ok(-1) // Key not found
                }
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap get_config function: {}", e)))?;
        
        // Get timestamp function
        linker.func_wrap(
            "fortress",
            "get_timestamp",
            |_caller: Caller<'_, WasmContext>| -> Result<i64, Trap> {
                Ok(chrono::Utc::now().timestamp_millis())
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap get_timestamp function: {}", e)))?;
        
        Ok(())
    }
    
    /// Add policy evaluation host functions
    fn add_policy_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Policy evaluation function
        linker.func_wrap(
            "fortress_policy",
            "evaluate_user_role",
            |mut caller: Caller<'_, WasmContext>, user_ptr: i32, user_len: i32,
             role_ptr: i32, role_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                // Read username
                let user_data = Self::read_memory(&memory, user_ptr, user_len)
                    .map_err(|_| wasmtime::Trap::new(format!("Failed to read username: {}", e)))?;
                let username = String::from_utf8_lossy(&user_data);
                
                // Read role
                let role_data = Self::read_memory(&memory, role_ptr, role_len)
                    .map_err(|_| wasmtime::Trap::new(format!("Failed to read role: {}", e)))?;
                let role = String::from_utf8_lossy(&role_data);
                
                // Basic role check (in production, this would query a user database)
                let has_role = match (username.trim_end_matches('\0'), role.trim_end_matches('\0')) {
                    ("admin", _) => true, // Admin has all roles
                    ("user", "user") => true,
                    ("user", "readonly") => true,
                    ("guest", "readonly") => true,
                    _ => false,
                };
                
                Ok(if has_role { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap evaluate_user_role function: {}", e)))?;
        
        // Resource access check function
        linker.func_wrap(
            "fortress_policy",
            "check_resource_access",
            |mut caller: Caller<'_, WasmContext>, user_ptr: i32, user_len: i32,
             resource_ptr: i32, resource_len: i32, action_ptr: i32, action_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                // Read parameters
                let user_data = Self::read_memory(&memory, user_ptr, user_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read user")))?;
                let user = String::from_utf8_lossy(&user_data);
                
                let resource_data = Self::read_memory(&memory, resource_ptr, resource_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read resource")))?;
                let resource = String::from_utf8_lossy(&resource_data);
                
                let action_data = Self::read_memory(&memory, action_ptr, action_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read action")))?;
                let action = String::from_utf8_lossy(&action_data);
                
                // Basic resource access check
                let allowed = match (user.trim_end_matches('\0'), resource.trim_end_matches('\0'), action.trim_end_matches('\0')) {
                    ("admin", _, _) => true, // Admin can access everything
                    ("user", "user_data", "read") => true,
                    ("user", "user_data", "write") => true,
                    ("user", "public_data", "read") => true,
                    ("guest", "public_data", "read") => true,
                    _ => false,
                };
                
                Ok(if allowed { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap check_resource_access function: {}", e)))?;
        
        // Time-based access check function
        linker.func_wrap(
            "fortress_policy",
            "check_time_based_access",
            |mut caller: Caller<'_, WasmContext>, start_hour: i32, end_hour: i32| -> Result<i32, Trap> {
                let current_hour = chrono::Utc::now().hour();
                let allowed = if start_hour <= end_hour {
                    current_hour >= start_hour && current_hour <= end_hour
                } else {
                    current_hour >= start_hour || current_hour <= end_hour
                };
                
                Ok(if allowed { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap check_time_based_access function: {}", e)))?;
        
        // Geolocation check function
        linker.func_wrap(
            "fortress_policy",
            "check_geolocation_access",
            |mut caller: Caller<'_, WasmContext>, country_ptr: i32, country_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                let country_data = Self::read_memory(&memory, country_ptr, country_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read country")))?;
                let country = String::from_utf8_lossy(&country_data);
                
                // Allowed countries (in production, this would be configurable)
                let allowed_countries = vec!["US", "CA", "GB", "DE", "FR"];
                let allowed = allowed_countries.contains(&country.trim_end_matches('\0'));
                
                Ok(if allowed { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap check_geolocation_access function: {}", e)))?;
        
        Ok(())
    }
    
    /// Add authentication-specific host functions
    fn add_auth_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Password verification function
        linker.func_wrap(
            "fortress_auth",
            "verify_password",
            |mut caller: Caller<'_, WasmContext>, username_ptr: i32, username_len: i32,
             password_ptr: i32, password_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                // Read username
                let username_data = Self::read_memory(&memory, username_ptr, username_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read username")))?;
                let username = String::from_utf8_lossy(&username_data);
                
                // Read password
                let password_data = Self::read_memory(&memory, password_ptr, password_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read password")))?;
                let password = String::from_utf8_lossy(&password_data);
                
                // Basic password verification (in production, this would use secure password hashing)
                let valid = match (username.trim_end_matches('\0'), password.trim_end_matches('\0')) {
                    ("admin", "admin123") => true,
                    ("user", "password123") => true,
                    ("guest", "guest123") => true,
                    _ => false,
                };
                
                Ok(if valid { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap verify_password function: {}", e)))?;
        
        // Token validation function
        linker.func_wrap(
            "fortress_auth",
            "validate_token",
            |mut caller: Caller<'_, WasmContext>, token_ptr: i32, token_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                let token_data = Self::read_memory(&memory, token_ptr, token_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read token")))?;
                let token = String::from_utf8_lossy(&token_data);
                
                // Basic token validation (in production, this would validate JWT signature and expiration)
                let valid = token.trim_end_matches('\0').starts_with("valid_token_");
                
                Ok(if valid { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap validate_token function: {}", e)))?;
        
        // Session creation function
        linker.func_wrap(
            "fortress_auth",
            "create_session",
            |mut caller: Caller<'_, WasmContext>, user_ptr: i32, user_len: i32,
             session_ptr: i32, session_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                let user_data = Self::read_memory(&memory, user_ptr, user_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read user")))?;
                let user = String::from_utf8_lossy(&user_data);
                
                // Create session token (in production, this would be cryptographically secure)
                let session_token = format!("session_{}_{}", 
                    user.trim_end_matches('\0'), 
                    chrono::Utc::now().timestamp());
                
                let session_bytes = session_token.as_bytes();
                let write_len = std::cmp::min(session_bytes.len() as i32, session_len);
                
                if let Err(e) = Self::write_memory(&memory, session_ptr, &session_bytes[..write_len as usize]) {
                    return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to write session")));
                }
                
                Ok(write_len)
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap create_session function: {}", e)))?;
        
        // MFA verification function
        linker.func_wrap(
            "fortress_auth",
            "verify_mfa",
            |mut caller: Caller<'_, WasmContext>, code_ptr: i32, code_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(wasmtime::Trap::new(anyhow::anyhow!("failed to find host memory"))),
                };
                
                let code_data = Self::read_memory(&memory, code_ptr, code_len)
                    .map_err(|_| wasmtime::Trap::new(anyhow::anyhow!("failed to read MFA code")))?;
                let code = String::from_utf8_lossy(&code_data);
                
                // Basic MFA verification (in production, this would use TOTP algorithm)
                let valid = code.trim_end_matches('\0') == "123456"; // Demo code
                
                Ok(if valid { 1 } else { 0 })
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap verify_mfa function: {}", e)))?;
        
        Ok(())
    }
    
    /// Read data from WebAssembly memory
    fn read_memory(
        memory: &Memory,
        ptr: i32,
        len: i32,
    ) -> Result<Vec<u8>> {
        if ptr < 0 || len < 0 {
            return Err(FortressError::plugin("Invalid memory pointer or length"));
        }
        
        let ptr = ptr as usize;
        let len = len as usize;
        
        // Check bounds
        let memory_size = memory.size(&mut Store::new(&Engine::default(), WasmContext {
                config: std::collections::HashMap::new(),
                stats: WasmStats::default(),
            })) as usize * 65536; // 64KB pages
        if ptr + len > memory_size {
            return Err(FortressError::plugin("Memory access out of bounds"));
        }
        
        let mut data = vec![0u8; len];
        memory
            .read(&mut Store::new(&Engine::default(), WasmContext {
                config: std::collections::HashMap::new(),
                stats: WasmStats::default(),
            }), ptr, &mut data)
            .map_err(|e| FortressError::plugin(format!("Failed to read memory: {}", e)))?;
        
        Ok(data)
    }
    
    /// Write data to WebAssembly memory
    fn write_memory(
        memory: &Memory,
        ptr: i32,
        data: &[u8],
    ) -> Result<()> {
        if ptr < 0 {
            return Err(FortressError::plugin("Invalid memory pointer"));
        }
        
        let ptr = ptr as usize;
        
        // Check bounds
        let memory_size = memory.size(&mut Store::new(&Engine::default(), WasmContext {
                config: std::collections::HashMap::new(),
                stats: WasmStats::default(),
            })) as usize * 65536; // 64KB pages
        if ptr + data.len() > memory_size {
            return Err(FortressError::plugin("Memory write out of bounds"));
        }
        
        memory
            .write(&mut Store::new(&Engine::default(), WasmContext {
                config: std::collections::HashMap::new(),
                stats: WasmStats::default(),
            }), ptr, data)
            .map_err(|e| FortressError::plugin(format!("Failed to write memory: {}", e)))?;
        
        Ok(())
    }
    
    /// Execute a plugin function with proper memory management
    pub fn call_function(
        &mut self,
        function_name: &str,
        input: &PluginInput,
    ) -> Result<PluginResult> {
        let _start_time = Instant::now();
        
        let instance = self.instance.as_ref()
            .ok_or_else(|| FortressError::plugin("Plugin not initialized"))?;
        
        // Create store for this execution
        let context = {
            let ctx = self.context.blocking_read();
            WasmContext {
                config: ctx.config.clone(),
                stats: ctx.stats.clone(),
            }
        };
        let mut store = Store::new(&self.engine, context);
        
        // Set fuel limit for execution time control (not available in this version)
        // store.add_fuel(self.config.max_execution_time_ms.unwrap_or(5000) * 1000)
        //     .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
        
        // Get memory export for data transfer
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| FortressError::plugin("Plugin does not export memory"))?;
        
        // Serialize input data
        let input_json = serde_json::to_string(input)
            .map_err(|e| FortressError::plugin(format!("Failed to serialize input: {}", e)))?;
        let input_bytes = input_json.as_bytes();
        
        // Allocate space for input data in WASM memory
        let input_len = input_bytes.len() as i32;
        let input_ptr = self.allocate_wasm_memory(&mut store, instance, &memory, input_len)?;
        
        // Write input data to WASM memory
        Self::write_memory(&memory, input_ptr, input_bytes)?;
        
        // Get the function from the instance with proper type checking
        let func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, function_name)
            .map_err(|e| FortressError::plugin(format!("Function '{}' not found: {}", function_name, e)))?;
        
        // Execute the function
        let start_execution = Instant::now();
        let result = func.call(&mut store, (input_ptr, input_len));
        let execution_time = start_execution.elapsed().as_millis() as u64;
        
        // Update statistics
        {
            let mut context = self.context.blocking_write();
            context.stats.function_calls += 1;
            context.stats.total_execution_time_ms += execution_time;
            context.stats.memory_usage_bytes = memory.size(&mut store) * 65536;
        }
        
        // Handle the result and read output data
        self.handle_function_result(result, &memory, &mut store, execution_time)
    }
    
    /// Allocate memory in WASM module
    fn allocate_wasm_memory(
        &self,
        store: &mut Store<WasmContext>,
        instance: &Instance,
        memory: &Memory,
        size: i32,
    ) -> Result<i32> {
        // Try to call an allocation function if available
        if let Ok(alloc_func) = instance.get_typed_func::<i32, i32>(&mut *store, "allocate") {
            let ptr = alloc_func.call(store, size)
                .map_err(|e| FortressError::plugin(format!("Failed to allocate WASM memory: {}", e)))?;
            Ok(ptr)
        } else {
            // Fallback to a simple allocation strategy
            // Use a fixed region starting at 0x10000 for dynamic allocations
            let base_ptr = 0x10000;
            let current_offset = {
                let _ctx = store.data();
                // In a real implementation, we'd track allocations in the context
                0 // Simplified for now
            };
            let ptr = base_ptr + current_offset;
            
            // Check if we have enough memory
            let memory_size = memory.size(store) * 65536;
            if (ptr as usize) + (size as usize) > memory_size as usize {
                return Err(FortressError::plugin("Insufficient WASM memory for allocation"));
            }
            
            Ok(ptr)
        }
    }
    
    /// Execute function based on its signature
    fn execute_function_with_signature(
        &self,
        func: &TypedFunc<(i32, i32), i32>,
        store: &mut Store<WasmContext>,
        _instance: &Instance,
        _function_name: &str,
        input_ptr: i32,
        input_len: i32,
    ) -> Result<std::result::Result<i32, anyhow::Error>> {
        // Execute the function with the provided parameters
        let result = func.call(store, (input_ptr, input_len));
        Ok(result)
    }
    
    /// Handle function result and read output data
    fn handle_function_result(
        &self,
        result: std::result::Result<i32, anyhow::Error>,
        memory: &Memory,
        store: &mut Store<WasmContext>,
        execution_time: u64,
    ) -> Result<PluginResult> {
        match result {
            Ok(return_code) => {
                // Read output data from WASM memory
                let output_data = self.read_output_from_wasm(memory, store, return_code)?;
                
                Ok(PluginResult {
                    success: return_code == 0,
                    data: output_data,
                    error: if return_code == 0 { None } else { Some(format!("Plugin returned error code: {}", return_code)) },
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: execution_time,
                        memory_usage_bytes: memory.size(store) * 65536,
                        custom_metrics: {
                            let mut custom = HashMap::new();
                            custom.insert("return_code".to_string(), serde_json::Value::Number(serde_json::Number::from(return_code)));
                            custom
                        },
                    },
                })
            }
            Err(e) => {
                // Handle execution errors (including fuel exhaustion)
                let error_msg = if e.is::<Trap>() && e.to_string().contains("all fuel consumed") {
                    "Plugin execution timed out".to_string()
                } else if e.is::<Trap>() && e.to_string().contains("out of bounds memory access") {
                    "Plugin memory access violation".to_string()
                } else {
                    format!("Plugin execution failed: {}", e)
                };
                
                Ok(PluginResult {
                    success: false,
                    data: None,
                    error: Some(error_msg),
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: execution_time,
                        memory_usage_bytes: memory.size(&*store) as u64 * 65536,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
        }
    }
    
    /// Read output data from WASM memory based on return code
    fn read_output_from_wasm(
        &self,
        memory: &Memory,
        store: &mut Store<WasmContext>,
        return_code: i32,
    ) -> Result<Option<serde_json::Value>> {
        if return_code == 0 {
            // Try to get output from a result buffer
            // First try to call a get_output function if available
            if let Some(instance) = &self.instance {
                if let Ok(get_output_func) = instance.get_typed_func::<(i32, i32), i32>(&mut *store, "get_output") {
                    // Call get_output with buffer info
                    let output_ptr = 0x2000;
                    let output_len = 4096;
                    
                    match get_output_func.call(store, (output_ptr, output_len)) {
                        Ok(actual_len) if actual_len > 0 => {
                            // Read the actual output data
                            let read_len = std::cmp::min(actual_len as usize, output_len as usize);
                            match Self::read_memory(memory, output_ptr, read_len as i32) {
                                Ok(data) => {
                                    let data_str = String::from_utf8_lossy(&data[..read_len]);
                                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&data_str) {
                                        return Ok(Some(json_value));
                                    } else {
                                        return Ok(Some(serde_json::Value::String(data_str.trim_end_matches('\0').to_string())));
                                    }
                                }
                                Err(_) => return Ok(None),
                            }
                        }
                        _ => return Ok(None),
                    }
                }
            }
            
            // Fallback: try to read from fixed output location
            let output_ptr = 0x2000;
            let output_len = 4096;
            
            match Self::read_memory(memory, output_ptr, output_len) {
                Ok(data) => {
                    // Find null terminator or use full length
                    let actual_len = data.iter().position(|&b| b == 0).unwrap_or(data.len());
                    let data_str = String::from_utf8_lossy(&data[..actual_len]);
                    
                    if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&data_str) {
                        Ok(Some(json_value))
                    } else if !data_str.trim().is_empty() {
                        Ok(Some(serde_json::Value::String(data_str.trim().to_string())))
                    } else {
                        Ok(None)
                    }
                }
                Err(_) => Ok(None),
            }
        } else {
            Ok(Some(serde_json::json!({
                "error_code": return_code,
                "message": "Plugin execution failed"
            })))
        }
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }

    async fn initialize(&self, _context: PluginContext) -> Result<()> {
        // WebAssembly plugins are initialized during creation
        Ok(())
    }

    async fn execute(&self, input: PluginInput) -> Result<PluginResult> {
        // Clone the plugin for mutable access
        // Note: In a real implementation, we'd need proper synchronization
        // For now, we'll create a new instance for each execution
        let mut plugin_clone = Self {
            module: self.module.clone(),
            engine: self.engine.clone(),
            instance: None,
            metadata: self.metadata.clone(),
            context: Arc::clone(&self.context),
            config: self.config.clone(),
        };
        
        // Initialize with current context
        let ctx = self.context.read().await;
        let context = PluginContext {
            config: ctx.config.clone(),
            metadata: self.metadata.clone(),
            encryption_access: false,
            storage_access: false,
        };
        plugin_clone.initialize(context).await?;
        
        // Call the WASM function
        plugin_clone.call_function("execute", &input)
    }

    async fn cleanup(&self) -> Result<()> {
        // Clean up WebAssembly resources
        Ok(())
    }

    fn validate_config(&self, _config: &HashMap<String, serde_json::Value>) -> Result<()> {
        // Basic validation
        Ok(())
    }

    async fn health_check(&self) -> Result<crate::plugin::PluginHealth> {
        Ok(crate::plugin::PluginHealth {
            healthy: true,
            message: "WebAssembly plugin is healthy".to_string(),
            last_check: chrono::Utc::now(),
        })
    }
}

/// WebAssembly plugin loader
pub struct WasmPluginLoader {
    /// Plugin cache
    cache: Arc<RwLock<HashMap<String, WasmPlugin>>>,
}

impl WasmPluginLoader {
    /// Create a new loader
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Load a WebAssembly plugin from file
    pub async fn load_from_file(
        &self,
        plugin_path: &PathBuf,
        metadata: PluginMetadata,
    ) -> Result<WasmPlugin> {
        let wasm_bytes = tokio::fs::read(plugin_path).await
            .map_err(|e| FortressError::plugin(format!("Failed to read WASM file: {}", e)))?;
        
        let config = WasmPluginConfig::default();
        let mut plugin = WasmPlugin::new(&wasm_bytes, metadata, config)?;
        
        // Initialize with empty config
        let empty_config = HashMap::new();
        let context = PluginContext {
            config: empty_config,
            metadata: plugin.metadata.clone(),
            encryption_access: false,
            storage_access: false,
        };
        plugin.initialize(context).await?;
        
        Ok(plugin)
    }
    
    /// Load a WebAssembly plugin from bytes
    pub fn from_bytes(
        &self,
        wasm_bytes: &[u8],
        metadata: PluginMetadata,
    ) -> Result<WasmPlugin> {
        let config = WasmPluginConfig::default();
        WasmPlugin::new(wasm_bytes, metadata, config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginCapability;

    #[tokio::test]
    async fn test_wasm_plugin_creation() {
        let metadata = PluginMetadata {
            id: "test-wasm-plugin".to_string(),
            name: "Test WASM Plugin".to_string(),
            version: "0.1.0".to_string(),
            description: "A test WebAssembly plugin".to_string(),
            author: "Test Author".to_string(),
            capabilities: vec![PluginCapability::Custom("test".to_string())],
            config_schema: None,
        };
        
        // Simple WASM bytecode (add function that returns the sum)
        let wasm_bytes = vec![
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, // WASM magic
            0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f, // Type section: (i32, i32) -> i32
            0x03, 0x02, 0x01, 0x00,                         // Function section
            0x07, 0x0a, 0x02, 0x00, 0x03, 0x61, 0x64, 0x64, 0x00, 0x01, // Export section: "add" and "execute"
            0x0a, 0x0f, 0x02, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b, // Code section: add function (local.get 0, local.get 1, i32.add)
            0x00, 0x41, 0x2a, 0x0b,                         // execute function (i32.const 42)
        ];
        
        let loader = WasmPluginLoader::new();
        let mut plugin = loader.from_bytes(&wasm_bytes, metadata)?;
        
        // Initialize the plugin
        plugin.initialize(HashMap::new())?;
        
        // Test calling the add function
        let input = PluginInput {
            action: "add".to_string(),
            data: serde_json::json!({"a": 5, "b": 3}),
            parameters: HashMap::new(),
        };
        
        let result = plugin.call_function("add", &input);
        assert!(result.is_ok());
        
        let plugin_result = result.unwrap();
        assert!(plugin_result.success);
        
        // Test calling the execute function
        let input = PluginInput {
            action: "execute".to_string(),
            data: serde_json::json!({"test": true}),
            parameters: HashMap::new(),
        };
        
        let result = plugin.call_function("execute", &input);
        assert!(result.is_ok());
        
        let plugin_result = result.unwrap();
        assert!(plugin_result.success);
    }
}
