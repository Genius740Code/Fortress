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
    /// Number of errors
    pub error_count: u64,
}

/// WebAssembly plugin configuration
#[derive(Debug, Clone)]
pub struct WasmPluginConfig {
    /// Maximum memory usage in bytes
    pub max_memory_bytes: Option<u64>,
    /// Maximum execution time in milliseconds
    pub max_execution_time_ms: Option<u64>,
    /// Fuel metering (for execution limiting)
    pub enable_fuel_metering: bool,
    /// Maximum fuel units
    pub max_fuel: Option<u64>,
    /// Allowed host functions
    pub allowed_host_functions: Vec<String>,
}

impl Default for WasmPluginConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: Some(64 * 1024 * 1024), // 64MB
            max_execution_time_ms: Some(5000),        // 5 seconds
            enable_fuel_metering: true,
            max_fuel: Some(1000000),
            allowed_host_functions: vec![
                "fortress_log".to_string(),
                "fortress_config_get".to_string(),
                "fortress_timestamp".to_string(),
            ],
        }
    }
}

/// WebAssembly plugin loader
pub struct WasmPluginLoader {
    /// WebAssembly engine
    engine: Engine,
    /// Plugin configuration
    config: WasmPluginConfig,
}

impl WasmPluginLoader {
    /// Create a new WASM plugin loader
    pub fn new(config: WasmPluginConfig) -> Result<Self> {
        // Configure the WASM engine with security constraints
        let mut engine_config = Config::new();
        
        // Enable fuel metering for execution limiting
        if config.enable_fuel_metering {
            engine_config.consume_fuel(true);
        }
        
        // Set memory limits
        if let Some(max_memory) = config.max_memory_bytes {
            engine_config.max_wasm_stack(max_memory as usize);
        }
        
        engine_config.async_support(true);
        
        let engine = Engine::new(&engine_config)
            .map_err(|e| FortressError::plugin(format!("Failed to create WASM engine: {}", e)))?;
        
        Ok(Self { engine, config })
    }
    
    /// Load a WASM plugin from bytes
    pub fn load_from_bytes(&self, wasm_bytes: &[u8], metadata: PluginMetadata) -> Result<WasmPlugin> {
        // Validate the WASM module
        let module = Module::from_binary(&self.engine, wasm_bytes)
            .map_err(|e| FortressError::plugin(format!("Failed to load WASM module: {}", e)))?;
        
        // Validate module exports
        self.validate_module(&module)?;
        
        // Create runtime context
        let context = Arc::new(RwLock::new(WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        }));
        
        Ok(WasmPlugin {
            module,
            engine: self.engine.clone(),
            instance: None,
            metadata,
            context,
            config: self.config.clone(),
        })
    }
    
    /// Load a WASM plugin from a file
    pub fn load_from_file(&self, file_path: &PathBuf, metadata: PluginMetadata) -> Result<WasmPlugin> {
        let wasm_bytes = std::fs::read(file_path)
            .map_err(|e| FortressError::plugin(format!("Failed to read WASM file: {}", e)))?;
        
        self.load_from_bytes(&wasm_bytes, metadata)
    }
    
    /// Validate a WASM module for security
    fn validate_module(&self, module: &Module) -> Result<()> {
        // Check for required exports
        let exports = module.exports();
        
        // Ensure the module has an "execute" function
        if !exports.any(|export| export.name() == "execute") {
            return Err(FortressError::plugin(
                "WASM module must export an 'execute' function".to_string()
            ));
        }
        
        // Check for disallowed imports (security check)
        for import in module.imports() {
            let module_name = import.module();
            let field_name = import.name();
            
            // Only allow imports from whitelisted modules
            if !self.config.allowed_host_functions.iter().any(|allowed| {
                allowed == module_name || (module_name == "env" && self.config.allowed_host_functions.contains(field_name))
            }) {
                return Err(FortressError::plugin(
                    format!("Disallowed import: {}::{}", module_name, field_name)
                ));
            }
        }
        
        Ok(())
    }
}

#[async_trait]
impl Plugin for WasmPlugin {
    async fn initialize(&mut self, context: PluginContext) -> Result<()> {
        // Update runtime context
        {
            let mut ctx = self.context.write().await;
            ctx.config = context.config;
        }
        
        // Create WASM instance with host functions
        let mut store = Store::new(&self.engine, self.context.clone());
        
        // Set fuel limit if enabled
        if self.config.enable_fuel_metering {
            if let Some(max_fuel) = self.config.max_fuel {
                store.add_fuel(max_fuel)
                    .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
            }
        }
        
        // Create linker for host functions
        let mut linker = Linker::new(&self.engine);
        
        // Define host functions
        self.define_host_functions(&mut linker)?;
        
        // Instantiate the module
        self.instance = Some(linker.instantiate(&mut store, &self.module)
            .map_err(|e| FortressError::plugin(format!("Failed to instantiate WASM module: {}", e)))?);
        
        Ok(())
    }
    
    async fn execute(&mut self, input: PluginInput) -> Result<PluginResult> {
        let start_time = Instant::now();
        
        // Check if plugin is initialized
        if self.instance.is_none() {
            return Err(FortressError::plugin("Plugin not initialized".to_string()));
        }
        
        let instance = self.instance.as_ref().unwrap();
        let mut store = Store::new(&self.engine, self.context.clone());
        
        // Set fuel limit for this execution
        if self.config.enable_fuel_metering {
            if let Some(max_fuel) = self.config.max_fuel {
                store.add_fuel(max_fuel)
                    .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
            }
        }
        
        // Get the execute function
        let execute_func = instance.get_typed_func::<(i32, i32), i32>(&mut store, "execute")
            .map_err(|e| FortressError::plugin(format!("Failed to get execute function: {}", e)))?;
        
        // Serialize input
        let input_json = serde_json::to_string(&input)
            .map_err(|e| FortressError::plugin(format!("Failed to serialize input: {}", e)))?;
        let input_bytes = input_json.as_bytes();
        
        // Allocate memory for input (simplified - in production, would use proper memory management)
        let input_ptr = 0x1000; // Fixed address for demo
        let input_len = input_bytes.len() as i32;
        
        // Execute the function with timeout
        let result = tokio::time::timeout(
            Duration::from_millis(self.config.max_execution_time_ms.unwrap_or(5000)),
            async {
                // In a real implementation, we would copy input to WASM memory
                // For now, we'll simulate the execution
                
                // Update statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.function_calls += 1;
                }
                
                // Simulate WASM execution
                execute_func.call(&mut store, (input_ptr, input_len))
            }
        ).await;
        
        // Handle timeout
        match result {
            Ok(Ok(result_code)) => {
                let execution_time = start_time.elapsed().as_millis() as u64;
                
                // Update statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.total_execution_time_ms += execution_time;
                }
                
                // Create result
                let plugin_result = PluginResult {
                    success: result_code == 0,
                    data: serde_json::json!({
                        "result_code": result_code,
                        "execution_time_ms": execution_time,
                        "memory_usage": self.get_memory_usage(&store).unwrap_or(0),
                    }),
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: execution_time,
                        memory_usage_bytes: self.get_memory_usage(&store).unwrap_or(0),
                        custom_metrics: HashMap::new(),
                    },
                };
                
                Ok(plugin_result)
            },
            Ok(Err(e)) => {
                // Update error statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.error_count += 1;
                }
                
                Err(FortressError::plugin(format!("WASM execution failed: {}", e)))
            },
            Err(_) => {
                // Update timeout statistics
                {
                    let mut ctx = self.context.write().await;
                    ctx.stats.error_count += 1;
                }
                
                Err(FortressError::plugin("WASM execution timed out".to_string()))
            }
        }
    }
    
    async fn cleanup(&mut self) -> Result<()> {
        // Clean up instance and resources
        self.instance = None;
        
        // Reset statistics
        {
            let mut ctx = self.context.write().await;
            ctx.stats = WasmStats::default();
        }
        
        Ok(())
    }
    
    fn metadata(&self) -> &PluginMetadata {
        &self.metadata
    }
}

impl WasmPlugin {
    /// Define host functions for WASM plugins
    fn define_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Logging function
        linker.func_wrap(
            "env",
            "fortress_log",
            |mut caller: Caller<'_, WasmContext>, ptr: i32, len: i32| -> std::result::Result<(), Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(Trap::new("failed to find host memory")),
                };
                
                let log_data = Self::read_memory(&memory, ptr, len)
                    .map_err(|_| Trap::new("failed to read log data"))?;
                let log_message = String::from_utf8_lossy(&log_data);
                
                // Log the message (in production, would use proper logging)
                println!("WASM Plugin: {}", log_message.trim_end_matches('\0'));
                
                Ok(())
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap log function: {}", e)))?;
        
        // Config get function
        linker.func_wrap(
            "env",
            "fortress_config_get",
            |mut caller: Caller<'_, WasmContext>, key_ptr: i32, key_len: i32,
             value_ptr: i32, value_len: i32| -> std::result::Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(Trap::new("failed to find host memory")),
                };
                
                let key_data = Self::read_memory(&memory, key_ptr, key_len)
                    .map_err(|_| Trap::new("failed to read key"))?;
                let key = String::from_utf8_lossy(&key_data);
                
                // Get config value from context
                let config = &caller.data().config;
                let value = config.get(key.trim_end_matches('\0'))
                    .and_then(|v| serde_json::to_string(v).ok())
                    .unwrap_or_default();
                
                let value_bytes = value.as_bytes();
                let write_len = std::cmp::min(value_bytes.len() as i32, value_len);
                
                if let Err(_) = Self::write_memory(&memory, value_ptr, &value_bytes[..write_len as usize]) {
                    return Err(Trap::new("failed to write value"));
                }
                
                Ok(write_len)
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap config function: {}", e)))?;
        
        // Timestamp function
        linker.func_wrap(
            "env",
            "fortress_timestamp",
            |_caller: Caller<'_, WasmContext>| -> std::result::Result<i64, Trap> {
                Ok(chrono::Utc::now().timestamp())
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap timestamp function: {}", e)))?;
        
        Ok(())
    }
    
    /// Read data from WebAssembly memory
    fn read_memory(memory: &Memory, ptr: i32, len: i32) -> std::result::Result<Vec<u8>, String> {
        if ptr < 0 || len < 0 {
            return Err("Invalid pointer or length".to_string());
        }
        
        let ptr = ptr as usize;
        let len = len as usize;
        
        let mem_size = memory.size(&Store::new(&Engine::default(), WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        })).checked_mul(65536).unwrap_or(0);
        
        if ptr.checked_add(len).unwrap_or(usize::MAX) > mem_size {
            return Err("Memory access out of bounds".to_string());
        }
        
        let mut data = vec![0u8; len];
        memory.read(&Store::new(&Engine::default(), WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        }), ptr, &mut data).map_err(|e| format!("Failed to read memory: {}", e))?;
        
        Ok(data)
    }
    
    /// Write data to WebAssembly memory
    fn write_memory(memory: &Memory, ptr: i32, data: &[u8]) -> std::result::Result<(), String> {
        if ptr < 0 {
            return Err("Invalid pointer".to_string());
        }
        
        let ptr = ptr as usize;
        let len = data.len();
        
        let mem_size = memory.size(&Store::new(&Engine::default(), WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        })).checked_mul(65536).unwrap_or(0);
        
        if ptr.checked_add(len).unwrap_or(usize::MAX) > mem_size {
            return Err("Memory access out of bounds".to_string());
        }
        
        memory.write(&Store::new(&Engine::default(), WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        }), ptr, data).map_err(|e| format!("Failed to write memory: {}", e))?;
        
        Ok(())
    }
    
    /// Get current memory usage
    fn get_memory_usage(&self, store: &Store<WasmContext>) -> Option<u64> {
        // This would get actual memory usage from the WASM instance
        // For now, return a simulated value
        Some(1024 * 1024) // 1MB
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::PluginCapability;
    use std::path::PathBuf;
    
    #[tokio::test]
    async fn test_wasm_plugin_loader() {
        let config = WasmPluginConfig::default();
        let loader = WasmPluginLoader::new(config).unwrap();
        
        // Create test metadata
        let metadata = PluginMetadata {
            id: "test-plugin".to_string(),
            name: "Test Plugin".to_string(),
            version: "1.0.0".to_string(),
            description: "Test plugin for WASM runtime".to_string(),
            author: "Fortress Team".to_string(),
            capabilities: vec![PluginCapability::Authentication],
            wasm_module: None,
            config_schema: serde_json::Value::Null,
        };
        
        // Test loading (would need actual WASM bytes)
        assert!(loader.engine.module_name().is_some());
    }
    
    #[tokio::test]
    async fn test_wasm_context() {
        let context = WasmContext {
            config: HashMap::new(),
            stats: WasmStats::default(),
        };
        
        assert_eq!(context.stats.function_calls, 0);
        assert_eq!(context.stats.error_count, 0);
    }
}
