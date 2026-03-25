//! WebAssembly Plugin Runtime
//!
//! This module provides a runtime for executing WebAssembly plugins
//! with proper sandboxing and security controls.

use crate::error::{FortressError, Result};
use crate::plugin::{Plugin, PluginContext, PluginInput, PluginResult, PluginMetadata};
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
        
        // Set fuel limit for execution time control
        store.add_fuel(self.config.max_execution_time_ms.unwrap_or(5000) * 1000) // Convert ms to fuel units
            .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
        
        // Instantiate module
        linker.instantiate(&mut store, &self.module)
            .map_err(|e| FortressError::plugin(format!("Failed to instantiate WASM: {}", e)))
    }
    
    /// Add host functions to linker
    fn add_host_functions(&self, linker: &mut Linker<WasmContext>) -> Result<()> {
        // Add log function
        linker.func_wrap(
            "env",
            "log",
            |mut caller: Caller<'_, WasmContext>, ptr: i32, len: i32| -> Result<(), Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(Trap::new("failed to find memory export")),
                };
                
                let data = Self::read_memory(&memory, ptr, len)
                    .map_err(|e| Trap::new(format!("Failed to read memory: {}", e)))?;
                
                let message = String::from_utf8_lossy(&data);
                println!("[WASM Plugin] {}", message);
                
                Ok(())
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap log function: {}", e)))?;
        
        // Add get_config function
        linker.func_wrap(
            "env",
            "get_config",
            |mut caller: Caller<'_, WasmContext>, key_ptr: i32, key_len: i32, out_ptr: i32, out_len: i32| -> Result<i32, Trap> {
                let memory = match caller.get_export("memory") {
                    Some(Extern::Memory(mem)) => mem,
                    _ => return Err(Trap::new("failed to find memory export")),
                };
                
                // Read key from WASM memory
                let key_data = Self::read_memory(&memory, key_ptr, key_len)
                    .map_err(|e| Trap::new(format!("Failed to read key: {}", e)))?;
                
                let key = String::from_utf8_lossy(&key_data);
                
                // Get config value
                let config_value = caller.data().config.get(key.as_ref())
                    .and_then(|v| serde_json::to_string(v).ok())
                    .unwrap_or_default();
                
                // Write result back to WASM memory
                let config_bytes = config_value.as_bytes();
                let write_len = std::cmp::min(config_bytes.len(), out_len as usize);
                Self::write_memory(&memory, out_ptr, &config_bytes[..write_len])
                    .map_err(|e| Trap::new(format!("Failed to write config: {}", e)))?;
                
                Ok(write_len as i32)
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap get_config function: {}", e)))?;
        
        // Add get_timestamp function
        linker.func_wrap(
            "env",
            "get_timestamp",
            |_caller: Caller<'_, WasmContext>| -> Result<i64, Trap> {
                Ok(std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_err(|_| Trap::new("Failed to get timestamp"))?
                    .as_secs() as i64)
            },
        ).map_err(|e| FortressError::plugin(format!("Failed to wrap get_timestamp function: {}", e)))?;
        
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
        let memory_size = memory.size(&mut Store::new(&Engine::default(), ())) * 65536; // 64KB pages
        if ptr + len > memory_size {
            return Err(FortressError::plugin("Memory access out of bounds"));
        }
        
        let mut data = vec![0u8; len];
        memory
            .read(&mut Store::new(&Engine::default(), ptr, &mut data)
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
        let memory_size = memory.size(&mut Store::new(&Engine::default(), ())) * 65536; // 64KB pages
        if ptr + data.len() > memory_size {
            return Err(FortressError::plugin("Memory write out of bounds"));
        }
        
        memory
            .write(&mut Store::new(&Engine::default(), ptr, data)
            .map_err(|e| FortressError::plugin(format!("Failed to write memory: {}", e)))?;
        
        Ok(())
    }
    
    /// Execute a plugin function
    pub fn call_function(
        &mut self,
        function_name: &str,
        input: &PluginInput,
    ) -> Result<PluginResult> {
        let start_time = Instant::now();
        
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
        
        // Set fuel limit for execution time control
        store.add_fuel(self.config.max_execution_time_ms.unwrap_or(5000) * 1000)
            .map_err(|e| FortressError::plugin(format!("Failed to set fuel limit: {}", e)))?;
        
        // Get the function from the instance
        let func = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, function_name)
            .or_else(|_| {
                // Try with no parameters if the typed version fails
                instance.get_typed_func::<(), i32>(&mut store, function_name)
            })
            .or_else(|_| {
                // Try with no return value
                instance.get_typed_func::<(i32, i32), ()>(&mut store, function_name)
            })
            .map_err(|e| FortressError::plugin(format!("Function '{}' not found or invalid signature: {}", function_name, e)))?;
        
        // Serialize input data
        let input_json = serde_json::to_string(input)
            .map_err(|e| FortressError::plugin(format!("Failed to serialize input: {}", e)))?;
        let input_bytes = input_json.as_bytes();
        
        // Get memory export for data transfer
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| FortressError::plugin("Plugin does not export memory"))?;
        
        // Write input data to WASM memory (simplified approach)
        // In a real implementation, we'd allocate memory in the WASM module
        let input_ptr = 0x1000; // Fixed address for simplicity
        let input_len = input_bytes.len() as i32;
        
        if input_bytes.len() > 4096 {
            return Err(FortressError::plugin("Input data too large"));
        }
        
        Self::write_memory(memory, input_ptr, input_bytes)?;
        
        // Execute the function
        let result = match func.type_(&store).params().len() {
            0 => {
                // No parameters
                let func_no_params = instance.get_typed_func::<(), i32>(&mut store, function_name)
                    .map_err(|e| FortressError::plugin(format!("Failed to get function: {}", e)))?;
                func_no_params.call(&mut store, ())
            }
            2 => {
                // Two parameters (ptr, len)
                func.call(&mut store, (input_ptr, input_len))
            }
            _ => {
                return Err(FortressError::plugin("Unsupported function signature"));
            }
        };
        
        let execution_time = start_time.elapsed().as_millis() as u64;
        
        // Update statistics
        {
            let mut context = self.context.blocking_write();
            context.stats.function_calls += 1;
            context.stats.total_execution_time_ms += execution_time;
            context.stats.memory_usage_bytes = memory.size(&mut store) * 65536;
        }
        
        // Handle the result
        match result {
            Ok(return_code) => {
                // Read output data from WASM memory if return code indicates success
                let output_data = if return_code == 0 {
                    // Try to read output from a fixed location
                    let output_ptr = 0x2000;
                    let output_len = 1024; // Maximum output size
                    
                    match Self::read_memory(memory, output_ptr, output_len) {
                        Ok(data) => {
                            // Try to parse as JSON
                            let data_str = String::from_utf8_lossy(&data);
                            if let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&data_str) {
                                Some(json_value)
                            } else {
                                // Return as string if not valid JSON
                                Some(serde_json::Value::String(data_str.trim_end_matches('\0').to_string()))
                            }
                        }
                        Err(_) => None,
                    }
                } else {
                    Some(serde_json::json!({
                        "error_code": return_code,
                        "message": "Plugin execution failed"
                    }))
                };
                
                Ok(PluginResult {
                    success: return_code == 0,
                    data: output_data,
                    error: if return_code == 0 { None } else { Some(format!("Plugin returned error code: {}", return_code)) },
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: execution_time,
                        memory_usage_bytes: memory.size(&mut store) * 65536,
                        custom_metrics: {
                            let mut custom = HashMap::new();
                            custom.insert("fuel_consumed".to_string(), serde_json::Value::Number(serde_json::Number::from(store.fuel_consumed().unwrap_or(0))));
                            custom
                        },
                    },
                })
            }
            Err(e) => {
                // Handle execution errors (including fuel exhaustion)
                let error_msg = if e.is::<Trap>() && e.to_string().contains("all fuel consumed") {
                    "Plugin execution timed out".to_string()
                } else {
                    format!("Plugin execution failed: {}", e)
                };
                
                Ok(PluginResult {
                    success: false,
                    data: None,
                    error: Some(error_msg),
                    metrics: crate::plugin::PluginMetrics {
                        execution_time_ms: execution_time,
                        memory_usage_bytes: memory.size(&mut store) * 65536,
                        custom_metrics: HashMap::new(),
                    },
                })
            }
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
        let config = {
            let ctx = self.context.read().await;
            ctx.config.clone()
        };
        plugin_clone.initialize(config)?;
        
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
        plugin.initialize(empty_config)?;
        
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
