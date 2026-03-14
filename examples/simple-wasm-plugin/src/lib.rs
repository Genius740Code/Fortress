//! Simple WebAssembly Plugin Example
//!
//! This is a minimal, working WebAssembly plugin that demonstrates
//! the basic plugin interface with simple functionality.

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;

// Plugin metadata that Fortress will read
#[no_mangle]
pub static PLUGIN_METADATA: &str = r#"{
  "name": "simple-wasm-plugin",
  "version": "0.1.0",
  "description": "A simple WebAssembly plugin that provides basic text processing",
  "author": "Fortress Team",
  "license": "MIT",
  "capabilities": ["text_processing", "data_validation"],
  "entry_point": "process_text"
}"#;

/// Simple text processing request
#[derive(Debug, Serialize, Deserialize)]
pub struct TextProcessingRequest {
    pub text: String,
    pub operation: String, // "uppercase", "lowercase", "reverse", "count"
}

/// Text processing response
#[derive(Debug, Serialize, Deserialize)]
pub struct TextProcessingResponse {
    pub result: String,
    pub original_length: usize,
    pub processed_length: usize,
    pub operation: String,
}

/// Plugin state
pub struct SimplePlugin {
    request_count: u64,
}

impl SimplePlugin {
    pub fn new() -> Self {
        Self {
            request_count: 0,
        }
    }
}

/// Process text based on operation
fn process_text(text: &str, operation: &str) -> String {
    match operation {
        "uppercase" => text.to_uppercase(),
        "lowercase" => text.to_lowercase(),
        "reverse" => text.chars().rev().collect(),
        "count" => text.len().to_string(),
        "trim" => text.trim().to_string(),
        _ => format!("Unknown operation: {}", operation),
    }
}

// Plugin entry point - creates a new plugin instance
#[no_mangle]
pub extern "C" fn create_plugin() -> *mut SimplePlugin {
    let plugin = Box::new(SimplePlugin::new());
    Box::into_raw(plugin)
}

// Plugin cleanup
#[no_mangle]
pub extern "C" fn destroy_plugin(plugin: *mut SimplePlugin) {
    if !plugin.is_null() {
        unsafe {
            let _ = Box::from_raw(plugin);
        }
    }
}

// Main text processing function
#[no_mangle]
pub extern "C" fn process_text(
    plugin: *mut SimplePlugin,
    request_ptr: *const u8,
    request_len: usize,
) -> *mut u8 {
    if plugin.is_null() || request_ptr.is_null() {
        return std::ptr::null_mut();
    }

    // Get plugin instance
    let plugin = unsafe { &mut *plugin };
    plugin.request_count += 1;

    // Read request from memory
    let request_bytes = unsafe {
        std::slice::from_raw_parts(request_ptr, request_len)
    };
    
    let request: TextProcessingRequest = match serde_json::from_slice(request_bytes) {
        Ok(req) => req,
        Err(_) => {
            // Return error response
            let error_response = TextProcessingResponse {
                result: "Invalid request format".to_string(),
                original_length: 0,
                processed_length: 0,
                operation: "error".to_string(),
            };
            let response_bytes = serde_json::to_vec(&error_response).unwrap_or_default();
            let ptr = response_bytes.as_ptr();
            std::mem::forget(response_bytes);
            return ptr as *mut u8;
        }
    };

    // Process the text
    let processed_text = process_text(&request.text, &request.operation);
    
    // Create response
    let response = TextProcessingResponse {
        result: processed_text,
        original_length: request.text.len(),
        processed_length: processed_text.len(),
        operation: request.operation.clone(),
    };

    // Convert response to bytes and return pointer
    let response_bytes = match serde_json::to_vec(&response) {
        Ok(bytes) => bytes,
        Err(_) => {
            // Fallback response
            let fallback = TextProcessingResponse {
                result: "Serialization error".to_string(),
                original_length: request.text.len(),
                processed_length: 0,
                operation: request.operation,
            };
            serde_json::to_vec(&fallback).unwrap_or_default()
        }
    };

    let ptr = response_bytes.as_ptr();
    std::mem::forget(response_bytes);
    ptr as *mut u8
}

// Get plugin statistics
#[no_mangle]
pub extern "C" fn get_stats(plugin: *mut SimplePlugin) -> *mut u8 {
    if plugin.is_null() {
        return std::ptr::null_mut();
    }

    let plugin = unsafe { &*plugin };
    
    let stats = serde_json::json!({
        "request_count": plugin.request_count,
        "timestamp": Utc::now(),
        "plugin_name": "simple-wasm-plugin"
    });

    let stats_bytes = serde_json::to_vec(&stats).unwrap_or_default();
    let ptr = stats_bytes.as_ptr();
    std::mem::forget(stats_bytes);
    ptr as *mut u8
}

// Free memory allocated by plugin
#[no_mangle]
pub extern "C" fn free_memory(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        unsafe {
            let _ = Vec::from_raw_parts(ptr, len, len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_text() {
        assert_eq!(process_text("hello", "uppercase"), "HELLO");
        assert_eq!(process_text("WORLD", "lowercase"), "world");
        assert_eq!(process_text("rust", "reverse"), "tsur");
        assert_eq!(process_text("testing", "count"), "7");
    }

    #[test]
    fn test_plugin_creation() {
        let plugin = SimplePlugin::new();
        assert_eq!(plugin.request_count, 0);
    }

    #[test]
    fn test_serialization() {
        let request = TextProcessingRequest {
            text: "Hello World".to_string(),
            operation: "uppercase".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: TextProcessingRequest = serde_json::from_str(&json).unwrap();
        
        assert_eq!(parsed.text, "Hello World");
        assert_eq!(parsed.operation, "uppercase");
    }
}
