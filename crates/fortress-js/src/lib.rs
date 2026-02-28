//! JavaScript/TypeScript bindings for Fortress secure database system
//!
//! This module provides a WebAssembly interface to the Fortress core library,
//! allowing JavaScript and TypeScript developers to use Fortress's encryption
//! and key management capabilities directly from web browsers and Node.js.

use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::future_to_promise;
use js_sys::{Promise, Object, Array, Function, Reflect};
use serde_wasm_bindgen::{to_value, from_value};
use std::collections::HashMap;
use std::sync::Arc;

use fortress_core::prelude::*;
use fortress_core::{VERSION, build};

mod encryption;
mod key_management;
mod storage;
mod error;
mod config;
mod audit;
mod policy;
mod tenant;
mod utils;

use encryption::*;
use key_management::*;
use storage::*;
use error::*;
use config::*;
use audit::*;
use policy::*;
use tenant::*;
use utils::*;

// Initialize console error panic hook for better error messages
#[cfg(feature = "console_error_panic_hook")]
console_error_panic_hook::set_once();

/// Fortress JavaScript/TypeScript library
#[wasm_bindgen(start)]
pub fn main() {
    console_error_panic_hook::set_once();
    console_log!("Fortress WASM module initialized");
}

/// Get Fortress version information
#[wasm_bindgen(js_name = getVersion)]
pub fn get_version() -> String {
    VERSION.to_string()
}

/// Get Fortress build information
#[wasm_bindgen(js_name = getBuildInfo)]
pub fn get_build_info() -> Result<Object, JsValue> {
    let info = BuildInfo {
        timestamp: build::TIMESTAMP.to_string(),
        git_sha: build::GIT_SHA.to_string(),
        rust_version: build::RUST_VERSION.to_string(),
        target: build::TARGET.to_string(),
    };
    to_value(&info).map(|v| v.into())
}

/// List available encryption algorithms
#[wasm_bindgen(js_name = listAlgorithms)]
pub fn list_algorithms() -> Result<Array, JsValue> {
    let algorithms = vec![
        "aegis256",
        "chacha20poly1305", 
        "aes256gcm",
        "xchacha20poly1305",
        "blake3_encrypt",
        "hmacsha512_encrypt",
        "aes256ctr",
        "argon2id_encrypt",
        "composite_encrypt",
    ];
    
    let array = Array::new();
    for algorithm in algorithms {
        array.push(&JsValue::from_str(algorithm));
    }
    Ok(array)
}

/// Create a new Fortress configuration
#[wasm_bindgen(js_name = createConfig)]
pub fn create_config(profile: Option<String>) -> Result<FortressConfig, JsValue> {
    let config = match profile.as_deref() {
        Some("lightning") => Config::lightning(),
        Some("balanced") => Config::balanced(),
        Some("fortress") => Config::fortress(),
        Some("startup") => Config::startup(),
        Some("enterprise") => Config::enterprise(),
        _ => Config::default(),
    };
    Ok(FortressConfig::new(config))
}

/// Check if the current environment supports WebAssembly
#[wasm_bindgen(js_name = checkWasmSupport)]
pub fn check_wasm_support() -> bool {
    // Check if WebAssembly is supported
    web_sys::window()
        .and_then(|w| w.dyn_into::<web_sys::Window>().ok())
        .map(|w| {
            w.performance().is_some() && 
            w.crypto().is_some() &&
            w.document().is_some()
        })
        .unwrap_or(false)
}

/// Get supported features for the current environment
#[wasm_bindgen(js_name = getSupportedFeatures)]
pub fn get_supported_features() -> Result<Array, JsValue> {
    let features = vec![
        "encryption",
        "key_management",
        "storage",
        "configuration", 
        "audit_logging",
        "policy_engine",
        "multi_tenant",
        "error_handling",
        "webassembly",
    ];
    
    let array = Array::new();
    for feature in features {
        array.push(&JsValue::from_str(feature));
    }
    Ok(array)
}

/// Utility struct for build information
#[derive(serde::Serialize)]
struct BuildInfo {
    timestamp: String,
    git_sha: String,
    rust_version: String,
    target: String,
}

/// Global error handling
#[wasm_bindgen]
pub struct FortressError {
    error: fortress_core::error::FortressError,
}

#[wasm_bindgen]
impl FortressError {
    /// Get error message
    #[wasm_bindgen(getter, js_name = message)]
    pub fn message(&self) -> String {
        self.error.to_string()
    }

    /// Get error kind
    #[wasm_bindgen(getter, js_name = kind)]
    pub fn kind(&self) -> String {
        format!("{:?}", self.error.kind())
    }

    /// Get error code
    #[wasm_bindgen(getter, js_name = code)]
    pub fn code(&self) -> String {
        self.error.code().to_string()
    }

    /// Get error details as object
    #[wasm_bindgen(js_name = getDetails)]
    pub fn get_details(&self) -> Result<Object, JsValue> {
        let details = ErrorDetails {
            message: self.error.to_string(),
            kind: format!("{:?}", self.error.kind()),
            code: self.error.code().to_string(),
            source: self.error.source().map(|s| s.to_string()),
            is_retryable: self.error.is_retryable(),
            is_temporary: self.error.is_temporary(),
        };
        to_value(&details).map(|v| v.into())
    }

    /// Check if error is retryable
    #[wasm_bindgen(js_name = isRetryable)]
    pub fn is_retryable(&self) -> bool {
        self.error.is_retryable()
    }

    /// Check if error is temporary
    #[wasm_bindgen(js_name = isTemporary)]
    pub fn is_temporary(&self) -> bool {
        self.error.is_temporary()
    }
}

#[derive(serde::Serialize)]
struct ErrorDetails {
    message: String,
    kind: String,
    code: String,
    source: Option<String>,
    is_retryable: bool,
    is_temporary: bool,
}

/// Convert FortressError to JsValue
impl From<fortress_core::error::FortressError> for JsValue {
    fn from(error: fortress_core::error::FortressError) -> Self {
        let fortress_error = FortressError { error };
        JsValue::from(fortress_error)
    }
}

/// Convert Result<T, FortressError> to Result<T, JsValue>
pub trait IntoJsResult<T> {
    fn into_js_result(self) -> Result<T, JsValue>;
}

impl<T> IntoJsResult<T> for Result<T, fortress_core::error::FortressError> {
    fn into_js_result(self) -> Result<T, JsValue> {
        self.map_err(|e| JsValue::from(e))
    }
}

/// Console logging utilities
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn info(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn debug(s: &str);
}

macro_rules! console_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

macro_rules! console_error {
    ($($t:tt)*) => (error(&format_args!($($t)*).to_string()))
}

macro_rules! console_warn {
    ($($t:tt)*) => (warn(&format_args!($($t)*).to_string()))
}

macro_rules! console_info {
    ($($t:tt)*) => (info(&format_args!($($t)*).to_string()))
}

macro_rules! console_debug {
    ($($t:tt)*) => (debug(&format_args!($($t)*).to_string()))
}
