#![deny(clippy::all)]

use napi_derive::napi;

/// Get Fortress version
#[napi]
pub fn get_version() -> String {
    "0.1.0".to_string()
}

/// Execute a simple test command
#[napi]
pub fn test_command(args: Vec<String>) -> napi::Result<String> {
    Ok(format!("Test command executed with {} args", args.len()))
}

/// Simple Fortress CLI wrapper
#[napi]
pub struct FortressCli {
    _private: (),
}

#[napi]
impl FortressCli {
    /// Create new CLI instance
    #[napi(constructor)]
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get version information
    #[napi]
    pub fn version(&self) -> napi::Result<String> {
        Ok("Fortress CLI v0.1.0 - NAPI Binding".to_string())
    }

    /// Get help information
    #[napi]
    pub fn help(&self) -> napi::Result<String> {
        Ok("Fortress CLI - NAPI Binding\nCommands:\n  version - Show version\n  help    - Show this help\n  test    - Run test command".to_string())
    }

    /// Execute test command
    #[napi]
    pub fn test(&self, args: Option<Vec<String>>) -> napi::Result<String> {
        let arg_count = args.as_ref().map_or(0, |a| a.len());
        Ok(format!(
            "Test command executed with {} arguments",
            arg_count
        ))
    }
}
