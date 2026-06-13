#[cfg(feature = "napi-build")]
extern crate napi_build;

fn main() {
    // Try to setup NAPI, but don't fail if it doesn't work
    // This allows the CLI to build even if Node.js integration has issues
    #[cfg(feature = "napi-build")]
    {
        match std::panic::catch_unwind(|| {
            napi_build::setup();
        }) {
            Ok(_) => {
                eprintln!("NAPI build completed successfully");
            }
            Err(_) => {
                eprintln!("Warning: NAPI build failed, but continuing...");
                eprintln!("This may limit Node.js integration functionality");
            }
        }
    }

    #[cfg(not(feature = "napi-build"))]
    {
        eprintln!("NAPI build skipped (napi-build feature disabled)");
    }
}
