@echo off
REM Build script for Fortress authentication WASM plugins (Windows)

echo Building Fortress authentication plugins...

REM Create output directory
if not exist "..\..\target\wasm-plugins" mkdir "..\..\target\wasm-plugins"

REM Build JWT plugin
echo Building JWT plugin...
cargo build --release --bin jwt_plugin --target wasm32-unknown-unknown
copy "..\..\target\wasm32-unknown-unknown\release\jwt_plugin.wasm" "..\..\target\wasm-plugins\"

REM Build OAuth plugin  
echo Building OAuth plugin...
cargo build --release --bin oauth_plugin --target wasm32-unknown-unknown
copy "..\..\target\wasm32-unknown-unknown\release\oauth_plugin.wasm" "..\..\target\wasm-plugins\"

REM Build SAML plugin
echo Building SAML plugin...
cargo build --release --bin saml_plugin --target wasm32-unknown-unknown
copy "..\..\target\wasm32-unknown-unknown\release\saml_plugin.wasm" "..\..\target\wasm-plugins\"

echo Plugin build complete!
echo Generated WASM files:
dir "..\..\target\wasm-plugins\"

REM Create plugin manifest
echo Creating plugin manifest...
(
echo {
echo   "version": "1.0.0",
echo   "plugins": {
echo     "jwt": {
echo       "wasm_file": "jwt_plugin.wasm",
echo       "supported_methods": ["JWT", "Basic"],
echo       "capabilities": {
echo         "can_generate_tokens": true,
echo         "can_validate_tokens": true,
echo         "can_refresh_tokens": true,
echo         "supports_mfa": false,
echo         "supports_rbac": true
echo       }
echo     },
echo     "oauth": {
echo       "wasm_file": "oauth_plugin.wasm", 
echo       "supported_methods": ["OAuth"],
echo       "capabilities": {
echo         "can_generate_tokens": true,
echo         "can_validate_tokens": true,
echo         "can_refresh_tokens": true,
echo         "supports_mfa": true,
echo         "supports_rbac": true
echo       }
echo     },
echo     "saml": {
echo       "wasm_file": "saml_plugin.wasm",
echo       "supported_methods": ["SAML"],
echo       "capabilities": {
echo         "can_generate_tokens": false,
echo         "can_validate_tokens": true,
echo         "can_refresh_tokens": false,
echo         "supports_mfa": true,
echo         "supports_rbac": true
echo       }
echo     }
echo   }
echo }
) > "..\..\target\wasm-plugins\plugin-manifest.json"

echo Plugin manifest created: ..\..\target\wasm-plugins\plugin-manifest.json
