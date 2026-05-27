Critical (fix before any production use)
1. API routes lack JWT middleware — data/key endpoints are open
auth_middleware exists but is never applied to the Axum router in main.rs or server.rs. Handlers use OptionalTokenClaims, which reads extensions that nothing populates.


handlers.rs
Lines 167-171
pub async fn store_data(
    State(state): State<Arc<AppState>>,
    OptionalTokenClaims(claims): OptionalTokenClaims,
    Json(request): Json<StoreRequest>,
) -> ServerResult<Json<ApiResponse<StoreDataResponse>>> {
store_data, retrieve_data, list_data, and generate_key proceed without requiring auth. Tenant checks only run when both a tenant is set and a token is present — otherwise anyone can store/read keys and data. OpenAPI security(jwt_auth) does not match runtime behavior.

Fix: Apply global or per-route middleware that validates JWT and inserts TokenClaims, or switch sensitive handlers to RequiredTokenClaims.

2. Auth plugin management API is unauthenticated
AuthApiConfig::require_auth defaults to true but is never enforced on warp routes. with_auth_api_manager only injects the manager, not credentials.

Endpoints like plugin deploy/reload, set default auth method, and token operations are exposed without auth checks in create_auth_api_routes.

3. CORS misconfiguration on auth API

auth_api.rs
Lines 921-951
pub fn create_cors_config(_config: &AuthApiConfig) -> warp::cors::Builder {
    let cors = warp::cors()
        .allow_any_origin()
        // ...
        .allow_credentials(true);
allow_any_origin + allow_credentials(true) is invalid per the CORS spec and encourages unsafe client patterns. gRPC-compatible server also uses CorsLayer::permissive().

4. Broken “secure” password helper in memory_safety

memory_safety.rs
Lines 428-429
    pub fn verify_password_secure(password: &str, stored_hash: &str) -> bool {
        ConstantTimeOps::compare_strings_secure(password, stored_hash)
This compares plaintext password to hash string, not Argon2 verification. Tests pass only because they compare identical strings. Any caller using this instead of fortress-api-server/src/auth.rs Argon2 helpers has a critical auth bug.

5. JWT plugin uses fake crypto (SHA-256, not HMAC)

jwt_plugin.rs
Lines 226-233
fn create_signature(data: &str, secret: &str) -> Result<String, String> {
    // Simple HMAC-SHA256 implementation (in production, use proper crypto)
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    hasher.update(secret.as_bytes());
This is SHA256(data || secret), not HMAC-SHA256 or JWT signing. Tokens are forgeable if this plugin is used. Signature check uses != (timing leak). unsafe { get_timestamp() } and static mut USER_DATABASE add UB/thread-safety risk.

6. SIMD “encryption” is XOR — not AES

simd.rs
Lines 110-120
    /// Simulate AES encryption with AVX2 (placeholder implementation)
    unsafe fn simulate_aes_avx2(...) -> ... {
        // Simple XOR-based simulation for demonstration
        std::arch::x86_64::_mm256_xor_si256(data, key)
SimdEncryptor / AdaptiveEncryptor are exported from the public API. If SIMD is ever enabled in HighPerformanceEncryptor (currently disabled), or used directly, confidentiality is destroyed.

7. Hardcoded all-zero encryption keys in performance paths

mod.rs
Lines 147-157
                let key = &[0u8; 32]; // Default key
                self.algorithm.encrypt(data, key)
Same pattern in async_ops.rs. Predictable key material if these code paths run in production.

High
8. Default admin credentials (admin / admin123)

auth.rs
Lines 740-748
    pub fn with_default_admin() -> Self {
        // ...
        let admin_password = "admin123"; // Change this in production!
Only used in tests today (main uses InMemoryUserStore::new()), but easy to enable by mistake.

9. Secrets KV: silent master-key mishandling and storage fallback

secrets_kv.rs
Lines 162-167
        let master_key = if let Some(key_str) = &config.master_key {
            base64::engine::general_purpose::STANDARD.decode(key_str)
                .unwrap_or_else(|_| {
                    Self::generate_master_key()
                })
Invalid base64 → new random key without failing — existing secrets become undecryptable; operators may not notice.

File storage failure silently falls back to in-memory storage (data loss on restart). Duplicate Some("s3") match arms (one behind cloud-storage feature) is a logic/maintenance bug.

Master key generation uses rand::thread_rng() instead of getrandom/OsRng.

10. SecureKey is Serialize, Deserialize, and Clone

memory_safety.rs
Lines 71-74
#[derive(Debug, Clone, ZeroizeOnDrop, Serialize, Deserialize)]
pub struct SecureKey {
    data: Vec<u8>,
Serialization can leak key material into logs, caches, or JSON APIs. Clone duplicates sensitive bytes in memory.

11. Security regression tests are stubs (always pass)

security_regression_tests.rs
Lines 27-29
        let codebase_safe = true; // This would be determined by actual code scanning
        
        assert!(codebase_safe, "Codebase should not contain placeholder authentication patterns");
Tests for hardcoded credentials, thread_rng, unwrap in production, etc. never scan the codebase. CI can be green while real issues remain (including admin123 and widespread thread_rng).

12. GraphQL “SQL injection” filters are brittle
Regex/blocklist checks on GraphQL/SQL strings (e.g. rejecting ;, ', select) cause false positives and are not a substitute for parameterized queries or an allowlisted query layer. Do not treat this as real SQLi protection.

Medium
13. TRNG module overclaims entropy
Software timing (CPU loops, TCP connect to 8.8.8.8, etc.) with inflated entropy_bits estimates. Fallback to getrandom is good, but labeling output as “true random” for key generation is misleading. Prefer getrandom/OsRng directly for crypto (as aes256gcm_wrapper already does).

14. Widespread rand::thread_rng() for secrets/keys
Used in secrets_kv, dynamic_secrets, kubernetes_auth, database_secrets, auth.rs (Argon2 salt — acceptable for salt but OsRng is preferred), etc. Not catastrophic for salts, but inconsistent with stated security goals.

15. Refresh tokens stored in memory without visible expiry
InMemoryUserStore stores refresh tokens in a HashMap with no TTL/eviction in the snippet reviewed — stolen refresh tokens work until restart.

16. Auth API + plugin surface area
Unauthenticated plugin deploy/reload is effectively remote code loading if plugins are dynamic libraries/WASM without strict sandboxing review.

ye