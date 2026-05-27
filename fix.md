 8
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