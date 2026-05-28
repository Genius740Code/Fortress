
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