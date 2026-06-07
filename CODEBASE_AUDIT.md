# Fortress Codebase Audit Summary

* **Total Issues Found:** 58
* **Critical Issues Count:** 11
* **High Issues Count:** 18
* **Medium Issues Count:** 19
* **Low Issues Count:** 10

## Top 10 Most Important Fixes

1. **Authentication Bypass via Unverified JWTs (`auth.rs`):** The OIDC `validate_id_token` decodes JWT payloads but skips cryptographic signature verification entirely, allowing trivial authentication bypass.
2. **Admin & Security Endpoints Unauthenticated (`main.rs`):** `/security/events`, `/security/blocked-requests`, `/metrics`, and `/graphql` are on `public_routes` with no authentication, leaking internal system structure and security telemetry to attackers.
3. **Denial of Service via `unwrap()` in API Server/Core:** Ubiquitous usage of `unwrap()` across production code allows malicious or malformed inputs to panic the entire server thread, causing immediate DoS.
4. **Denial of Service via `InMemoryUserStore` Write Lock (`auth.rs`):** The write lock on the user store is held during the 100ms+ Argon2 hashing phase, completely starving all other concurrent authentications.
5. **Admin Endpoint Ciphertext & Key Exposure (`handlers.rs`):** `admin_list_data` returns raw `StorageRecord` containing both the ciphertext and the raw `key_id`, allowing a compromised admin token to attempt key extraction.
6. **Incomplete Soft Delete Implementation Panics (`handlers.rs`):** The soft delete mechanism uses `todo!()`, meaning any authenticated user triggering it will panic and crash the Tokio worker thread.
7. **PKCE Bypass via Incorrect Base64 (`auth.rs`):** PKCE `code_challenge` uses standard base64 instead of URL-safe base64, breaking the OAuth2 handshake and defeating CSRF/code-injection protections.
8. **Memory Corruption Risks in SIMD Encryptors (`performance/simd.rs`):** `unsafe` blocks lack comprehensive bounds checking and CPU feature gating validation, risking severe memory corruption and potential RCE.
9. **Missing Implementation in Dynamic Secrets Engine (`graphql/query.rs`):** The `DynamicSecretsEngine` is completely lacking a `read` method, breaking the expected workflow for secret retrieval.
10. **Global DDoS Counter TOCTOU Race (`middleware.rs`):** The global rate limiter has a Time-Of-Check to Time-Of-Use race condition during bucket reset, resulting in lost request counts and bypassing rate limits.

## Overall Codebase Score

* **Security: 3/10** - Critical auth bypasses, unauthenticated admin routes, exposed metrics, and broken PKCE severely degrade the security posture. 
* **Performance: 5/10** - Severe DoS vectors exist (e.g., holding write locks during Argon2 hashing, missing pagination leading to RAM exhaustion).
* **Architecture: 5/10** - The API architecture mixes public and private routes poorly. Core system limits flexibility due to tight coupling.
* **Maintainability: 4/10** - Numerous `todo!()` macros, hardcoded fake metrics, and incomplete features create high technical debt.
* **Scalability: 4/10** - Global locks, unbounded cache growth, and linear O(n) lookups (e.g., `get_user`) prevent horizontal scaling.
* **Code Quality: 4/10** - Widespread `unwrap()`, unused parameters, and masking of raw errors reflect poor code quality.
* **Gameplay/Design Robustness: N/A** - (Database System context; robustness of data flows is poor due to panics).

---

# Audit Details

## Security Issues

### Title: Authentication Bypass via Unverified JWTs
**Severity:** Critical
**Category:** Security
**Location:** `crates/fortress-api-server/src/auth.rs`, lines 445–509
**Problem:** The OIDC `validate_id_token` method decodes the JWT payload with base64 but never validates the cryptographic signature.
**Why It Matters:** An attacker can craft any JWT token with arbitrary claims (including elevated roles) and it will be accepted as valid.
**Example Scenario:** An attacker creates a token claiming to be `admin` with a fake signature. The server decodes it and grants admin access.
**Recommended Fix:** Use a proper OIDC library that fetches JWKS and verifies signatures. Never accept unsigned or unverified ID tokens.
**Confidence:** High

### Title: Admin & Metrics Endpoints Exposed Publicly
**Severity:** Critical
**Category:** Security
**Location:** `crates/fortress-api-server/src/main.rs`, lines 69-73
**Problem:** `/security/events`, `/security/blocked-requests`, `/metrics`, and `/graphql` are on `public_routes` with no JWT middleware applied.
**Why It Matters:** Any unauthenticated client can query which IPs are blocked, what security events occurred, internal memory layouts, and full GraphQL schemas.
**Example Scenario:** An attacker reads `/security/events` to verify their evasion techniques are working and uses `/metrics` to plan a resource exhaustion attack.
**Recommended Fix:** Move these routes inside `protected_routes`, requiring admin roles.
**Confidence:** High

### Title: PKCE `code_challenge` uses Standard Base64
**Severity:** Critical
**Category:** Security
**Location:** `crates/fortress-api-server/src/auth.rs`, lines 302-304
**Problem:** `general_purpose::STANDARD.encode(challenge_bytes)` is used instead of URL-safe encoding.
**Why It Matters:** RFC 7636 requires base64url encoding without padding. This breaks the OAuth2 handshake, defeating CSRF protections.
**Recommended Fix:** Use `general_purpose::URL_SAFE_NO_PAD.encode(challenge_bytes)`.
**Confidence:** High

### Title: IP Spoofing via X-Forwarded-For
**Severity:** High
**Category:** Security
**Location:** `crates/fortress-api-server/src/middleware.rs`, lines 950-963
**Problem:** The middleware trusts the `X-Forwarded-For` header to determine the client IP without verifying if the request came from a trusted reverse proxy.
**Why It Matters:** An attacker can forge this header to bypass IP-based rate limiting or pretend to originate from an internal IP.
**Recommended Fix:** Only trust `X-Forwarded-For` if the direct TCP connection source is a known trusted proxy.
**Confidence:** High

### Title: Default Wildcard CORS with Credentials
**Severity:** High
**Category:** Security
**Location:** `config.rs` (lines 174-192), `main.rs` (line 123)
**Problem:** CORS is configured to allow `*` combined with `allow_credentials(true)`. Origin parsing is also broken.
**Why It Matters:** Any website can make cross-origin requests bearing credentials (cookies/tokens), leading to severe Cross-Site Request Forgery (CSRF) vulnerabilities.
**Recommended Fix:** Never combine `*` with credentials. Parse allowed origins correctly into a `Vec<HeaderValue>`.
**Confidence:** High

### Title: Server Panic via Unhandled `unwrap()` calls
**Severity:** Critical
**Category:** Security
**Location:** Widespread (e.g., `handlers.rs`, `security_developer_guide.rs`)
**Problem:** The codebase relies on `.unwrap()` on `Option` and `Result` types. 
**Why It Matters:** An attacker can craft requests that intentionally trigger these panics, bringing down the entire server or worker threads (DoS).
**Recommended Fix:** Replace all instances of `.unwrap()` with proper error matching returning HTTP 400 or 500.
**Confidence:** High

### Title: Unsafe SIMD Memory Access
**Severity:** Critical
**Category:** Security
**Location:** `crates/fortress-core/src/performance/simd.rs`, lines 32, 55
**Problem:** `unsafe fn encrypt_avx2` and `encrypt_avx512` lack bounds checking on the input `plaintext` slice lengths.
**Why It Matters:** Could cause out-of-bounds reads/writes leading to memory corruption or Remote Code Execution (RCE).
**Recommended Fix:** Add strict length assertions before entering the `unsafe` block.
**Confidence:** Medium

## Performance Issues

### Title: Write Lock Held During Argon2 Hashing
**Severity:** Critical
**Category:** Performance / Logic
**Location:** `crates/fortress-api-server/src/auth.rs`, lines 854-906
**Problem:** `InMemoryUserStore::authenticate` acquires a write lock on `self.users`, then performs an Argon2 hash verification.
**Why It Matters:** Argon2 is memory-hard and takes 100ms+. Holding a write lock blocks all other concurrent authentication attempts, allowing a trivial single-request DoS.
**Example Scenario:** An attacker sends 10 login requests per second. The entire server's auth pipeline locks up, denying legitimate users.
**Recommended Fix:** Read the password hash under a read lock, drop the lock, verify, and re-acquire a write lock only if updating login attempts.
**Confidence:** High

### Title: Global DDoS Counter TOCTOU Race
**Severity:** High
**Category:** Performance / Logic
**Location:** `crates/fortress-api-server/src/middleware.rs`, lines 343-358
**Problem:** The DDoS counter has a Time-Of-Check to Time-Of-Use race condition during bucket reset using `Relaxed` ordering.
**Why It Matters:** Concurrent requests can reset the bucket simultaneously, losing counts and allowing attackers to exceed rate limits.
**Recommended Fix:** Use `compare_exchange` to atomically reset the bucket or use stronger memory ordering (`AcqRel`).
**Confidence:** High

### Title: `list_data` Loads All Records into RAM
**Severity:** High
**Category:** Performance
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 498-584
**Problem:** Calls `batch_get(&keys)` for all matching keys before filtering in memory, ignoring pagination.
**Why It Matters:** A single un-filtered request on a large database will load millions of records into RAM, triggering OOM.
**Recommended Fix:** Push filtering to the storage layer and enforce hard server-side pagination limits.
**Confidence:** High

### Title: Rate Limiter Cleanup Never Called
**Severity:** Medium
**Category:** Performance
**Location:** `crates/fortress-api-server/src/middleware.rs`, lines 657-682
**Problem:** The `cleanup()` method for rate limiting `DashMap` entries is never called in any background task.
**Why It Matters:** The map will grow infinitely as unique IPs connect, causing a slow memory leak and eventual OOM.
**Recommended Fix:** Spawn a background Tokio task that calls `rate_limiter.cleanup()` periodically.
**Confidence:** High

## Logic Errors

### Title: `todo!()` Panics the Server on Soft Delete
**Severity:** Critical
**Category:** Logic
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 456-458
**Problem:** The soft delete path literally calls `todo!("Implement proper soft delete...");`.
**Why It Matters:** Any user sending `{"soft_delete": true}` will panic the Tokio thread and drop the connection.
**Recommended Fix:** Return `HTTP 501 Not Implemented` gracefully instead of using `todo!()`.
**Confidence:** High

### Title: `generate_key` Returns Wrong Key ID
**Severity:** High
**Category:** Logic
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 644-671
**Problem:** The key is stored under one randomly generated `Uuid::new_v4()` but a different `Uuid` is returned in the API response.
**Why It Matters:** The client can never retrieve the key they just created, breaking the entire key management flow.
**Recommended Fix:** Store the UUID in a variable and use it for both storage and the response.
**Confidence:** High

### Title: Admin Users Blocked from All Tenants
**Severity:** High
**Category:** Logic
**Location:** `crates/fortress-api-server/src/auth.rs`, lines 817-822
**Problem:** `has_tenant_access` returns `false` if the user has no `tenant_id`. 
**Why It Matters:** Bootstrapped admin users without a specific tenant ID will silently fail access checks.
**Recommended Fix:** explicitly allow access if the user possesses the `admin` role.
**Confidence:** High

## Architecture Problems

### Title: Admin List Data Exposes Ciphertext and Key IDs
**Severity:** Critical
**Category:** Architecture
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 1895-1920
**Problem:** `admin_list_data` returns the raw `StorageRecord` containing `data: Vec<u8>` (ciphertext) and `key_id`.
**Why It Matters:** An attacker with a compromised admin token can retrieve the exact ciphertexts and knowing the `key_id` simplifies targeted offline decryption attempts.
**Recommended Fix:** Strip sensitive fields (ciphertext bytes, keys) from bulk admin endpoints.
**Confidence:** High

### Title: In-Memory Storage Default Anti-Pattern
**Severity:** Informational
**Category:** Architecture
**Location:** `server.rs:108`, `main.rs:148`
**Problem:** The key manager and user store default to in-memory persistence.
**Why It Matters:** A server restart destroys all encryption keys, making the entire database permanently unrecoverable.

## Code Quality Issues

### Title: Hardcoded Health Check and Security Metrics
**Severity:** Medium
**Category:** Code Quality
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 787-833, 851-970
**Problem:** Health check endpoints return fictional performance metrics (e.g., `avg_response_time_ms: 15`) and hardcoded fake security events.
**Why It Matters:** Operations teams integrating these endpoints for alerting will be misled.
**Recommended Fix:** Wire the endpoints to actual runtime metrics and security event logs.
**Confidence:** High

### Title: Full SQL Logged in Plaintext
**Severity:** High
**Category:** Code Quality
**Location:** `crates/fortress-api-server/src/handlers.rs`, lines 1459-1462
**Problem:** `execute_query` logs the complete `request.sql` at `info` level.
**Why It Matters:** May leak passwords, tokens, or PII embedded in query literals to log aggregation systems.
**Recommended Fix:** Redact SQL queries or log at `trace` level only.
**Confidence:** High

### Title: Missing JWT Secret Length Enforcement
**Severity:** High
**Category:** Code Quality
**Location:** `crates/fortress-api-server/src/config.rs`, lines 150-155
**Problem:** Validation checks maximum length but not minimum length. A 1-character JWT secret would pass validation.
**Why It Matters:** Weak JWT secrets are easily cracked offline.
**Recommended Fix:** Enforce a minimum length of 32 bytes for the JWT secret.
**Confidence:** High
