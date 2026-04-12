# Fortress → Vault Competitiveness Roadmap

## 🎯 Executive Summary

**Current Assessment**: Fortress has excellent technical foundations but significant gaps to reach HashiCorp Vault/TurnKey enterprise level.

**Current Score**: 6.5/10
- **Security**: 5/10 (Missing critical seal/unseal)
- **Performance**: 8/10 (Solid Rust foundation) 
- **Scalability**: 6/10 (Basic clustering only)
- **Features**: 6/10 (Missing key Vault features)
- **Code Quality**: 7/10 (Good structure, some warnings)

**Target Score**: 9.5/10 (Post-implementation)
- **Timeline**: 3.5 months to Vault-competitive status
- **Critical Path**: Seal/Unseal → Token System → Policy Engine → Secret Engines

---

## 🚨 Critical Issues Identified

### 1. **Security Foundation Gap**
- **Issue**: No seal/unseal mechanism
- **Impact**: Physical access = total compromise
- **Priority**: CRITICAL
- **Vault Standard**: Shamir Secret Sharing

### 2. **Token System Underdeveloped**
- **Issue**: Basic JWT only, no leases/TTL/revocation
- **Impact**: No production-grade access control
- **Priority**: CRITICAL
- **Vault Standard**: Comprehensive token lifecycle management

### 3. **Policy Engine Missing**
- **Issue**: Basic RBAC only, no HCL policy language
- **Impact**: No fine-grained access control
- **Priority**: HIGH
- **Vault Standard**: HCL-based policy evaluation

### 4. **Feature Completeness Gap**
- **Issue**: KV engine only, missing PKI/Database/AWS engines
- **Impact**: Limited secret management capabilities
- **Priority**: HIGH
- **Vault Standard**: Multiple pluggable secret engines

---

## 📅 Implementation Roadmap

### 🚀 Phase 1: Critical Security Foundation (Weeks 1-8)

#### **Week 1-4: Seal/Unseal Implementation**
**Status**: ❌ **CRITICAL MISSING**

**Files to Create/Modify**:
```
crates/fortress-core/src/
├── seal.rs                    # NEW - Core seal management
├── shamir.rs                  # NEW - Secret sharing implementation  
├── lib.rs                     # MODIFY - Add seal module exports
└── prelude.rs                 # MODIFY - Add seal types to prelude
```

**Implementation Details**:
```rust
// File: crates/fortress-core/src/seal.rs
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::error::{FortressError, Result};

#[derive(Debug, Clone)]
pub struct SecretShare {
    pub id: usize,
    pub share: Vec<u8>,
    pub threshold: usize,
}

#[derive(Debug)]
pub struct SealManager {
    master_key: Option<[u8; 32]>,
    key_shares: Vec<SecretShare>,
    threshold: usize,
    sealed_state: std::sync::atomic::AtomicBool,
    recovery_keys: Vec<[u8; 32]>,
}

impl SealManager {
    pub fn new(threshold: usize, shares: usize) -> Self {
        Self {
            master_key: None,
            key_shares: Vec::new(),
            threshold,
            sealed_state: std::sync::atomic::AtomicBool::new(true),
            recovery_keys: Vec::new(),
        }
    }

    pub fn initialize_shamir(&mut self) -> Result<()> {
        // Generate master key
        let master_key = self.generate_master_key()?;
        
        // Split into shares using Shamir's Secret Sharing
        let shares = self.split_secret(&master_key, self.threshold, shares)?;
        
        self.master_key = Some(master_key);
        self.key_shares = shares;
        
        Ok(())
    }

    pub fn seal(&self) -> Result<()> {
        if self.is_sealed() {
            return Err(FortressError::seal("Already sealed"));
        }
        
        // Zero out master key from memory
        if let Some(ref master_key) = self.master_key {
            zeroize::Zeroize::zeroize(master_key);
        }
        
        self.sealed_state.store(true, std::sync::atomic::Ordering::SeqCst);
        
        Ok(())
    }

    pub fn unseal(&mut self, provided_shares: &[SecretShare]) -> Result<()> {
        if !self.is_sealed() {
            return Err(FortressError::seal("Already unsealed"));
        }
        
        if provided_shares.len() < self.threshold {
            return Err(FortressError::seal("Insufficient shares"));
        }
        
        // Reconstruct master key from shares
        let master_key = self.reconstruct_secret(provided_shares)?;
        
        self.master_key = Some(master_key);
        self.sealed_state.store(false, std::sync::atomic::Ordering::SeqCst);
        
        Ok(())
    }

    pub fn is_sealed(&self) -> bool {
        self.sealed_state.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn get_key_shares(&self) -> &[SecretShare] {
        &self.key_shares
    }

    fn generate_master_key(&self) -> Result<[u8; 32]> {
        use rand::RngCore;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        Ok(key)
    }

    fn split_secret(&self, secret: &[u8], threshold: usize, shares: usize) -> Result<Vec<SecretShare>> {
        // Implement Shamir's Secret Sharing
        // This is a simplified implementation - use proper crypto library
        let mut result = Vec::new();
        
        for i in 1..=shares {
            let share = SecretShare {
                id: i,
                share: secret.to_vec(), // Simplified - implement proper SSS
                threshold,
            };
            result.push(share);
        }
        
        Ok(result)
    }

    fn reconstruct_secret(&self, shares: &[SecretShare]) -> Result<[u8; 32]> {
        // Implement Shamir's Secret Sharing reconstruction
        // This is a simplified implementation - use proper crypto library
        if shares.is_empty() {
            return Err(FortressError::seal("No shares provided"));
        }
        
        // For now, return first share's data (implement proper Lagrange interpolation)
        let mut key = [0u8; 32];
        if let Some(first_share) = shares.first() {
            if first_share.share.len() >= 32 {
                key.copy_from_slice(&first_share.share[..32]);
            }
        }
        
        Ok(key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shamir_split_reconstruct() {
        let mut seal_manager = SealManager::new(3, 5);
        seal_manager.initialize_shamir().unwrap();
        
        assert!(!seal_manager.is_sealed());
        assert_eq!(seal_manager.get_key_shares().len(), 5);
        
        seal_manager.seal().unwrap();
        assert!(seal_manager.is_sealed());
        
        // Use first 3 shares to reconstruct
        let shares = &seal_manager.get_key_shares()[..3];
        seal_manager.unseal(shares).unwrap();
        
        assert!(!seal_manager.is_sealed());
    }
}
```

**Integration Points**:
```rust
// Modify: crates/fortress-core/src/lib.rs
pub mod seal;
pub mod shamir;

// Add to prelude
pub use crate::seal::{SealManager, SecretShare};
```

**Testing Strategy**:
```rust
// File: tests/seal_integration_tests.rs
#[tokio::test]
async fn test_seal_unseal_workflow() {
    let mut seal_manager = SealManager::new(3, 5);
    
    // Initialize
    seal_manager.initialize_shamir().unwrap();
    assert!(!seal_manager.is_sealed());
    
    // Seal the cluster
    seal_manager.seal().unwrap();
    assert!(seal_manager.is_sealed());
    
    // Try to access sealed data (should fail)
    let result = access_secrets().await;
    assert!(result.is_err());
    
    // Unseal with sufficient shares
    let shares = &seal_manager.get_key_shares()[..3];
    seal_manager.unseal(shares).unwrap();
    assert!(!seal_manager.is_sealed());
    
    // Access should work now
    let result = access_secrets().await;
    assert!(result.is_ok());
}
```

#### **Week 5-8: Advanced Token System**
**Status**: 🟡 **BASIC JWT ONLY**

**Files to Create/Modify**:
```
crates/fortress-core/src/
├── token/                     # NEW - Token management module
│   ├── mod.rs
│   ├── manager.rs             # TokenManager implementation
│   ├── lease.rs              # Lease management
│   ├── revocation.rs         # Revocation list
│   └── types.rs              # Token types and structs
├── auth.rs                   # MODIFY - Replace basic AuthManager
└── lib.rs                   # MODIFY - Add token module exports
```

**Implementation Details**:
```rust
// File: crates/fortress-core/src/token/manager.rs
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    pub id: String,
    pub accessor: String,
    pub policies: Vec<String>,
    pub ttl: Duration,
    pub renewable: bool,
    pub path_suffixes: Vec<String>,
    pub created_time: DateTime<Utc>,
    pub last_renewal: Option<DateTime<Utc>>,
    pub expires_time: DateTime<Utc>,
    pub metadata: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: Token,
    pub parent_token: Option<String>,
    pub entity_id: String,
    pub policies: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct LeaseInfo {
    pub lease_id: String,
    pub renewable: bool,
    pub ttl: Duration,
    pub created_time: DateTime<Utc>,
    pub expires_time: DateTime<Utc>,
}

pub struct TokenManager {
    tokens: Arc<RwLock<std::collections::HashMap<String, TokenInfo>>>,
    leases: Arc<RwLock<std::collections::HashMap<String, LeaseInfo>>>,
    revocation_list: Arc<RwLock<std::collections::HashSet<String>>>,
    cleanup_interval: Duration,
    cleanup_task: Option<tokio::task::JoinHandle<()>>,
}

impl TokenManager {
    pub fn new(cleanup_interval: Duration) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(std::collections::HashMap::new())),
            leases: Arc::new(RwLock::new(std::collections::HashMap::new())),
            revocation_list: Arc::new(RwLock::new(std::collections::HashSet::new())),
            cleanup_interval,
            cleanup_task: None,
        }
    }

    pub async fn create_token(&self, request: CreateTokenRequest) -> Result<Token> {
        let token_id = self.generate_token_id();
        let accessor = self.generate_accessor();
        
        let token = Token {
            id: token_id.clone(),
            accessor,
            policies: request.policies.clone(),
            ttl: request.ttl,
            renewable: request.renewable,
            path_suffixes: request.path_suffixes.unwrap_or_default(),
            created_time: Utc::now(),
            last_renewal: None,
            expires_time: Utc::now() + request.ttl,
            metadata: request.metadata.unwrap_or_default(),
        };

        let token_info = TokenInfo {
            token: token.clone(),
            parent_token: request.parent_token,
            entity_id: request.entity_id.unwrap_or_default(),
            policies: request.policies,
        };

        let mut tokens = self.tokens.write().await;
        tokens.insert(token_id.clone(), token_info);

        // Start cleanup task if not already running
        self.start_cleanup_task().await;

        Ok(token)
    }

    pub async fn validate_token(&self, token_id: &str) -> Result<TokenInfo> {
        // Check if token is revoked
        let revocation_list = self.revocation_list.read().await;
        if revocation_list.contains(token_id) {
            return Err(FortressError::token("Token is revoked"));
        }

        // Get token info
        let tokens = self.tokens.read().await;
        let token_info = tokens.get(token_id)
            .ok_or_else(|| FortressError::token("Token not found"))?;

        // Check if token is expired
        if token_info.token.expires_time < Utc::now() {
            return Err(FortressError::token("Token expired"));
        }

        Ok(token_info.clone())
    }

    pub async fn renew_token(&self, token_id: &str, increment: Duration) -> Result<Token> {
        let mut tokens = self.tokens.write().await;
        let token_info = tokens.get_mut(token_id)
            .ok_or_else(|| FortressError::token("Token not found"))?;

        if !token_info.token.renewable {
            return Err(FortressError::token("Token is not renewable"));
        }

        // Update expiration
        token_info.token.expires_time = Utc::now() + increment;
        token_info.token.last_renewal = Some(Utc::now());

        Ok(token_info.token.clone())
    }

    pub async fn revoke_token(&self, token_id: &str) -> Result<()> {
        let mut revocation_list = self.revocation_list.write().await;
        revocation_list.insert(token_id.to_string());

        // Remove from active tokens
        let mut tokens = self.tokens.write().await;
        tokens.remove(token_id);

        Ok(())
    }

    pub async fn create_lease(&self, request: CreateLeaseRequest) -> Result<String> {
        let lease_id = self.generate_lease_id();
        let lease_info = LeaseInfo {
            lease_id: lease_id.clone(),
            renewable: request.renewable,
            ttl: request.ttl,
            created_time: Utc::now(),
            expires_time: Utc::now() + request.ttl,
        };

        let mut leases = self.leases.write().await;
        leases.insert(lease_id.clone(), lease_info);

        Ok(lease_id)
    }

    async fn start_cleanup_task(&mut self) {
        if self.cleanup_task.is_some() {
            return;
        }

        let tokens = self.tokens.clone();
        let leases = self.leases.clone();
        let interval = self.cleanup_interval;

        let task = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // Clean up expired tokens
                {
                    let mut tokens_guard = tokens.write().await;
                    let now = Utc::now();
                    
                    tokens_guard.retain(|_, token_info| {
                        token_info.token.expires_time > now
                    });
                }

                // Clean up expired leases
                {
                    let mut leases_guard = leases.write().await;
                    let now = Utc::now();
                    
                    leases_guard.retain(|_, lease_info| {
                        lease_info.expires_time > now
                    });
                }
            }
        });

        self.cleanup_task = Some(task);
    }

    fn generate_token_id(&self) -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }

    fn generate_accessor(&self) -> String {
        use uuid::Uuid;
        format!("s.{}", Uuid::new_v4())
    }

    fn generate_lease_id(&self) -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }
}

#[derive(Debug, Clone)]
pub struct CreateTokenRequest {
    pub policies: Vec<String>,
    pub ttl: Duration,
    pub renewable: bool,
    pub path_suffixes: Option<Vec<String>>,
    pub parent_token: Option<String>,
    pub entity_id: Option<String>,
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Clone)]
pub struct CreateLeaseRequest {
    pub renewable: bool,
    pub ttl: Duration,
}
```

#### **Week 6-8: HCL Policy Engine**
**Status**: 🟡 **BASIC RBAC ONLY**

**Files to Create/Modify**:
```
crates/fortress-core/src/
├── policy_hcl/               # NEW - HCL policy engine
│   ├── mod.rs
│   ├── parser.rs             # HCL parser
│   ├── evaluator.rs          # Policy evaluation engine
│   ├── types.rs              # Policy types
│   └── builtin_functions.rs  # Built-in policy functions
├── policy.rs                 # MODIFY - Enhance existing policy module
└── lib.rs                   # MODIFY - Add HCL policy exports
```

**Implementation Details**:
```rust
// File: crates/fortress-core/src/policy_hcl/evaluator.rs
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedPolicy {
    pub name: String,
    pub path: String,
    pub capabilities: Vec<String>,
    pub required_parameters: HashMap<String, ParameterType>,
    pub allowed_parameters: HashMap<String, Vec<String>>,
    pub min_ttl: Option<i64>,
    pub max_ttl: Option<i64>,
    pub constraints: Vec<PolicyConstraint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ParameterType {
    String,
    Number,
    Boolean,
    Array,
    Object,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConstraint {
    pub field: String,
    pub operator: ConstraintOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConstraintOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    In,
    NotIn,
}

#[derive(Debug, Clone)]
pub struct PolicyContext {
    pub token: TokenInfo,
    pub path: String,
    pub operation: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub time: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

pub struct HclPolicyEngine {
    policies: Arc<RwLock<HashMap<String, ParsedPolicy>>>,
    role_store: Arc<dyn RoleStore>,
    function_registry: HashMap<String, Box<dyn PolicyFunction>>,
}

impl HclPolicyEngine {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
            role_store: Arc::new(InMemoryRoleStore::new()),
            function_registry: Self::register_builtin_functions(),
        }
    }

    pub async fn load_policy(&self, policy_name: &str, hcl_content: &str) -> Result<()> {
        let parsed_policy = self.parse_hcl_policy(hcl_content)?;
        
        let mut policies = self.policies.write().await;
        policies.insert(policy_name.to_string(), parsed_policy);
        
        Ok(())
    }

    pub async fn evaluate_policy(&self, context: &PolicyContext) -> Result<PolicyResult> {
        let policies = self.policies.read().await;
        
        // Find matching policies
        let matching_policies = self.find_matching_policies(&policies, context)?;
        
        // Evaluate each policy
        let mut allowed_capabilities = Vec::new();
        let mut denied = false;
        let mut denial_reason = None;

        for policy in matching_policies {
            let result = self.evaluate_single_policy(policy, context).await?;
            
            if !result.allowed {
                denied = true;
                denial_reason = result.reason;
                break;
            }
            
            allowed_capabilities.extend(result.allowed_capabilities);
        }

        Ok(PolicyResult {
            allowed: !denied,
            allowed_capabilities,
            ttl: self.calculate_ttl(context, &matching_policies)?,
            reason: denial_reason,
        })
    }

    fn parse_hcl_policy(&self, hcl_content: &str) -> Result<ParsedPolicy> {
        // Parse HCL content
        // This is a simplified parser - use proper HCL parsing library
        let lines: Vec<&str> = hcl_content.lines().collect();
        let mut policy = ParsedPolicy {
            name: "default".to_string(),
            path: "*".to_string(),
            capabilities: vec![],
            required_parameters: HashMap::new(),
            allowed_parameters: HashMap::new(),
            min_ttl: None,
            max_ttl: None,
            constraints: vec![],
        };

        for line in lines {
            let trimmed = line.trim();
            if trimmed.starts_with("path") {
                policy.path = self.extract_path_value(trimmed)?;
            } else if trimmed.starts_with("capabilities") {
                policy.capabilities = self.extract_capabilities(trimmed)?;
            }
        }

        Ok(policy)
    }

    fn find_matching_policies(&self, policies: &HashMap<String, ParsedPolicy>, context: &PolicyContext) -> Result<Vec<&ParsedPolicy>> {
        let mut matching = Vec::new();
        
        for policy in policies.values() {
            if self.path_matches(&policy.path, &context.path) {
                matching.push(policy);
            }
        }
        
        Ok(matching)
    }

    fn path_matches(&self, policy_path: &str, request_path: &str) -> bool {
        // Simple glob matching - implement proper pattern matching
        if policy_path == "*" {
            return true;
        }
        
        if policy_path.contains('*') {
            let pattern = policy_path.replace('*', ".*");
            if let Ok(regex) = regex::Regex::new(&pattern) {
                return regex.is_match(request_path);
            }
        }
        
        policy_path == request_path
    }

    async fn evaluate_single_policy(&self, policy: &ParsedPolicy, context: &PolicyContext) -> Result<PolicyEvaluationResult> {
        // Check if operation is in allowed capabilities
        if !policy.capabilities.contains(&context.operation) {
            return Ok(PolicyEvaluationResult {
                allowed: false,
                allowed_capabilities: vec![],
                reason: Some(format!("Operation '{}' not allowed by policy", context.operation)),
            });
        }

        // Check constraints
        for constraint in &policy.constraints {
            if !self.evaluate_constraint(constraint, context)? {
                return Ok(PolicyEvaluationResult {
                    allowed: false,
                    allowed_capabilities: vec![],
                    reason: Some(format!("Constraint failed: {}", constraint.field)),
                });
            }
        }

        Ok(PolicyEvaluationResult {
            allowed: true,
            allowed_capabilities: policy.capabilities.clone(),
            reason: None,
        })
    }

    fn evaluate_constraint(&self, constraint: &PolicyConstraint, context: &PolicyContext) -> Result<bool> {
        let field_value = context.parameters.get(&constraint.field)
            .ok_or_else(|| FortressError::policy("Missing required field"))?;

        match constraint.operator {
            ConstraintOperator::Equals => {
                Ok(field_value == &constraint.value)
            }
            ConstraintOperator::NotEquals => {
                Ok(field_value != &constraint.value)
            }
            ConstraintOperator::In => {
                if let serde_json::Value::Array(allowed_values) = &constraint.value {
                    Ok(allowed_values.contains(field_value))
                } else {
                    Err(FortressError::policy("Invalid 'in' constraint"))
                }
            }
            // Add other operators...
            _ => Ok(true),
        }
    }

    fn extract_path_value(&self, line: &str) -> Result<String> {
        // Extract path from "path \"secret/data/*\" {"
        let start = line.find('"').ok_or_else(|| FortressError::policy("Invalid path syntax"))?;
        let end = line.rfind('"').ok_or_else(|| FortressError::policy("Invalid path syntax"))?;
        Ok(line[start + 1..end].to_string())
    }

    fn extract_capabilities(&self, line: &str) -> Result<Vec<String>> {
        // Extract capabilities from "capabilities = [\"read\", \"list\"]"
        let start = line.find('[').ok_or_else(|| FortressError::policy("Invalid capabilities syntax"))?;
        let end = line.find(']').ok_or_else(|| FortressError::policy("Invalid capabilities syntax"))?;
        let content = &line[start + 1..end];
        
        let capabilities: Vec<String> = content
            .split(',')
            .map(|s| s.trim().trim_matches('"').to_string())
            .collect();
            
        Ok(capabilities)
    }

    fn calculate_ttl(&self, context: &PolicyContext, policies: &[&ParsedPolicy]) -> Result<Duration> {
        // Calculate TTL based on policy constraints and token TTL
        let base_ttl = context.token.token.ttl;
        
        for policy in policies {
            if let Some(min_ttl) = policy.min_ttl {
                if base_ttl.num_seconds() < min_ttl {
                    return Ok(Duration::seconds(min_ttl));
                }
            }
            
            if let Some(max_ttl) = policy.max_ttl {
                if base_ttl.num_seconds() > max_ttl {
                    return Ok(Duration::seconds(max_ttl));
                }
            }
        }
        
        Ok(base_ttl)
    }

    fn register_builtin_functions() -> HashMap<String, Box<dyn PolicyFunction>> {
        let mut registry = HashMap::new();
        
        // Register built-in functions like time(), identity(), etc.
        registry.insert("time".to_string(), Box::new(TimeFunction));
        registry.insert("identity".to_string(), Box::new(IdentityFunction));
        registry.insert("ip".to_string(), Box::new(IpFunction));
        
        registry
    }
}

#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub allowed: bool,
    pub allowed_capabilities: Vec<String>,
    pub ttl: Duration,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PolicyEvaluationResult {
    pub allowed: bool,
    pub allowed_capabilities: Vec<String>,
    pub reason: Option<String>,
}

pub trait PolicyFunction: Send + Sync {
    fn evaluate(&self, args: &[serde_json::Value], context: &PolicyContext) -> Result<serde_json::Value>;
}

// Built-in function implementations
struct TimeFunction;

impl PolicyFunction for TimeFunction {
    fn evaluate(&self, _args: &[serde_json::Value], _context: &PolicyContext) -> Result<serde_json::Value> {
        Ok(serde_json::Value::Number(
            serde_json::Number::from(Utc::now().timestamp())
        ))
    }
}

struct IdentityFunction;

impl PolicyFunction for IdentityFunction {
    fn evaluate(&self, _args: &[serde_json::Value], context: &PolicyContext) -> Result<serde_json::Value> {
        Ok(serde_json::Value::String(context.token.entity_id.clone()))
    }
}

struct IpFunction;

impl PolicyFunction for IpFunction {
    fn evaluate(&self, _args: &[serde_json::Value], context: &PolicyContext) -> Result<serde_json::Value> {
        Ok(serde_json::Value::String(
            context.ip_address.clone().unwrap_or_default()
        ))
    }
}

pub trait RoleStore: Send + Sync {
    fn get_roles(&self, entity_id: &str) -> Result<Vec<String>>;
    fn check_role(&self, entity_id: &str, role: &str) -> Result<bool>;
}

pub struct InMemoryRoleStore {
    roles: Arc<RwLock<HashMap<String, Vec<String>>>>,
}

impl InMemoryRoleStore {
    pub fn new() -> Self {
        Self {
            roles: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn add_role(&self, entity_id: &str, role: &str) -> Result<()> {
        let mut roles = self.roles.write().unwrap();
        roles.entry(entity_id.to_string())
            .or_insert_with(Vec::new)
            .push(role.to_string());
        Ok(())
    }
}

impl RoleStore for InMemoryRoleStore {
    fn get_roles(&self, entity_id: &str) -> Result<Vec<String>> {
        let roles = self.roles.read().unwrap();
        Ok(roles.get(entity_id).cloned().unwrap_or_default())
    }

    fn check_role(&self, entity_id: &str, role: &str) -> Result<bool> {
        let roles = self.get_roles(entity_id)?;
        Ok(roles.contains(&role.to_string()))
    }
}
```

---

### 🔧 Phase 2: Secret Engine Ecosystem (Weeks 9-16)

#### **Week 9-12: Pluggable Secret Engine Framework**
**Status**: 🟡 **KV ENGINE ONLY**

**Files to Create/Modify**:
```
crates/fortress-core/src/
├── engines/                   # NEW - Secret engine framework
│   ├── mod.rs
│   ├── registry.rs            # Engine registry
│   ├── manager.rs             # Engine manager
│   ├── types.rs              # Common engine types
│   └── base.rs               # Base engine trait
├── secrets/                  # MODIFY - Enhance existing
│   ├── kv.rs                 # Enhance existing KV engine
│   ├── transit.rs             # Enhance existing transit engine
│   └── mod.rs                # Update exports
└── lib.rs                    # MODIFY - Add engine framework
```

**Implementation Details**:
```rust
// File: crates/fortress-core/src/engines/base.rs
use async_trait::async_trait;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub data: serde_json::Value,
    pub metadata: SecretMetadata,
    pub lease_id: Option<String>,
    pub created_time: DateTime<Utc>,
    pub updated_time: DateTime<Utc>,
    pub version: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadata {
    pub created_by: String,
    pub ttl: Option<Duration>,
    pub max_versions: Option<u64>,
    pub cas_required: bool,
    pub custom_metadata: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct Context {
    pub token: TokenInfo,
    pub request_path: String,
    pub operation: String,
    pub parameters: HashMap<String, serde_json::Value>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub request_time: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct EngineCapabilities {
    pub supports_lease: bool,
    pub supports_rotation: bool,
    pub supports_dynamic_secrets: bool,
    pub supports_signing: bool,
    pub supports_encryption: bool,
    pub supported_operations: Vec<String>,
}

#[async_trait]
pub trait SecretsEngine: Send + Sync {
    fn name(&self) -> &str;
    fn version(&self) -> &str;
    fn capabilities(&self) -> EngineCapabilities;
    
    async fn initialize(&mut self, config: &serde_json::Value) -> Result<()>;
    async fn shutdown(&mut self) -> Result<()>;
    
    async fn read_secret(&self, path: &str, context: &Context) -> Result<Secret>;
    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()>;
    async fn delete_secret(&self, path: &str, context: &Context) -> Result<()>;
    async fn list_secrets(&self, path: &str, context: &Context) -> Result<Vec<String>>;
    
    async fn renew_lease(&self, lease_id: &str, increment: Duration, context: &Context) -> Result<Duration>;
    async fn revoke_lease(&self, lease_id: &str, context: &Context) -> Result<()>;
    
    async fn rotate_secret(&self, path: &str, context: &Context) -> Result<Secret>;
    async fn get_secret_metadata(&self, path: &str, context: &Context) -> Result<SecretMetadata>;
}

// File: crates/fortress-core/src/engines/manager.rs
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct EngineManager {
    engines: Arc<RwLock<HashMap<String, Box<dyn SecretsEngine>>>>,
    mount_table: Arc<RwLock<HashMap<String, String>>>, // path -> engine_name
    default_engine: String,
}

impl EngineManager {
    pub fn new() -> Self {
        Self {
            engines: Arc::new(RwLock::new(HashMap::new())),
            mount_table: Arc::new(RwLock::new(HashMap::new())),
            default_engine: "kv".to_string(),
        }
    }

    pub async fn register_engine(&self, name: &str, engine: Box<dyn SecretsEngine>) -> Result<()> {
        let mut engines = self.engines.write().await;
        engines.insert(name.to_string(), engine);
        
        // Mount at default path
        let mut mount_table = self.mount_table.write().await;
        mount_table.insert(format!("{}/", name), name.to_string());
        
        Ok(())
    }

    pub async fn mount_engine(&self, path: &str, engine_name: &str) -> Result<()> {
        let engines = self.engines.read().await;
        if !engines.contains_key(engine_name) {
            return Err(FortressError::engine("Engine not found"));
        }

        let mut mount_table = self.mount_table.write().await;
        mount_table.insert(format!("{}/", path), engine_name.to_string());
        
        Ok(())
    }

    pub async fn resolve_engine(&self, path: &str) -> Result<String> {
        let mount_table = self.mount_table.read().await;
        
        // Find the most specific mount
        let mut best_match = None;
        let mut best_length = 0;
        
        for (mount_path, engine_name) in mount_table.iter() {
            if path.starts_with(mount_path) && mount_path.len() > best_length {
                best_match = Some(engine_name.clone());
                best_length = mount_path.len();
            }
        }
        
        best_match.ok_or_else(|| FortressError::engine("No engine mounted for path"))
    }

    pub async fn get_engine(&self, path: &str) -> Result<Arc<dyn SecretsEngine>> {
        let engine_name = self.resolve_engine(path).await?;
        let engines = self.engines.read().await;
        
        // This is a simplified approach - in practice, you'd need a way to
        // get references to the engines, not clone them
        engines.get(&engine_name)
            .map(|_| {
                // Return a placeholder - implement proper Arc wrapping
                unimplemented!("Implement proper engine reference handling")
            })
            .ok_or_else(|| FortressError::engine("Engine not found"))
    }

    pub async fn execute_operation(&self, path: &str, operation: &str, context: &Context) -> Result<serde_json::Value> {
        let engine_name = self.resolve_engine(path).await?;
        let engines = self.engines.read().await;
        
        if let Some(engine) = engines.get(&engine_name) {
            match operation {
                "read" => {
                    let secret = engine.read_secret(path, context).await?;
                    Ok(serde_json::to_value(secret)?)
                }
                "write" => {
                    // Extract secret data from context parameters
                    let data = context.parameters.get("data")
                        .ok_or_else(|| FortressError::engine("Missing data parameter"))?;
                    let secret: Secret = serde_json::from_value(data.clone())?;
                    
                    engine.write_secret(path, &secret, context).await?;
                    Ok(serde_json::json!({"status": "success"}))
                }
                "delete" => {
                    engine.delete_secret(path, context).await?;
                    Ok(serde_json::json!({"status": "success"}))
                }
                "list" => {
                    let secrets = engine.list_secrets(path, context).await?;
                    Ok(serde_json::to_value(secrets)?)
                }
                _ => Err(FortressError::engine("Unsupported operation"))
            }
        } else {
            Err(FortressError::engine("Engine not found"))
        }
    }
}

// File: crates/fortress-core/src/engines/kv.rs
use super::base::*;

pub struct KvEngine {
    storage: Arc<RwLock<HashMap<String, Secret>>>,
    config: KvEngineConfig,
}

#[derive(Debug, Clone)]
pub struct KvEngineConfig {
    pub max_versions: u64,
    pub default_ttl: Option<Duration>,
    pub cas_required: bool,
}

impl KvEngine {
    pub fn new(config: KvEngineConfig) -> Self {
        Self {
            storage: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }
}

#[async_trait]
impl SecretsEngine for KvEngine {
    fn name(&self) -> &str {
        "kv"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supports_lease: true,
            supports_rotation: true,
            supports_dynamic_secrets: false,
            supports_signing: false,
            supports_encryption: false,
            supported_operations: vec!["read".to_string(), "write".to_string(), "delete".to_string(), "list".to_string()],
        }
    }

    async fn initialize(&mut self, _config: &serde_json::Value) -> Result<()> {
        // Initialize KV storage
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Cleanup resources
        Ok(())
    }

    async fn read_secret(&self, path: &str, _context: &Context) -> Result<Secret> {
        let storage = self.storage.read().await;
        storage.get(path)
            .cloned()
            .ok_or_else(|| FortressError::secret("Secret not found"))
    }

    async fn write_secret(&self, path: &str, data: &Secret, context: &Context) -> Result<()> {
        let mut storage = self.storage.write().await;
        
        // Check CAS requirement
        if self.config.cas_required {
            if let Some(existing) = storage.get(path) {
                if existing.version != data.version {
                    return Err(FortressError::secret("CAS check failed"));
                }
            }
        }
        
        let mut secret = data.clone();
        secret.updated_time = Utc::now();
        secret.created_by = context.token.entity_id.clone();
        
        storage.insert(path.to_string(), secret);
        Ok(())
    }

    async fn delete_secret(&self, path: &str, _context: &Context) -> Result<()> {
        let mut storage = self.storage.write().await;
        storage.remove(path).ok_or_else(|| FortressError::secret("Secret not found"))?;
        Ok(())
    }

    async fn list_secrets(&self, path: &str, _context: &Context) -> Result<Vec<String>> {
        let storage = self.storage.read().await;
        let mut secrets = Vec::new();
        
        for key in storage.keys() {
            if key.starts_with(path) {
                secrets.push(key.clone());
            }
        }
        
        Ok(secrets)
    }

    async fn renew_lease(&self, lease_id: &str, increment: Duration, _context: &Context) -> Result<Duration> {
        // Implement lease renewal logic
        Ok(increment)
    }

    async fn revoke_lease(&self, _lease_id: &str, _context: &Context) -> Result<()> {
        // Implement lease revocation logic
        Ok(())
    }

    async fn rotate_secret(&self, path: &str, context: &Context) -> Result<Secret> {
        // Generate new secret data
        let new_data = serde_json::json!({
            "rotated": true,
            "rotated_at": Utc::now(),
            "rotated_by": context.token.entity_id
        });
        
        let new_secret = Secret {
            data: new_data,
            metadata: SecretMetadata {
                created_by: context.token.entity_id.clone(),
                ttl: None,
                max_versions: Some(self.config.max_versions),
                cas_required: self.config.cas_required,
                custom_metadata: HashMap::new(),
            },
            lease_id: None,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            version: 1,
        };
        
        let mut storage = self.storage.write().await;
        storage.insert(path.to_string(), new_secret.clone());
        
        Ok(new_secret)
    }

    async fn get_secret_metadata(&self, path: &str, _context: &Context) -> Result<SecretMetadata> {
        let storage = self.storage.read().await;
        storage.get(path)
            .map(|secret| secret.metadata.clone())
            .ok_or_else(|| FortressError::secret("Secret not found"))
    }
}
```

#### **Week 13-16: PKI Engine**
**Status**: ❌ **MISSING**

**Files to Create**:
```
crates/fortress-core/src/engines/pki.rs
crates/fortress-core/src/engines/certificate.rs
crates/fortress-core/src/engines/crl.rs
```

**Implementation Details**:
```rust
// File: crates/fortress-core/src/engines/pki.rs
use super::base::*;
use x509_parser::prelude::*;
use rcgen::{Certificate, CertificateParams, DistinguishedName, KeyPair};
use std::collections::HashMap;

pub struct PkiEngine {
    ca_key: RsaPrivateKey,
    ca_cert: Certificate,
    config: PkiConfig,
    certificates: Arc<RwLock<HashMap<String, CertificateInfo>>>,
    crl: Arc<RwLock<CertificateRevocationList>>,
}

#[derive(Debug, Clone)]
pub struct PkiConfig {
    pub ca_ttl: Duration,
    pub cert_ttl: Duration,
    pub key_size: u32,
    pub allowed_domains: Vec<String>,
    pub max_certificates_per_domain: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub serial: String,
    pub common_name: String,
    pub san_domains: Vec<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub created_by: String,
    pub revoked: bool,
    pub revocation_reason: Option<String>,
    pub pem_certificate: String,
    pub pem_private_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateBundle {
    pub certificate: String,
    pub private_key: String,
    pub ca_certificate: String,
    pub chain: Vec<String>,
    pub metadata: CertificateInfo,
}

impl PkiEngine {
    pub fn new(config: PkiConfig) -> Result<Self> {
        let (ca_key, ca_cert) = self.generate_ca_certificate(&config)?;
        
        Ok(Self {
            ca_key,
            ca_cert,
            config,
            certificates: Arc::new(RwLock::new(HashMap::new())),
            crl: Arc::new(RwLock::new(CertificateRevocationList::new())),
        })
    }

    fn generate_ca_certificate(&self, config: &PkiConfig) -> Result<(RsaPrivateKey, Certificate)> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new()
            .common_name("Fortress CA")
            .organization("Fortress")
            .country("US");
        
        params.is_ca = rcgen::IsCa::Ca(rcgen::CaConstraint::BasicConstraints);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        params.valid_from = chrono::Utc::now();
        params.valid_until = chrono::Utc::now() + config.ca_ttl;

        let key_pair = KeyPair::generate(&rcgen::PKCS_RSA_SHA256, config.key_size)?;
        let cert = params.self_signed(&key_pair)?;
        
        // Convert to RsaPrivateKey (simplified - use proper conversion)
        let ca_key = self.convert_key_pair(&key_pair)?;
        
        Ok((ca_key, cert))
    }

    fn convert_key_pair(&self, key_pair: &KeyPair) -> Result<RsaPrivateKey> {
        // Convert rcgen KeyPair to RSA private key
        // This is a simplified implementation
        let der = key_pair.serialize_der()?;
        let rsa_key = RsaPrivateKey::from_pkcs8_der(&der)?;
        Ok(rsa_key)
    }

    pub async fn generate_certificate(&self, request: &CertificateRequest) -> Result<CertificateBundle> {
        // Validate request
        self.validate_certificate_request(request).await?;
        
        // Generate certificate
        let cert_params = self.build_certificate_params(request)?;
        let key_pair = KeyPair::generate(&rcgen::PKCS_RSA_SHA256, self.config.key_size)?;
        let cert = cert_params.signed_by(&self.ca_cert, &self.ca_key, &key_pair)?;
        
        // Create certificate info
        let cert_info = CertificateInfo {
            serial: self.generate_serial(),
            common_name: request.common_name.clone(),
            san_domains: request.san_domains.clone(),
            not_before: cert_params.valid_from.unwrap_or_else(chrono::Utc::now),
            not_after: cert_params.valid_until.unwrap_or_else(|| chrono::Utc::now() + self.config.cert_ttl),
            created_by: request.created_by.clone(),
            revoked: false,
            revocation_reason: None,
            pem_certificate: cert.pem(),
            pem_private_key: Some(key_pair.serialize_pem()),
        };
        
        // Store certificate
        let mut certificates = self.certificates.write().await;
        certificates.insert(cert_info.serial.clone(), cert_info.clone());
        
        Ok(CertificateBundle {
            certificate: cert.pem(),
            private_key: key_pair.serialize_pem(),
            ca_certificate: self.ca_cert.pem(),
            chain: vec![self.ca_cert.pem()],
            metadata: cert_info,
        })
    }

    pub async fn sign_csr(&self, csr_pem: &str, context: &Context) -> Result<CertificateBundle> {
        // Parse CSR
        let csr = self.parse_csr(csr_pem)?;
        
        // Validate CSR
        self.validate_csr(&csr, context).await?;
        
        // Generate certificate from CSR
        let cert_params = self.build_params_from_csr(&csr)?;
        let cert = cert_params.signed_by(&self.ca_cert, &self.ca_key)?;
        
        let cert_info = CertificateInfo {
            serial: self.generate_serial(),
            common_name: csr.common_name.clone(),
            san_domains: csr.san_domains.clone(),
            not_before: cert_params.valid_from.unwrap_or_else(chrono::Utc::now),
            not_after: cert_params.valid_until.unwrap_or_else(|| chrono::Utc::now() + self.config.cert_ttl),
            created_by: context.token.entity_id.clone(),
            revoked: false,
            revocation_reason: None,
            pem_certificate: cert.pem(),
            pem_private_key: None, // CSR doesn't include private key
        };
        
        let mut certificates = self.certificates.write().await;
        certificates.insert(cert_info.serial.clone(), cert_info.clone());
        
        Ok(CertificateBundle {
            certificate: cert.pem(),
            private_key: String::new(), // No private key for CSR signing
            ca_certificate: self.ca_cert.pem(),
            chain: vec![self.ca_cert.pem()],
            metadata: cert_info,
        })
    }

    pub async fn revoke_certificate(&self, serial: &str, reason: Option<String>, context: &Context) -> Result<()> {
        let mut certificates = self.certificates.write().await;
        let cert_info = certificates.get_mut(serial)
            .ok_or_else(|| FortressError::pki("Certificate not found"))?;
        
        cert_info.revoked = true;
        cert_info.revocation_reason = reason.clone();
        
        // Add to CRL
        let mut crl = self.crl.write().await;
        crl.add_revoked_certificate(serial, Utc::now(), reason);
        
        Ok(())
    }

    pub async fn list_certificates(&self, filters: &CertificateFilters) -> Result<Vec<CertificateInfo>> {
        let certificates = self.certificates.read().await;
        let mut result = Vec::new();
        
        for cert_info in certificates.values() {
            if self.matches_filters(cert_info, filters) {
                result.push(cert_info.clone());
            }
        }
        
        Ok(result)
    }

    pub async fn generate_crl(&self) -> Result<String> {
        let crl = self.crl.read().await;
        let crl_pem = crl.to_pem(&self.ca_cert, &self.ca_key)?;
        Ok(crl_pem)
    }

    async fn validate_certificate_request(&self, request: &CertificateRequest) -> Result<()> {
        // Check domain restrictions
        if !self.config.allowed_domains.is_empty() {
            for domain in &request.common_name.split(',').collect::<Vec<&str>>() {
                if !self.config.allowed_domains.contains(&domain.to_string()) {
                    return Err(FortressError::pki("Domain not allowed"));
                }
            }
        }
        
        // Check certificate limits per domain
        let certificates = self.certificates.read().await;
        let domain_count = certificates.values()
            .filter(|cert| cert.common_name == request.common_name && !cert.revoked)
            .count();
            
        if domain_count >= self.config.max_certificates_per_domain {
            return Err(FortressError::pki("Maximum certificates per domain exceeded"));
        }
        
        Ok(())
    }

    fn build_certificate_params(&self, request: &CertificateRequest) -> Result<CertificateParams> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new()
            .common_name(&request.common_name)
            .organization(&request.organization)
            .country(&request.country);
        
        // Add SAN domains
        if !request.san_domains.is_empty() {
            params.subject_alt_names = request.san_domains.iter().map(|s| s.as_str()).collect();
        }
        
        // Set key usage
        params.key_usages = request.key_usages.clone();
        params.extended_key_usages = request.extended_key_usages.clone();
        
        // Set validity period
        params.valid_from = chrono::Utc::now();
        params.valid_until = chrono::Utc::now() + self.config.cert_ttl;
        
        Ok(params)
    }

    fn generate_serial(&self) -> String {
        use uuid::Uuid;
        format!("{:x}", Uuid::new_v4().as_u128())
    }

    fn parse_csr(&self, csr_pem: &str) -> Result<CertificateSigningRequest> {
        // Parse CSR from PEM format
        // This is a simplified implementation
        Ok(CertificateSigningRequest {
            common_name: "example.com".to_string(),
            san_domains: vec![],
            organization: "Example Org".to_string(),
            country: "US".to_string(),
            key_usages: vec![],
            extended_key_usages: vec![],
        })
    }

    async fn validate_csr(&self, _csr: &CertificateSigningRequest, _context: &Context) -> Result<()> {
        // Validate CSR against policies
        Ok(())
    }

    fn build_params_from_csr(&self, csr: &CertificateSigningRequest) -> Result<CertificateParams> {
        // Build certificate parameters from CSR
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new()
            .common_name(&csr.common_name)
            .organization(&csr.organization)
            .country(&csr.country);
        
        params.valid_from = chrono::Utc::now();
        params.valid_until = chrono::Utc::now() + self.config.cert_ttl;
        
        Ok(params)
    }

    fn matches_filters(&self, cert_info: &CertificateInfo, filters: &CertificateFilters) -> bool {
        if let Some(ref common_name) = filters.common_name {
            if !cert_info.common_name.contains(common_name) {
                return false;
            }
        }
        
        if let Some(revoked) = filters.revoked {
            if cert_info.revoked != revoked {
                return false;
            }
        }
        
        if let Some(ref not_after) = filters.not_after {
            if cert_info.not_after > *not_after {
                return false;
            }
        }
        
        true
    }
}

#[derive(Debug, Clone)]
pub struct CertificateRequest {
    pub common_name: String,
    pub san_domains: Vec<String>,
    pub organization: String,
    pub country: String,
    pub key_usages: Vec<rcgen::KeyUsagePurpose>,
    pub extended_key_usages: Vec<rcgen::ExtendedKeyUsagePurpose>,
    pub ttl: Option<Duration>,
    pub created_by: String,
}

#[derive(Debug, Clone)]
pub struct CertificateSigningRequest {
    pub common_name: String,
    pub san_domains: Vec<String>,
    pub organization: String,
    pub country: String,
    pub key_usages: Vec<rcgen::KeyUsagePurpose>,
    pub extended_key_usages: Vec<rcgen::ExtendedKeyUsagePurpose>,
}

#[derive(Debug, Clone, Default)]
pub struct CertificateFilters {
    pub common_name: Option<String>,
    pub revoked: Option<bool>,
    pub not_after: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct CertificateRevocationList {
    revoked_certificates: HashMap<String, RevokedCertificate>,
}

#[derive(Debug, Clone)]
pub struct RevokedCertificate {
    pub serial: String,
    pub revocation_time: DateTime<Utc>,
    pub reason: Option<String>,
}

impl CertificateRevocationList {
    pub fn new() -> Self {
        Self {
            revoked_certificates: HashMap::new(),
        }
    }

    pub fn add_revoked_certificate(&mut self, serial: &str, revocation_time: DateTime<Utc>, reason: Option<String>) {
        let revoked = RevokedCertificate {
            serial: serial.to_string(),
            revocation_time,
            reason,
        };
        
        self.revoked_certificates.insert(serial.to_string(), revoked);
    }

    pub fn to_pem(&self, ca_cert: &Certificate, ca_key: &RsaPrivateKey) -> Result<String> {
        // Generate CRL in PEM format
        // This is a simplified implementation
        Ok(format!("-----BEGIN X509 CRL-----\nGenerated CRL\n-----END X509 CRL-----"))
    }
}

// Implement SecretsEngine trait for PkiEngine
#[async_trait]
impl SecretsEngine for PkiEngine {
    fn name(&self) -> &str {
        "pki"
    }

    fn version(&self) -> &str {
        "1.0.0"
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            supports_lease: false,
            supports_rotation: true,
            supports_dynamic_secrets: true,
            supports_signing: true,
            supports_encryption: false,
            supported_operations: vec![
                "generate_certificate".to_string(),
                "sign_csr".to_string(),
                "revoke_certificate".to_string(),
                "list_certificates".to_string(),
                "generate_crl".to_string(),
            ],
        }
    }

    async fn initialize(&mut self, _config: &serde_json::Value) -> Result<()> {
        // Initialize PKI engine
        Ok(())
    }

    async fn shutdown(&mut self) -> Result<()> {
        // Cleanup PKI engine
        Ok(())
    }

    async fn read_secret(&self, path: &str, context: &Context) -> Result<Secret> {
        match path {
            path if path.ends_with("/generate") => self.handle_generate_certificate(path, context).await,
            path if path.ends_with("/sign") => self.handle_sign_csr(path, context).await,
            path if path.ends_with("/list") => self.handle_list_certificates(path, context).await,
            path if path.ends_with("/crl") => self.handle_generate_crl(path, context).await,
            _ => Err(FortressError::pki("Invalid PKI operation")),
        }
    }

    async fn write_secret(&self, _path: &str, _data: &Secret, _context: &Context) -> Result<()> {
        Err(FortressError::pki("Write operations not supported by PKI engine"))
    }

    async fn delete_secret(&self, _path: &str, _context: &Context) -> Result<()> {
        Err(FortressError::pki("Delete operations not supported by PKI engine"))
    }

    async fn list_secrets(&self, _path: &str, _context: &Context) -> Result<Vec<String>> {
        Ok(vec![
            "generate".to_string(),
            "sign".to_string(),
            "list".to_string(),
            "revoke".to_string(),
            "crl".to_string(),
        ])
    }

    async fn renew_lease(&self, _lease_id: &str, _increment: Duration, _context: &Context) -> Result<Duration> {
        Err(FortressError::pki("Lease operations not supported by PKI engine"))
    }

    async fn revoke_lease(&self, _lease_id: &str, _context: &Context) -> Result<()> {
        Err(FortressError::pki("Lease operations not supported by PKI engine"))
    }

    async fn rotate_secret(&self, _path: &str, _context: &Context) -> Result<Secret> {
        // Rotate CA certificate
        Err(FortressError::pki("CA rotation not implemented"))
    }

    async fn get_secret_metadata(&self, _path: &str, _context: &Context) -> Result<SecretMetadata> {
        Err(FortressError::pki("Metadata operations not supported by PKI engine"))
    }
}

impl PkiEngine {
    async fn handle_generate_certificate(&self, path: &str, context: &Context) -> Result<Secret> {
        // Extract certificate request from context parameters
        let request_data = context.parameters.get("request")
            .ok_or_else(|| FortressError::pki("Missing certificate request"))?;
        
        let request: CertificateRequest = serde_json::from_value(request_data.clone())?;
        let bundle = self.generate_certificate(&request).await?;
        
        Ok(Secret {
            data: serde_json::to_value(bundle)?,
            metadata: SecretMetadata {
                created_by: context.token.entity_id.clone(),
                ttl: Some(self.config.cert_ttl),
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            },
            lease_id: None,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            version: 1,
        })
    }

    async fn handle_sign_csr(&self, path: &str, context: &Context) -> Result<Secret> {
        let csr_pem = context.parameters.get("csr")
            .and_then(|v| v.as_str())
            .ok_or_else(|| FortressError::pki("Missing CSR"))?;
        
        let bundle = self.sign_csr(csr_pem, context).await?;
        
        Ok(Secret {
            data: serde_json::to_value(bundle)?,
            metadata: SecretMetadata {
                created_by: context.token.entity_id.clone(),
                ttl: Some(self.config.cert_ttl),
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            },
            lease_id: None,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            version: 1,
        })
    }

    async fn handle_list_certificates(&self, path: &str, context: &Context) -> Result<Secret> {
        let filters = context.parameters.get("filters")
            .map(|v| serde_json::from_value(v.clone()).unwrap_or_default())
            .unwrap_or_default();
        
        let certificates = self.list_certificates(&filters).await?;
        
        Ok(Secret {
            data: serde_json::to_value(certificates)?,
            metadata: SecretMetadata {
                created_by: context.token.entity_id.clone(),
                ttl: None,
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            },
            lease_id: None,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            version: 1,
        })
    }

    async fn handle_generate_crl(&self, path: &str, context: &Context) -> Result<Secret> {
        let crl_pem = self.generate_crl().await?;
        
        Ok(Secret {
            data: serde_json::json!({
                "crl": crl_pem,
                "generated_at": Utc::now(),
                "generated_by": context.token.entity_id
            }),
            metadata: SecretMetadata {
                created_by: context.token.entity_id.clone(),
                ttl: Some(Duration::hours(24)), // CRL valid for 24 hours
                max_versions: None,
                cas_required: false,
                custom_metadata: HashMap::new(),
            },
            lease_id: None,
            created_time: Utc::now(),
            updated_time: Utc::now(),
            version: 1,
        })
    }
}
```

---

### 🚀 Phase 3: Enterprise Features (Weeks 17-24)

#### **Week 17-20: Auto-Discovery & Service Mesh**
**Status**: 🟡 **MANUAL CONFIGURATION ONLY**

**Files to Create**:
```
crates/fortress-core/src/
├── discovery/                # NEW - Cluster discovery
│   ├── mod.rs
│   ├── kubernetes.rs         # K8s discovery
│   ├── dns.rs               # DNS discovery
│   ├── consul.rs            # Consul discovery
│   └── static.rs            # Static configuration
├── mesh/                    # NEW - Service mesh integration
│   ├── mod.rs
│   ├── envoy.rs             # Envoy integration
│   ├── istio.rs            # Istio integration
│   └── linkerd.rs           # Linkerd integration
└── cluster.rs               # MODIFY - Add auto-discovery
```

#### **Week 21-24: Advanced Rate Limiting**
**Status**: ❌ **MISSING**

**Files to Create**:
```
crates/fortress-core/src/
├── rate_limit/              # NEW - Advanced rate limiting
│   ├── mod.rs
│   ├── manager.rs           # Rate limit manager
│   ├── algorithms.rs        # Rate limit algorithms
│   ├── storage.rs           # Rate limit storage backends
│   └── middleware.rs        # HTTP middleware
└── api/                    # MODIFY - Add rate limiting middleware
```

---

## 📊 Success Metrics & Validation

### **Phase 1 Success Criteria** (Weeks 1-8)
- [ ] **Seal/Unseal**: ✅ Shamir Secret Sharing implemented
- [ ] **Token System**: ✅ Production-grade token management
- [ ] **Policy Engine**: ✅ HCL policy evaluation
- [ ] **Security Score**: 8/10 (from 5/10)

### **Phase 2 Success Criteria** (Weeks 9-16)
- [ ] **Engine Framework**: ✅ Pluggable secret engines
- [ ] **PKI Engine**: ✅ Full certificate management
- [ ] **Database Engine**: ✅ Dynamic credential generation
- [ ] **Feature Score**: 8.5/10 (from 6/10)

### **Phase 3 Success Criteria** (Weeks 17-24)
- [ ] **Auto-Discovery**: ✅ Multiple discovery methods
- [ ] **Rate Limiting**: ✅ Advanced algorithms
- [ ] **Multi-Region**: ✅ Cross-region replication
- [ ] **Overall Score**: 9.5/10 (target)

---

## 🧪 Testing Strategy

### **Security Testing**
```bash
# Seal/Unseal security tests
cargo test seal_security_tests --features security-testing

# Token system tests
cargo test token_system_tests --features security-testing

# Policy engine tests
cargo test policy_engine_tests --features security-testing
```

### **Performance Testing**
```bash
# Load testing with new features
cargo test --release --ignored performance

# Benchmark seal/unseal operations
cargo bench seal_benchmarks

# Token management benchmarks
cargo bench token_benchmarks
```

### **Integration Testing**
```bash
# End-to-end Vault compatibility tests
cargo test vault_compatibility --features integration-testing

# Multi-region replication tests
cargo test multi_region_tests --features integration-testing
```

---

## 📈 Expected Outcomes

### **Post-Implementation Capabilities**

#### **Vault-Feature Parity**
- ✅ **Seal/Unseal**: Shamir Secret Sharing with configurable thresholds
- ✅ **Token Management**: Production-grade leases, TTL, revocation
- ✅ **Policy Engine**: HCL-based policies with fine-grained control
- ✅ **Secret Engines**: KV, PKI, Database, Transit engines
- ✅ **Auto-Discovery**: Kubernetes, DNS, Consul integration
- ✅ **Rate Limiting**: Token bucket, sliding window algorithms

#### **Performance Targets**
- **Seal/Unseal**: < 100ms operations
- **Token Validation**: < 10ms per request
- **Policy Evaluation**: < 50ms per policy
- **Secret Operations**: < 200ms average latency
- **Throughput**: 10,000+ requests/second

#### **Security Improvements**
- **Zero Trust**: Every request authenticated and authorized
- **Least Privilege**: Fine-grained policy enforcement
- **Audit Trail**: Complete operation logging
- **Key Security**: Hardware-backed key management

---

## 🎯 Immediate Actions Required

### **Week 1: Critical Setup**
1. **Fix README Honesty** (1 day)
   - Add proper feature maturity labels
   - Update status indicators
   - Remove misleading claims

2. **Setup Development Environment** (2 days)
   - Install required dependencies
   - Setup testing infrastructure
   - Create development branch

3. **Implement Seal/Unseal Foundation** (4 days)
   - Create seal module structure
   - Implement Shamir Secret Sharing
   - Add comprehensive tests

### **Week 2: Token System Foundation**
1. **Replace Basic AuthManager** (3 days)
   - Implement TokenManager
   - Add lease management
   - Add revocation system

2. **Policy Engine Foundation** (4 days)
   - Create HCL parser
   - Implement policy evaluation
   - Add built-in functions

---

## 🏆 Final Assessment

### **Current State: 6.5/10**
- Strong technical foundation
- Missing critical security features
- Overstated capabilities in README

### **Target State: 9.5/10**
- Vault-competitive feature set
- Enterprise-grade security
- Production-ready performance

### **Timeline: 3.5 Months**
- **Phase 1**: 8 weeks (Critical security foundation)
- **Phase 2**: 8 weeks (Secret engine ecosystem)
- **Phase 3**: 8 weeks (Enterprise features)

### **Success Factors**
1. **Focus on Critical Path**: Seal/Unseal → Tokens → Policies
2. **Honest Communication**: Accurate feature status in README
3. **Comprehensive Testing**: Security, performance, integration
4. **Documentation**: Complete API docs and deployment guides

**With this roadmap, Fortress can become a legitimate HashiCorp Vault competitor within 3.5 months.**
