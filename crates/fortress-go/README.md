# Fortress Go SDK

The Go SDK for Fortress secure database system provides enterprise-grade encryption, key management, and multi-tenant isolation capabilities.

## Installation

```bash
go get github.com/Genius740Code/Fortress/fortress-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/Genius740Code/Fortress/fortress-go"
)

func main() {
    // Create a new Fortress client
    f, err := fortress.New()
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    // Encrypt data
    plaintext := []byte("Hello, Fortress!")
    ciphertext, err := f.Encrypt(plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Encrypted: %x\n", ciphertext)

    // Decrypt data (note: in real usage, you'd store and retrieve the key ID)
    // For this example, we'll skip the decryption step
    fmt.Println("Data encrypted successfully!")
}
```

## Configuration

### Default Configuration

```go
f, err := fortress.New()
```

### Predefined Configurations

```go
// Lightning fast configuration
f, err := fortress.NewWithConfig(fortress.LightningConfig())

// Balanced configuration
f, err := fortress.NewWithConfig(fortress.BalancedConfig())

// Fortress security configuration
f, err := fortress.NewWithConfig(fortress.FortressConfig())

// Enterprise configuration
f, err := fortress.NewWithConfig(fortress.EnterpriseConfig())

// Startup configuration
f, err := fortress.NewWithConfig(fortress.StartupConfig())
```

### Custom Configuration

```go
config := &fortress.Config{
    Encryption: fortress.EncryptionProfile{
        Name:      "custom",
        Algorithm: "aegis256",
        KeySize:   32,
        NonceSize: 12,
        TagSize:   16,
    },
    Storage: fortress.StorageConfig{
        Backend:        "memory",
        MaxConnections: 20,
        TimeoutMs:      5000,
        RetryAttempts:  3,
        CacheSize:      1000,
    },
    Debug:    true,
    LogLevel: "info",
}

f, err := fortress.NewWithConfig(config)
```

## Key Management

### Generate a Key

```go
key, err := f.GenerateKey(&fortress.KeyGenerationOptions{
    Algorithm: "aegis256",
    KeySize:   32,
})
if err != nil {
    log.Fatal(err)
}
```

### Import a Key

```go
keyID, err := f.ImportKey(existingKey, "aegis256")
if err != nil {
    log.Fatal(err)
}
```

### Export a Key

```go
keyData, err := f.ExportKey(keyID)
if err != nil {
    log.Fatal(err)
}
```

### List Keys

```go
keyIDs, err := f.ListKeys()
if err != nil {
    log.Fatal(err)
}

for _, id := range keyIDs {
    fmt.Printf("Key ID: %s\n", id)
}
```

### Delete a Key

```go
err = f.DeleteKey(keyID)
if err != nil {
    log.Fatal(err)
}
```

## Encryption and Decryption

### Basic Encryption

```go
plaintext := []byte("Hello, Fortress!")
ciphertext, err := f.Encrypt(plaintext, nil)
if err != nil {
    log.Fatal(err)
}
```

### Encryption with Options

```go
options := &fortress.EncryptionOptions{
    Algorithm: "aegis256",
    KeyID:     "your-key-id",
    Compression: true,
    Metadata: map[string]interface{}{
        "purpose": "test",
        "owner":   "demo",
    },
}

ciphertext, err := f.Encrypt(plaintext, options)
if err != nil {
    log.Fatal(err)
}
```

### Decryption

```go
plaintext, err := f.Decrypt(ciphertext, keyID, "aegis256")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Decrypted: %s\n", plaintext)
```

## Storage Operations

```go
storage := f.GetStorage()

// Store data
err := storage.Store("my-key", data, nil)
if err != nil {
    log.Fatal(err)
}

// Retrieve data
value, err := storage.Retrieve("my-key")
if err != nil {
    log.Fatal(err)
}

// Delete data
deleted, err := storage.Delete("my-key")
if err != nil {
    log.Fatal(err)
}

// List keys
keys, err := storage.ListKeys()
if err != nil {
    log.Fatal(err)
}
```

## Policy Engine

```go
policy := f.GetPolicyEngine()

// Add a policy
policyConfig := fortress.PolicyConfig{
    Name:           "my-policy",
    Version:        "1.0.0",
    Rules:          []fortress.PolicyRule{},
    DefaultAction:  "deny",
    EvaluationMode: "all",
}
policy.AddPolicy(policyConfig)

// Evaluate permission
allowed, err := policy.EvaluatePermission(
    "user-123",
    fortress.Resource{Type: "data", ID: "secret-456"},
    "read",
    map[string]interface{}{"department": "engineering"},
)
if err != nil {
    log.Fatal(err)
}

if allowed {
    fmt.Println("Access granted")
} else {
    fmt.Println("Access denied")
}
```

## Audit Logging

```go
audit := f.GetAuditLogger()

// Log successful operation
err = audit.LogSuccess("tenant-123", "user-456", "encrypt", 
    fortress.Resource{Type: "data", ID: "file-789"},
    map[string]interface{}{"size": 1024})

// Log failed operation
err = audit.LogFailure("tenant-123", "user-456", "decrypt",
    fortress.Resource{Type: "data", ID: "file-789"},
    "Invalid key",
    map[string]interface{}{"attempt": 3})

// Query audit entries
entries, err := audit.Query(&fortress.AuditQueryOptions{
    TenantID: "tenant-123",
    Limit:    100,
})
if err != nil {
    log.Fatal(err)
}

for _, entry := range entries {
    fmt.Printf("Entry: %+v\n", entry)
}
```

## Tenant Management

```go
tenant := f.GetTenantManager()

// Create a new tenant
tenantID, err := tenant.CreateTenant(fortress.TenantConfig{
    Name:           "My Tenant",
    Description:    "A test tenant",
    IsolationLevel: "strict",
    ResourceLimits: fortress.ResourceLimits{
        MaxKeys:                1000,
        MaxStorageBytes:         1024 * 1024 * 1024, // 1GB
        MaxEncryptionsPerHour:  10000,
        MaxDecryptionsPerHour:  10000,
        MaxConcurrentOperations: 100,
    },
})
if err != nil {
    log.Fatal(err)
}

// Get tenant configuration
tenantConfig := tenant.GetTenant(tenantID)
if tenantConfig != nil {
    fmt.Printf("Tenant: %+v\n", tenantConfig)
}

// Get tenant statistics
stats := tenant.GetTenantStats(tenantID)
if stats != nil {
    fmt.Printf("Stats: %+v\n", stats)
}
```

## Health Checks

```go
status := f.HealthCheck()
fmt.Printf("Health Status: %s\n", status.Status)
for key, value := range status.Details {
    fmt.Printf("  %s: %v\n", key, value)
}
```

## Error Handling

The Go SDK uses custom error types that provide detailed information:

```go
_, err := f.Encrypt(data, nil)
if err != nil {
    if fortressErr, ok := err.(*fortress.FortressError); ok {
        fmt.Printf("Error Code: %s\n", fortressErr.Code)
        fmt.Printf("Error Kind: %s\n", fortressErr.Kind)
        fmt.Printf("Is Retryable: %t\n", fortressErr.IsRetryable)
        fmt.Printf("Is Temporary: %t\n", fortressErr.IsTemporary)
    }
    log.Fatal(err)
}
```

## Supported Algorithms

- `aegis256` - AEGIS-256 (recommended)
- `chacha20poly1305` - ChaCha20-Poly1305
- `aes256gcm` - AES-256-GCM
- `xchacha20poly1305` - XChaCha20-Poly1305
- `blake3_encrypt` - BLAKE3-based encryption
- `hmacsha512_encrypt` - HMAC-SHA512-based encryption
- `aes256ctr` - AES-256-CTR
- `argon2id_encrypt` - Argon2id-based encryption
- `composite_encrypt` - Composite encryption (enterprise)

## License

Apache License 2.0
