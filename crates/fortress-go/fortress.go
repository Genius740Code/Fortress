// Package fortress provides Go bindings for the Fortress secure database system
//
// Fortress is a high-performance, secure database system with enterprise-grade encryption,
// key management, and multi-tenant isolation capabilities.
//
// Example usage:
//
//	fortress, err := fortress.New()
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer fortress.Close()
//
//	// Encrypt data
//	plaintext := []byte("Hello, Fortress!")
//	ciphertext, err := fortress.Encrypt(plaintext, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	// Decrypt data
//	decrypted, err := fortress.Decrypt(ciphertext, nil)
//	if err != nil {
//		log.Fatal(err)
//	}
//
//	fmt.Printf("Decrypted: %s\n", decrypted)
package fortress

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"runtime"
	"sync"
	"time"
)

// Version information
const (
	Version     = "1.0.0"
	APIVersion  = "1.0.0"
	BuildTime   = "unknown"
	GitCommit   = "unknown"
	RustVersion = "unknown"
)

// Fortress is the main client for the Fortress secure database system
type Fortress struct {
	config      *Config
	keyManager  *KeyManager
	storage     *StorageBackend
	policy      *PolicyEngine
	audit       *AuditLogger
	tenant      *TenantManager
	mu          sync.RWMutex
	initialized bool
	wasmLoaded  bool
}

// New creates a new Fortress client with the default configuration
func New() (*Fortress, error) {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig creates a new Fortress client with the specified configuration
func NewWithConfig(config *Config) (*Fortress, error) {
	if config == nil {
		config = DefaultConfig()
	}

	f := &Fortress{
		config: config,
	}

	// Initialize components
	f.keyManager = NewKeyManager(config)
	f.storage = NewStorageBackend(config)
	f.policy = NewPolicyEngine(config)
	f.audit = NewAuditLogger(config)
	f.tenant = NewTenantManager(config)

	f.initialized = true
	return f, nil
}

// Initialize initializes the Fortress client
func (f *Fortress) Initialize() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.initialized {
		return nil
	}

	// Initialize WASM module if available
	if err := f.initializeWASM(); err != nil {
		// Log warning but continue - WASM is optional for Go bindings
		fmt.Printf("Warning: WASM initialization failed: %v\n", err)
	}

	f.initialized = true
	return nil
}

// Close closes the Fortress client and cleans up resources
func (f *Fortress) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.initialized {
		return nil
	}

	var errs []error

	if err := f.storage.Close(); err != nil {
		errs = append(errs, fmt.Errorf("storage close error: %w", err))
	}

	if err := f.audit.Flush(); err != nil {
		errs = append(errs, fmt.Errorf("audit flush error: %w", err))
	}

	f.initialized = false

	if len(errs) > 0 {
		return fmt.Errorf("multiple errors during close: %v", errs)
	}

	return nil
}

// Version returns the Fortress version information
func (f *Fortress) Version() string {
	return Version
}

// BuildInfo returns build information
func (f *Fortress) BuildInfo() *BuildInfo {
	return &BuildInfo{
		Timestamp:   BuildTime,
		GitSHA:      GitCommit,
		RustVersion: RustVersion,
		Target:      "unknown",
	}
}

// HealthCheck performs a health check on all components
func (f *Fortress) HealthCheck() *HealthStatus {
	f.mu.RLock()
	defer f.mu.RUnlock()

	status := &HealthStatus{
		Status:  "healthy",
		Details: make(map[string]interface{}),
	}

	// Check WASM support
	status.Details["wasm_support"] = f.checkWASMSupport()
	status.Details["version"] = f.Version()
	status.Details["algorithms"] = f.ListAlgorithms()

	// Check storage health
	if err := f.storage.HealthCheck(); err != nil {
		status.Status = "unhealthy"
		status.Details["storage_error"] = err.Error()
	}

	// Check key manager health
	if err := f.keyManager.HealthCheck(); err != nil {
		status.Status = "unhealthy"
		status.Details["key_manager_error"] = err.Error()
	}

	return status
}

// ListAlgorithms returns the list of available encryption algorithms
func (f *Fortress) ListAlgorithms() []string {
	return []string{
		"aegis256",
		"chacha20poly1305",
		"aes256gcm",
		"xchacha20poly1305",
		"blake3_encrypt",
		"hmacsha512_encrypt",
		"aes256ctr",
		"argon2id_encrypt",
		"composite_encrypt",
	}
}

// Encrypt encrypts data using the specified options
func (f *Fortress) Encrypt(plaintext []byte, options *EncryptionOptions) ([]byte, error) {
	if !f.initialized {
		return nil, ErrNotInitialized
	}

	if options == nil {
		options = &EncryptionOptions{
			Algorithm: "aegis256",
		}
	}

	// Generate or get key
	var key []byte
	var err error

	if options.KeyID != "" {
		key, err = f.keyManager.GetKey(options.KeyID)
		if err != nil {
			return nil, fmt.Errorf("failed to get key: %w", err)
		}
	} else {
		key, err = f.keyManager.GenerateKey(&KeyGenerationOptions{
			Algorithm: options.Algorithm,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
	}

	// Create algorithm
	algorithm := f.CreateAlgorithm(options.Algorithm)

	// Encrypt
	ciphertext, err := algorithm.Encrypt(plaintext, key, options)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// Log audit entry
	if f.config.Audit.Enabled {
		f.audit.LogSuccess("default", "system", "encrypt", &Resource{
			Type: "data",
			ID:   "encrypted",
		}, map[string]interface{}{
			"algorithm": options.Algorithm,
			"size":      len(plaintext),
		})
	}

	return ciphertext, nil
}

// Decrypt decrypts data using the specified key ID and algorithm
func (f *Fortress) Decrypt(ciphertext []byte, keyID string, algorithm string) ([]byte, error) {
	if !f.initialized {
		return nil, ErrNotInitialized
	}

	if keyID == "" {
		return nil, ErrKeyIDRequired
	}

	// Get key
	key, err := f.keyManager.GetKey(keyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	// Create algorithm
	alg := f.CreateAlgorithm(algorithm)

	// Decrypt
	plaintext, err := alg.Decrypt(ciphertext, key)
	if err != nil {
		// Log audit entry for failure
		if f.config.Audit.Enabled {
			f.audit.LogFailure("default", "system", "decrypt", &Resource{
				Type: "data",
				ID:   "decrypted",
			}, err.Error(), map[string]interface{}{
				"algorithm": algorithm,
				"key_id":    keyID,
			})
		}
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	// Log audit entry for success
	if f.config.Audit.Enabled {
		f.audit.LogSuccess("default", "system", "decrypt", &Resource{
			Type: "data",
			ID:   "decrypted",
		}, map[string]interface{}{
			"algorithm": algorithm,
			"key_id":    keyID,
			"size":      len(plaintext),
		})
	}

	return plaintext, nil
}

// CreateAlgorithm creates a new encryption algorithm instance
func (f *Fortress) CreateAlgorithm(algorithm string) *EncryptionAlgorithm {
	return NewEncryptionAlgorithm(algorithm, f.config)
}

// GenerateKey generates a new encryption key
func (f *Fortress) GenerateKey(options *KeyGenerationOptions) ([]byte, error) {
	if !f.initialized {
		return nil, ErrNotInitialized
	}

	return f.keyManager.GenerateKey(options)
}

// ImportKey imports an existing key
func (f *Fortress) ImportKey(keyData []byte, algorithm string) (string, error) {
	if !f.initialized {
		return "", ErrNotInitialized
	}

	return f.keyManager.ImportKey(keyData, algorithm)
}

// ExportKey exports a key by ID
func (f *Fortress) ExportKey(keyID string) ([]byte, error) {
	if !f.initialized {
		return nil, ErrNotInitialized
	}

	return f.keyManager.ExportKey(keyID)
}

// DeleteKey deletes a key by ID
func (f *Fortress) DeleteKey(keyID string) error {
	if !f.initialized {
		return ErrNotInitialized
	}

	return f.keyManager.DeleteKey(keyID)
}

// ListKeys returns a list of all key IDs
func (f *Fortress) ListKeys() ([]string, error) {
	if !f.initialized {
		return nil, ErrNotInitialized
	}

	return f.keyManager.ListKeys()
}

// GetKeyManager returns the key manager instance
func (f *Fortress) GetKeyManager() *KeyManager {
	return f.keyManager
}

// GetStorage returns the storage backend instance
func (f *Fortress) GetStorage() *StorageBackend {
	return f.storage
}

// GetPolicyEngine returns the policy engine instance
func (f *Fortress) GetPolicyEngine() *PolicyEngine {
	return f.policy
}

// GetAuditLogger returns the audit logger instance
func (f *Fortress) GetAuditLogger() *AuditLogger {
	return f.audit
}

// GetTenantManager returns the tenant manager instance
func (f *Fortress) GetTenantManager() *TenantManager {
	return f.tenant
}

// GetConfig returns the current configuration
func (f *Fortress) GetConfig() *Config {
	return f.config
}

// UpdateConfig updates the configuration
func (f *Fortress) UpdateConfig(config *Config) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.config = config
}

// initializeWASM initializes the WASM module if available
func (f *Fortress) initializeWASM() error {
	// Check if we're running in a WASM-compatible environment
	if !f.checkWASMSupport() {
		return fmt.Errorf("WASM not supported in this environment")
	}

	// For Go bindings, WASM integration would typically involve:
	// 1. Loading the WASM module from embedded resources or external file
	// 2. Setting up the WASM runtime
	// 3. Initializing the Fortress core functions
	//
	// Since this is a pure Go implementation, we'll simulate WASM loading
	// In a real implementation, this would use syscall/js or wasmtime-go

	f.wasmLoaded = true
	return nil
}

// checkWASMSupport checks if WebAssembly is supported
func (f *Fortress) checkWASMSupport() bool {
	// Check if running in browser or WASM-compatible environment
	if runtime.GOOS == "js" || runtime.GOARCH == "wasm" {
		return true
	}

	// For server-side Go, WASM support would require a WASM runtime
	// This is a placeholder check - in practice, you'd check for
	// specific WASM runtime libraries or capabilities
	return false
}

// GenerateRandomBytes generates cryptographically secure random bytes
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return bytes, nil
}

// GenerateRandomString generates a random string of the specified length
func GenerateRandomString(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	bytes, err := GenerateRandomBytes(length)
	if err != nil {
		return "", err
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}

	return string(bytes), nil
}

// JSONMarshal marshals data to JSON with error handling
func JSONMarshal(data interface{}) ([]byte, error) {
	return json.Marshal(data)
}

// JSONUnmarshal unmarshals JSON data with error handling
func JSONUnmarshal(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}

// TimeNow returns the current time
func TimeNow() time.Time {
	return time.Now()
}

// TimeUnix returns the current Unix timestamp
func TimeUnix() int64 {
	return time.Now().Unix()
}
