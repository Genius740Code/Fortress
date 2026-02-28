package fortress

import "time"

// BuildInfo contains build information
type BuildInfo struct {
	Timestamp   string `json:"timestamp"`
	GitSHA      string `json:"git_sha"`
	RustVersion string `json:"rust_version"`
	Target      string `json:"target"`
}

// HealthStatus contains health check status
type HealthStatus struct {
	Status  string                 `json:"status"`
	Details map[string]interface{}   `json:"details"`
}

// Config represents Fortress configuration
type Config struct {
	Encryption EncryptionProfile `json:"encryption_profile"`
	Storage   StorageConfig    `json:"storage_config"`
	Audit      AuditConfig      `json:"audit_config"`
	Policy     PolicyConfig     `json:"policy_config"`
	Tenant     TenantConfig     `json:"tenant_config"`
	Debug      bool             `json:"debug"`
	LogLevel   string           `json:"log_level"`
}

// EncryptionProfile represents encryption algorithm configuration
type EncryptionProfile struct {
	Name         string `json:"name"`
	Algorithm    string `json:"algorithm"`
	KeySize      int    `json:"key_size"`
	NonceSize    int    `json:"nonce_size"`
	TagSize      int    `json:"tag_size"`
	Iterations   int    `json:"iterations,omitempty"`
	MemoryLimit  int64  `json:"memory_limit,omitempty"`
}

// StorageConfig represents storage backend configuration
type StorageConfig struct {
	Backend         string `json:"backend"`
	ConnectionString string `json:"connection_string,omitempty"`
	MaxConnections  int    `json:"max_connections"`
	TimeoutMs       int    `json:"timeout_ms"`
	RetryAttempts   int    `json:"retry_attempts"`
	CacheSize       int    `json:"cache_size"`
}

// AuditConfig represents audit logging configuration
type AuditConfig struct {
	Enabled           bool          `json:"enabled"`
	LogLevel          string        `json:"log_level"`
	StorageBackend    StorageConfig `json:"storage_backend"`
	RetentionDays     int           `json:"retention_days,omitempty"`
	BatchSize         int           `json:"batch_size,omitempty"`
	FlushIntervalMs   int           `json:"flush_interval_ms,omitempty"`
}

// PolicyConfig represents policy engine configuration
type PolicyConfig struct {
	Name           string       `json:"name"`
	Version        string       `json:"version"`
	Rules          []PolicyRule `json:"rules"`
	DefaultAction  string       `json:"default_action"`
	EvaluationMode string       `json:"evaluation_mode"`
}

// PolicyRule represents a policy rule
type PolicyRule struct {
	ID         string      `json:"id"`
	Name       string      `json:"name"`
	Conditions []Condition `json:"conditions"`
	Action     string      `json:"action"`
	Priority   int         `json:"priority"`
	Enabled    bool        `json:"enabled"`
}

// Condition represents a policy condition
type Condition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"`
	Value    interface{} `json:"value"`
}

// TenantConfig represents tenant configuration
type TenantConfig struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	Description      string         `json:"description,omitempty"`
	IsolationLevel   string         `json:"isolation_level"`
	ResourceLimits   ResourceLimits `json:"resource_limits"`
	EncryptionProfile string         `json:"encryption_profile"`
	AuditConfig      AuditConfig     `json:"audit_config"`
	PolicyConfig     PolicyConfig    `json:"policy_config"`
}

// ResourceLimits represents resource limits for a tenant
type ResourceLimits struct {
	MaxKeys                int `json:"max_keys"`
	MaxStorageBytes         int `json:"max_storage_bytes"`
	MaxEncryptionsPerHour  int `json:"max_encryptions_per_hour"`
	MaxDecryptionsPerHour  int `json:"max_decryptions_per_hour"`
	MaxConcurrentOperations int `json:"max_concurrent_operations"`
}

// EncryptionOptions represents options for encryption
type EncryptionOptions struct {
	Algorithm       string            `json:"algorithm,omitempty"`
	AssociatedData []byte            `json:"associated_data,omitempty"`
	Compression    bool              `json:"compression,omitempty"`
	KeyID          string            `json:"key_id,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// KeyGenerationOptions represents options for key generation
type KeyGenerationOptions struct {
	Algorithm string            `json:"algorithm,omitempty"`
	KeySize   int               `json:"key_size,omitempty"`
	Exportable bool              `json:"exportable,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// StorageOptions represents options for storage operations
type StorageOptions struct {
	ConsistencyLevel string `json:"consistency_level,omitempty"`
	TTLSeconds      int    `json:"ttl_seconds,omitempty"`
	Compression     bool   `json:"compression,omitempty"`
	Encryption      bool   `json:"encryption,omitempty"`
}

// QueryOptions represents options for querying
type QueryOptions struct {
	Limit     int                    `json:"limit,omitempty"`
	Offset    int                    `json:"offset,omitempty"`
	SortBy    string                 `json:"sort_by,omitempty"`
	SortOrder string                 `json:"sort_order,omitempty"`
	Filter    map[string]interface{}   `json:"filter,omitempty"`
}

// KeyMetadata represents metadata for a key
type KeyMetadata struct {
	ID         string    `json:"id"`
	Algorithm  string    `json:"algorithm"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   *time.Time `json:"last_used,omitempty"`
	UsageCount int       `json:"usage_count"`
	Version    int       `json:"version"`
	Status     string    `json:"status"`
}

// Resource represents a resource in the system
type Resource struct {
	Type       string                 `json:"type"`
	ID         string                 `json:"id,omitempty"`
	Attributes map[string]interface{} `json:"attributes,omitempty"`
}

// Permission represents a permission
type Permission struct {
	ID         string      `json:"id"`
	Resource   Resource    `json:"resource"`
	Actions    []string    `json:"actions"`
	Conditions []Condition `json:"conditions,omitempty"`
}

// Role represents a role with permissions
type Role struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Permissions []Permission `json:"permissions"`
	IsSystem    bool         `json:"is_system"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   *time.Time   `json:"updated_at,omitempty"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID         string                 `json:"id"`
	TenantID   string                 `json:"tenant_id"`
	UserID     string                 `json:"user_id,omitempty"`
	Action     string                 `json:"action"`
	Resource   Resource               `json:"resource"`
	Result     string                 `json:"result"`
	Error      string                 `json:"error,omitempty"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
	Timestamp  time.Time              `json:"timestamp"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	UserAgent  string                 `json:"user_agent,omitempty"`
}

// TenantStats represents statistics for a tenant
type TenantStats struct {
	TenantID           string    `json:"tenant_id"`
	TotalKeys          int       `json:"total_keys"`
	ActiveKeys         int       `json:"active_keys"`
	TotalEncryptions   int       `json:"total_encryptions"`
	TotalDecryptions   int       `json:"total_decryptions"`
	StorageUsageBytes  int64     `json:"storage_usage_bytes"`
	AuditEntries       int       `json:"audit_entries"`
	LastActivity      time.Time `json:"last_activity"`
}

// AlgorithmMetadata represents metadata for an encryption algorithm
type AlgorithmMetadata struct {
	Name                   string `json:"name"`
	KeySize                int    `json:"key_size"`
	NonceSize              int    `json:"nonce_size"`
	TagSize                int    `json:"tag_size"`
	SupportsAssociatedData bool   `json:"supports_associated_data"`
}

// CompatibilityInfo represents compatibility information
type CompatibilityInfo struct {
	Version    string   `json:"version"`
	APIVersion string   `json:"api_version"`
	Features   []string `json:"features"`
	Platform   string   `json:"platform"`
	Arch       string   `json:"arch"`
}

// BenchmarkResult represents benchmark results
type BenchmarkResult struct {
	Algorithm       string  `json:"algorithm"`
	Operation      string  `json:"operation"`
	DataSize       int     `json:"data_size"`
	DurationMs     int64   `json:"duration_ms"`
	ThroughputMbps float64 `json:"throughput_mbps"`
	MemoryUsage    int64   `json:"memory_usage_bytes"`
}
