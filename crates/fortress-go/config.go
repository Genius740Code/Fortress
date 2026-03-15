package fortress

// DefaultConfig returns the default Fortress configuration
func DefaultConfig() *Config {
	return &Config{
		Encryption: EncryptionProfile{
			Name:      "default",
			Algorithm: "aegis256",
			KeySize:   32,
			NonceSize: 12,
			TagSize:   16,
		},
		Storage: StorageConfig{
			Backend:        "memory",
			MaxConnections: 10,
			TimeoutMs:      5000,
			RetryAttempts:  3,
			CacheSize:      1000,
		},
		Audit: AuditConfig{
			Enabled:  true,
			LogLevel: "info",
			StorageBackend: StorageConfig{
				Backend: "memory",
			},
			RetentionDays:   30,
			BatchSize:       100,
			FlushIntervalMs: 1000,
		},
		Policy: PolicyConfig{
			Name:           "default",
			Version:        "1.0.0",
			Rules:          []PolicyRule{},
			DefaultAction:  "deny",
			EvaluationMode: "all",
		},
		Tenant: TenantConfig{
			ID:             "default",
			Name:           "Default Tenant",
			IsolationLevel: "strict",
			ResourceLimits: ResourceLimits{
				MaxKeys:                 1000,
				MaxStorageBytes:         1024 * 1024 * 1024, // 1GB
				MaxEncryptionsPerHour:   10000,
				MaxDecryptionsPerHour:   10000,
				MaxConcurrentOperations: 100,
			},
			EncryptionProfile: "default",
			AuditConfig: AuditConfig{
				Enabled:  true,
				LogLevel: "info",
				StorageBackend: StorageConfig{
					Backend: "memory",
				},
			},
			PolicyConfig: PolicyConfig{
				Name:           "default",
				Version:        "1.0.0",
				Rules:          []PolicyRule{},
				DefaultAction:  "deny",
				EvaluationMode: "all",
			},
		},
		Debug:    false,
		LogLevel: "info",
	}
}

// LightningConfig returns a configuration optimized for speed
func LightningConfig() *Config {
	config := DefaultConfig()
	config.Encryption = EncryptionProfile{
		Name:      "lightning",
		Algorithm: "chacha20poly1305",
		KeySize:   32,
		NonceSize: 12,
		TagSize:   16,
	}
	config.Storage = StorageConfig{
		Backend:        "memory",
		MaxConnections: 50,
		TimeoutMs:      1000,
		RetryAttempts:  1,
		CacheSize:      10000,
	}
	config.Audit = AuditConfig{
		Enabled:       false,
		LogLevel:      "error",
		RetentionDays: 0,
	}
	config.Debug = false
	config.LogLevel = "error"
	return config
}

// BalancedConfig returns a balanced configuration
func BalancedConfig() *Config {
	config := DefaultConfig()
	config.Storage = StorageConfig{
		Backend:        "memory",
		MaxConnections: 20,
		TimeoutMs:      3000,
		RetryAttempts:  2,
		CacheSize:      5000,
	}
	config.Audit.RetentionDays = 7
	return config
}

// FortressConfig returns a configuration optimized for security
func FortressConfig() *Config {
	config := DefaultConfig()
	config.Encryption = EncryptionProfile{
		Name:       "fortress",
		Algorithm:  "aegis256",
		KeySize:    32,
		NonceSize:  12,
		TagSize:    16,
		Iterations: 3,
	}
	config.Storage = StorageConfig{
		Backend:        "file",
		MaxConnections: 10,
		TimeoutMs:      5000,
		RetryAttempts:  3,
		CacheSize:      1000,
	}
	return config
}

// EnterpriseConfig returns an enterprise-grade configuration
func EnterpriseConfig() *Config {
	config := DefaultConfig()
	config.Encryption = EncryptionProfile{
		Name:        "enterprise",
		Algorithm:   "composite_encrypt",
		KeySize:     64,
		NonceSize:   16,
		TagSize:     32,
		Iterations:  5,
		MemoryLimit: 1024 * 1024 * 64, // 64MB
	}
	config.Storage = StorageConfig{
		Backend:        "postgres",
		MaxConnections: 100,
		TimeoutMs:      10000,
		RetryAttempts:  5,
		CacheSize:      50000,
	}
	config.Audit = AuditConfig{
		Enabled:         true,
		LogLevel:        "debug",
		RetentionDays:   365,
		BatchSize:       1000,
		FlushIntervalMs: 500,
	}
	config.Debug = true
	config.LogLevel = "debug"
	return config
}

// StartupConfig returns a configuration optimized for startup
func StartupConfig() *Config {
	config := DefaultConfig()
	config.Encryption = EncryptionProfile{
		Name:      "startup",
		Algorithm: "aes256gcm",
		KeySize:   32,
		NonceSize: 12,
		TagSize:   16,
	}
	config.Storage = StorageConfig{
		Backend:        "memory",
		MaxConnections: 5,
		TimeoutMs:      2000,
		RetryAttempts:  1,
		CacheSize:      100,
	}
	config.Audit = AuditConfig{
		Enabled:  false,
		LogLevel: "warn",
	}
	config.Debug = false
	config.LogLevel = "warn"
	return config
}

// Clone creates a deep copy of the configuration
func (c *Config) Clone() *Config {
	// Create deep copy of all nested structures
	clone := &Config{
		Encryption: EncryptionProfile{
			Name:        c.Encryption.Name,
			Algorithm:   c.Encryption.Algorithm,
			KeySize:     c.Encryption.KeySize,
			NonceSize:   c.Encryption.NonceSize,
			TagSize:     c.Encryption.TagSize,
			Iterations:  c.Encryption.Iterations,
			MemoryLimit: c.Encryption.MemoryLimit,
		},
		Storage: StorageConfig{
			Backend:          c.Storage.Backend,
			ConnectionString: c.Storage.ConnectionString,
			MaxConnections:   c.Storage.MaxConnections,
			TimeoutMs:        c.Storage.TimeoutMs,
			RetryAttempts:    c.Storage.RetryAttempts,
			CacheSize:        c.Storage.CacheSize,
		},
		Audit: AuditConfig{
			Enabled:  c.Audit.Enabled,
			LogLevel: c.Audit.LogLevel,
			StorageBackend: StorageConfig{
				Backend:          c.Audit.StorageBackend.Backend,
				ConnectionString: c.Audit.StorageBackend.ConnectionString,
				MaxConnections:   c.Audit.StorageBackend.MaxConnections,
				TimeoutMs:        c.Audit.StorageBackend.TimeoutMs,
				RetryAttempts:    c.Audit.StorageBackend.RetryAttempts,
				CacheSize:        c.Audit.StorageBackend.CacheSize,
			},
			RetentionDays:   c.Audit.RetentionDays,
			BatchSize:       c.Audit.BatchSize,
			FlushIntervalMs: c.Audit.FlushIntervalMs,
		},
		Policy: PolicyConfig{
			Name:           c.Policy.Name,
			Version:        c.Policy.Version,
			Rules:          make([]PolicyRule, len(c.Policy.Rules)),
			DefaultAction:  c.Policy.DefaultAction,
			EvaluationMode: c.Policy.EvaluationMode,
		},
		Tenant: TenantConfig{
			ID:             c.Tenant.ID,
			Name:           c.Tenant.Name,
			Description:    c.Tenant.Description,
			IsolationLevel: c.Tenant.IsolationLevel,
			ResourceLimits: ResourceLimits{
				MaxKeys:                 c.Tenant.ResourceLimits.MaxKeys,
				MaxStorageBytes:         c.Tenant.ResourceLimits.MaxStorageBytes,
				MaxEncryptionsPerHour:   c.Tenant.ResourceLimits.MaxEncryptionsPerHour,
				MaxDecryptionsPerHour:   c.Tenant.ResourceLimits.MaxDecryptionsPerHour,
				MaxConcurrentOperations: c.Tenant.ResourceLimits.MaxConcurrentOperations,
			},
			EncryptionProfile: c.Tenant.EncryptionProfile,
			AuditConfig: AuditConfig{
				Enabled:  c.Tenant.AuditConfig.Enabled,
				LogLevel: c.Tenant.AuditConfig.LogLevel,
				StorageBackend: StorageConfig{
					Backend:          c.Tenant.AuditConfig.StorageBackend.Backend,
					ConnectionString: c.Tenant.AuditConfig.StorageBackend.ConnectionString,
					MaxConnections:   c.Tenant.AuditConfig.StorageBackend.MaxConnections,
					TimeoutMs:        c.Tenant.AuditConfig.StorageBackend.TimeoutMs,
					RetryAttempts:    c.Tenant.AuditConfig.StorageBackend.RetryAttempts,
					CacheSize:        c.Tenant.AuditConfig.StorageBackend.CacheSize,
				},
			},
			PolicyConfig: PolicyConfig{
				Name:           c.Tenant.PolicyConfig.Name,
				Version:        c.Tenant.PolicyConfig.Version,
				Rules:          make([]PolicyRule, len(c.Tenant.PolicyConfig.Rules)),
				DefaultAction:  c.Tenant.PolicyConfig.DefaultAction,
				EvaluationMode: c.Tenant.PolicyConfig.EvaluationMode,
			},
		},
		Debug:    c.Debug,
		LogLevel: c.LogLevel,
	}

	// Deep copy policy rules
	for i, rule := range c.Policy.Rules {
		clone.Policy.Rules[i] = PolicyRule{
			ID:          rule.ID,
			Name:        rule.Name,
			Conditions:  make([]Condition, len(rule.Conditions)),
			Permissions: make([]Permission, len(rule.Permissions)),
			Action:      rule.Action,
			Priority:    rule.Priority,
			Enabled:     rule.Enabled,
		}
		copy(clone.Policy.Rules[i].Conditions, rule.Conditions)
		copy(clone.Policy.Rules[i].Permissions, rule.Permissions)
	}

	// Deep copy tenant policy rules
	for i, rule := range c.Tenant.PolicyConfig.Rules {
		clone.Tenant.PolicyConfig.Rules[i] = PolicyRule{
			ID:          rule.ID,
			Name:        rule.Name,
			Conditions:  make([]Condition, len(rule.Conditions)),
			Permissions: make([]Permission, len(rule.Permissions)),
			Action:      rule.Action,
			Priority:    rule.Priority,
			Enabled:     rule.Enabled,
		}
		copy(clone.Tenant.PolicyConfig.Rules[i].Conditions, rule.Conditions)
		copy(clone.Tenant.PolicyConfig.Rules[i].Permissions, rule.Permissions)
	}

	return clone
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.Encryption.KeySize <= 0 {
		return NewValidationError("encryption key size must be positive", nil)
	}
	if c.Encryption.NonceSize <= 0 {
		return NewValidationError("encryption nonce size must be positive", nil)
	}
	if c.Encryption.TagSize <= 0 {
		return NewValidationError("encryption tag size must be positive", nil)
	}

	if c.Storage.MaxConnections <= 0 {
		return NewValidationError("storage max connections must be positive", nil)
	}
	if c.Storage.TimeoutMs <= 0 {
		return NewValidationError("storage timeout must be positive", nil)
	}

	if c.Audit.BatchSize <= 0 {
		return NewValidationError("audit batch size must be positive", nil)
	}

	validIsolationLevels := []string{"strict", "shared", "partial"}
	isolationValid := false
	for _, level := range validIsolationLevels {
		if c.Tenant.IsolationLevel == level {
			isolationValid = true
			break
		}
	}
	if !isolationValid {
		return NewValidationError("invalid tenant isolation level", nil)
	}

	if c.Tenant.ResourceLimits.MaxKeys <= 0 {
		return NewValidationError("max keys must be positive", nil)
	}
	if c.Tenant.ResourceLimits.MaxStorageBytes <= 0 {
		return NewValidationError("max storage bytes must be positive", nil)
	}

	return nil
}
