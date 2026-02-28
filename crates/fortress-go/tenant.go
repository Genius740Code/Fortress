package fortress

import (
	"fmt"
	"sync"
	"time"
)

// TenantManager manages tenant isolation and configuration
type TenantManager struct {
	config  *Config
	tenants map[string]*TenantConfig
	stats   map[string]*TenantStats
	mu      sync.RWMutex
}

// NewTenantManager creates a new tenant manager
func NewTenantManager(config *Config) *TenantManager {
	return &TenantManager{
		config:  config,
		tenants: make(map[string]*TenantConfig),
		stats:   make(map[string]*TenantStats),
	}
}

// CreateTenant creates a new tenant
func (t *TenantManager) CreateTenant(config *TenantConfig) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tenantID := GenerateRandomString(16)
	tenantConfig := *config
	tenantConfig.ID = tenantID

	t.tenants[tenantID] = &tenantConfig
	t.stats[tenantID] = t.createDefaultStats(tenantID)

	return tenantID, nil
}

// GetTenant retrieves tenant configuration by ID
func (t *TenantManager) GetTenant(tenantID string) *TenantConfig {
	t.mu.RLock()
	defer t.mu.RUnlock()

	tenant, exists := t.tenants[tenantID]
	if !exists {
		return nil
	}
	return tenant
}

// UpdateTenant updates tenant configuration
func (t *TenantManager) UpdateTenant(tenantID string, updates *TenantConfig) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	tenant, exists := t.tenants[tenantID]
	if !exists {
		return false, NewTenantError("tenant not found", nil)
	}

	// Update fields
	if updates.Name != "" {
		tenant.Name = updates.Name
	}
	if updates.Description != "" {
		tenant.Description = updates.Description
	}
	if updates.IsolationLevel != "" {
		tenant.IsolationLevel = updates.IsolationLevel
	}

	return true, nil
}

// DeleteTenant deletes a tenant
func (t *TenantManager) DeleteTenant(tenantID string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, exists := t.tenants[tenantID]
	if exists {
		delete(t.tenants, tenantID)
		delete(t.stats, tenantID)
		return true, nil
	}
	return false, nil
}

// ListTenants returns all tenant IDs
func (t *TenantManager) ListTenants() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var tenantIDs []string
	for tenantID := range t.tenants {
		tenantIDs = append(tenantIDs, tenantID)
	}
	return tenantIDs
}

// GetTenantStats retrieves tenant statistics
func (t *TenantManager) GetTenantStats(tenantID string) *TenantStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	stats, exists := t.stats[tenantID]
	if !exists {
		return nil
	}
	return stats
}

// UpdateStats updates tenant statistics
func (t *TenantManager) UpdateStats(tenantID string, operation string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	stats, exists := t.stats[tenantID]
	if !exists {
		return NewTenantError("tenant not found", nil)
	}

	switch operation {
	case "encrypt":
		stats.TotalEncryptions++
	case "decrypt":
		stats.TotalDecryptions++
	}

	stats.LastActivity = time.Now()
	return nil
}

// CheckResourceLimits checks if tenant is within resource limits
func (t *TenantManager) CheckResourceLimits(tenantID string, resource string, amount int) (bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	tenant, exists := t.tenants[tenantID]
	stats, statsExists := t.stats[tenantID]

	if !exists || !statsExists {
		return false, NewTenantError("tenant not found", nil)
	}

	limits := tenant.ResourceLimits

	switch resource {
	case "keys":
		return stats.TotalKeys+amount <= limits.MaxKeys, nil
	case "storage":
		return int64(stats.StorageUsageBytes)+int64(amount) <= int64(limits.MaxStorageBytes), nil
	case "encryptions":
		return stats.TotalEncryptions+amount <= limits.MaxEncryptionsPerHour, nil
	case "decryptions":
		return stats.TotalDecryptions+amount <= limits.MaxDecryptionsPerHour, nil
	case "concurrent_operations":
		return amount <= limits.MaxConcurrentOperations, nil
	default:
		return true, nil
	}
}

// GetAllStats returns all tenant statistics
func (t *TenantManager) GetAllStats() map[string]*TenantStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make(map[string]*TenantStats)
	for tenantID, stats := range t.stats {
		// Return a copy to avoid mutation
		statsCopy := *stats
		result[tenantID] = &statsCopy
	}
	return result
}

// ResetStats resets tenant statistics
func (t *TenantManager) ResetStats(tenantID string) (bool, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, exists := t.tenants[tenantID]
	if !exists {
		return false, NewTenantError("tenant not found", nil)
	}

	t.stats[tenantID] = t.createDefaultStats(tenantID)
	return true, nil
}

// ValidateTenantConfig validates tenant configuration
func (t *TenantManager) ValidateTenantConfig(config *TenantConfig) error {
	if config.ID == "" {
		return NewValidationError("tenant ID is required", nil)
	}

	if config.Name == "" {
		return NewValidationError("tenant name is required", nil)
	}

	validIsolationLevels := []string{"strict", "shared", "partial"}
	isolationValid := false
	for _, level := range validIsolationLevels {
		if config.IsolationLevel == level {
			isolationValid = true
			break
		}
	}
	if !isolationValid {
		return NewValidationError("invalid tenant isolation level", nil)
	}

	if config.ResourceLimits.MaxKeys <= 0 {
		return NewValidationError("max keys must be positive", nil)
	}

	if config.ResourceLimits.MaxStorageBytes <= 0 {
		return NewValidationError("max storage bytes must be positive", nil)
	}

	return nil
}

// GetTenantsByIsolationLevel returns tenants by isolation level
func (t *TenantManager) GetTenantsByIsolationLevel(level string) []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var tenantIDs []string
	for tenantID, tenant := range t.tenants {
		if tenant.IsolationLevel == level {
			tenantIDs = append(tenantIDs, tenantID)
		}
	}
	return tenantIDs
}

// GetTenantsNearLimits returns tenants approaching resource limits
func (t *TenantManager) GetTenantsNearLimits(threshold float64) []TenantLimitWarning {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var warnings []TenantLimitWarning

	for tenantID, tenant := range t.tenants {
		stats := t.stats[tenantID]
		limits := tenant.ResourceLimits

		// Check each resource
		checks := []struct {
			resource string
			usage    int
			limit    int
		}{
			{"keys", stats.TotalKeys, limits.MaxKeys},
			{"storage", stats.StorageUsageBytes, limits.MaxStorageBytes},
			{"encryptions", stats.TotalEncryptions, limits.MaxEncryptionsPerHour},
			{"decryptions", stats.TotalDecryptions, limits.MaxDecryptionsPerHour},
		}

		for _, check := range checks {
			if check.limit > 0 && float64(check.usage)/float64(check.limit) >= threshold {
				warnings = append(warnings, TenantLimitWarning{
					TenantID: tenantID,
					Resource: check.resource,
					Usage:    check.usage,
					Limit:    check.limit,
				})
			}
		}
	}

	return warnings
}

// createDefaultStats creates default statistics for a tenant
func (t *TenantManager) createDefaultStats(tenantID string) *TenantStats {
	return &TenantStats{
		TenantID:          tenantID,
		TotalKeys:         0,
		ActiveKeys:        0,
		TotalEncryptions:   0,
		TotalDecryptions:   0,
		StorageUsageBytes: 0,
		AuditEntries:      0,
		LastActivity:      time.Now(),
	}
}

// TenantLimitWarning represents a warning about resource limits
type TenantLimitWarning struct {
	TenantID string `json:"tenant_id"`
	Resource string `json:"resource"`
	Usage    int    `json:"usage"`
	Limit    int    `json:"limit"`
}
