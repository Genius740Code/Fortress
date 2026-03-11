package fortress

import (
	"crypto/rand"
	"sync"
)

// KeyManager manages encryption keys
type KeyManager struct {
	config *Config
	keys   map[string]*KeyMetadata
	mu     sync.RWMutex
}

// NewKeyManager creates a new key manager
func NewKeyManager(config *Config) *KeyManager {
	return &KeyManager{
		config: config,
		keys:   make(map[string]*KeyMetadata),
	}
}

// GenerateKey generates a new encryption key
func (km *KeyManager) GenerateKey(options *KeyGenerationOptions) ([]byte, error) {
	if options == nil {
		options = &KeyGenerationOptions{
			Algorithm: km.config.Encryption.Algorithm,
			KeySize:   km.config.Encryption.KeySize,
		}
	}

	// Determine key size
	keySize := options.KeySize
	if keySize == 0 {
		keySize = km.config.Encryption.KeySize
	}

	// Generate random key
	key := make([]byte, keySize)
	if _, err := rand.Read(key); err != nil {
		return nil, NewKeyManagementError("failed to generate random key", err)
	}

	// Store key metadata
	keyID, err := GenerateRandomString(16)
	if err != nil {
		return nil, NewKeyManagementError("failed to generate key ID", err)
	}

	metadata := &KeyMetadata{
		ID:         keyID,
		Algorithm:  options.Algorithm,
		CreatedAt:  TimeNow(),
		UsageCount: 0,
		Version:    1,
		Status:     "active",
	}

	km.mu.Lock()
	km.keys[keyID] = metadata
	km.mu.Unlock()

	return key, nil
}

// ImportKey imports an existing key
func (km *KeyManager) ImportKey(keyData []byte, algorithm string) (string, error) {
	keyID, err := GenerateRandomString(16)
	if err != nil {
		return "", NewKeyManagementError("failed to generate key ID", err)
	}

	metadata := &KeyMetadata{
		ID:         keyID,
		Algorithm:  algorithm,
		CreatedAt:  TimeNow(),
		UsageCount: 0,
		Version:    1,
		Status:     "active",
	}

	km.mu.Lock()
	km.keys[keyID] = metadata
	km.mu.Unlock()

	// TODO: Actually store the key data securely
	// For now, we're just storing metadata

	return keyID, nil
}

// ExportKey exports a key by ID
func (km *KeyManager) ExportKey(keyID string) ([]byte, error) {
	km.mu.RLock()
	_, exists := km.keys[keyID]
	km.mu.RUnlock()

	if !exists {
		return nil, NewKeyManagementError("key not found", nil)
	}

	// TODO: Actually export the key data securely
	// For now, return a placeholder
	return make([]byte, km.config.Encryption.KeySize), nil
}

// DeleteKey deletes a key by ID
func (km *KeyManager) DeleteKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	if _, exists := km.keys[keyID]; !exists {
		return NewKeyManagementError("key not found", nil)
	}

	delete(km.keys, keyID)
	return nil
}

// GetKey retrieves a key by ID
func (km *KeyManager) GetKey(keyID string) ([]byte, error) {
	km.mu.RLock()
	metadata, exists := km.keys[keyID]
	km.mu.RUnlock()

	if !exists {
		return nil, NewKeyManagementError("key not found", nil)
	}

	// Update usage count
	km.mu.Lock()
	metadata.UsageCount++
	now := TimeNow()
	metadata.LastUsed = &now
	km.mu.Unlock()

	// TODO: Actually retrieve the key data securely
	// For now, return a placeholder
	return make([]byte, km.config.Encryption.KeySize), nil
}

// GetKeyMetadata retrieves key metadata by ID
func (km *KeyManager) GetKeyMetadata(keyID string) (*KeyMetadata, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	metadata, exists := km.keys[keyID]
	if !exists {
		return nil, NewKeyManagementError("key not found", nil)
	}

	// Return a copy to avoid mutation
	return &KeyMetadata{
		ID:         metadata.ID,
		Algorithm:  metadata.Algorithm,
		CreatedAt:  metadata.CreatedAt,
		LastUsed:   metadata.LastUsed,
		UsageCount: metadata.UsageCount,
		Version:    metadata.Version,
		Status:     metadata.Status,
	}, nil
}

// ListKeys returns a list of all key IDs
func (km *KeyManager) ListKeys() ([]string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keyIDs := make([]string, 0, len(km.keys))
	for keyID := range km.keys {
		keyIDs = append(keyIDs, keyID)
	}

	return keyIDs, nil
}

// RotateKey rotates a key
func (km *KeyManager) RotateKey(keyID string) (string, error) {
	km.mu.Lock()
	metadata, exists := km.keys[keyID]
	km.mu.Unlock()

	if !exists {
		return "", NewKeyManagementError("key not found", nil)
	}

	// Generate new key
	newKey, err := km.GenerateKey(&KeyGenerationOptions{
		Algorithm: metadata.Algorithm,
	})
	if err != nil {
		return "", NewKeyManagementError("failed to generate new key", err)
	}

	// Mark old key as deprecated
	km.mu.Lock()
	metadata.Status = "deprecated"
	km.mu.Unlock()

	// TODO: Store the actual new key securely
	_ = newKey

	// Return new key ID (this is a placeholder - in real implementation,
	// we'd need to store the key and return its ID)
	return GenerateRandomString(16)
}

// UpdateKeyStatus updates the status of a key
func (km *KeyManager) UpdateKeyStatus(keyID, status string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	metadata, exists := km.keys[keyID]
	if !exists {
		return NewKeyManagementError("key not found", nil)
	}

	validStatuses := []string{"active", "deprecated", "revoked"}
	statusValid := false
	for _, validStatus := range validStatuses {
		if status == validStatus {
			statusValid = true
			break
		}
	}

	if !statusValid {
		return NewValidationError("invalid key status", nil)
	}

	metadata.Status = status
	return nil
}

// GetKeysByAlgorithm returns keys for a specific algorithm
func (km *KeyManager) GetKeysByAlgorithm(algorithm string) ([]string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var keyIDs []string
	for keyID, metadata := range km.keys {
		if metadata.Algorithm == algorithm {
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// GetActiveKeys returns all active keys
func (km *KeyManager) GetActiveKeys() ([]string, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	var keyIDs []string
	for keyID, metadata := range km.keys {
		if metadata.Status == "active" {
			keyIDs = append(keyIDs, keyID)
		}
	}

	return keyIDs, nil
}

// CleanupExpiredKeys removes keys that are past their retention period
func (km *KeyManager) CleanupExpiredKeys() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	cutoff := TimeNow().AddDate(0, 0, -30) // 30 days ago

	for keyID, metadata := range km.keys {
		if metadata.Status == "deprecated" && metadata.CreatedAt.Before(cutoff) {
			delete(km.keys, keyID)
		}
	}

	return nil
}

// HealthCheck performs a health check on the key manager
func (km *KeyManager) HealthCheck() error {
	km.mu.RLock()
	defer km.mu.RUnlock()

	// Basic health check - ensure we can access the keys map
	if km.keys == nil {
		return NewKeyManagementError("keys map not initialized", nil)
	}

	return nil
}

// GetStats returns key manager statistics
func (km *KeyManager) GetStats() (map[string]interface{}, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	stats := map[string]interface{}{
		"total_keys":      len(km.keys),
		"active_keys":     0,
		"deprecated_keys": 0,
		"revoked_keys":    0,
	}

	for _, metadata := range km.keys {
		switch metadata.Status {
		case "active":
			stats["active_keys"] = stats["active_keys"].(int) + 1
		case "deprecated":
			stats["deprecated_keys"] = stats["deprecated_keys"].(int) + 1
		case "revoked":
			stats["revoked_keys"] = stats["revoked_keys"].(int) + 1
		}
	}

	return stats, nil
}
