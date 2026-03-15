package fortress

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// StorageBackend manages data storage
type StorageBackend struct {
	config  *Config
	storage map[string]*StorageEntry
	mu      sync.RWMutex
}

// StorageEntry represents a stored data entry
type StorageEntry struct {
	Value     []byte    `json:"value"`
	Timestamp time.Time `json:"timestamp"`
	TTL       *int64    `json:"ttl,omitempty"`
}

// NewStorageBackend creates a new storage backend
func NewStorageBackend(config *Config) *StorageBackend {
	return &StorageBackend{
		config:  config,
		storage: make(map[string]*StorageEntry),
	}
}

// Store stores data with optional TTL
func (s *StorageBackend) Store(key string, data []byte, options *StorageOptions) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := &StorageEntry{
		Value:     data,
		Timestamp: time.Now(),
	}

	if options != nil && options.TTLSeconds > 0 {
		ttl := time.Now().Add(time.Duration(options.TTLSeconds) * time.Second).Unix()
		entry.TTL = &ttl
	}

	s.storage[key] = entry
	return nil
}

// Retrieve retrieves data by key
func (s *StorageBackend) Retrieve(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.storage[key]
	if !exists {
		return nil, nil
	}

	// Check TTL
	if entry.TTL != nil && time.Now().Unix() > *entry.TTL {
		delete(s.storage, key)
		return nil, nil
	}

	return entry.Value, nil
}

// Delete deletes data by key
func (s *StorageBackend) Delete(key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, exists := s.storage[key]
	if exists {
		delete(s.storage, key)
		return true, nil
	}
	return false, nil
}

// Exists checks if a key exists
func (s *StorageBackend) Exists(key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entry, exists := s.storage[key]
	if !exists {
		return false, nil
	}

	// Check TTL
	if entry.TTL != nil && time.Now().Unix() > *entry.TTL {
		delete(s.storage, key)
		return false, nil
	}

	return true, nil
}

// ListKeys returns all keys with optional filtering
func (s *StorageBackend) ListKeys(options *QueryOptions) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var keys []string
	now := time.Now().Unix()

	for key, entry := range s.storage {
		// Filter expired keys
		if entry.TTL != nil && now > *entry.TTL {
			continue
		}

		// Apply filters
		if options != nil && options.Filter != nil {
			if !s.applyFilters(key, entry, options.Filter) {
				continue
			}
		}

		keys = append(keys, key)
	}

	// Apply sorting
	if options != nil && options.SortBy != "" {
		s.applySorting(keys, options.SortBy, options.SortOrder)
	}

	// Apply pagination
	if options != nil && options.Offset > 0 {
		if options.Offset >= len(keys) {
			return []string{}, nil
		}
		keys = keys[options.Offset:]
	}

	if options != nil && options.Limit > 0 && options.Limit < len(keys) {
		keys = keys[:options.Limit]
	}

	return keys, nil
}

// Clear clears all data
func (s *StorageBackend) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.storage = make(map[string]*StorageEntry)
	return nil
}

// GetStats returns storage statistics
func (s *StorageBackend) GetStats() (*StorageStats, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stats := &StorageStats{
		TotalKeys: len(s.storage),
		TotalSize: 0,
		Backend:   s.config.Storage.Backend,
	}

	for _, entry := range s.storage {
		stats.TotalSize += int64(len(entry.Value))
	}

	return stats, nil
}

// applyFilters applies filters to a key-value pair
func (s *StorageBackend) applyFilters(key string, entry *StorageEntry, filters map[string]interface{}) bool {
	for filterKey, filterValue := range filters {
		switch filterKey {
		case "key_prefix":
			if prefix, ok := filterValue.(string); ok {
				if !strings.HasPrefix(key, prefix) {
					return false
				}
			} else {
				return false
			}
		case "key_contains":
			if contains, ok := filterValue.(string); ok {
				if !strings.Contains(key, contains) {
					return false
				}
			} else {
				return false
			}
		case "created_after":
			if timestamp, ok := filterValue.(float64); ok {
				if entry.Timestamp.Unix() < int64(timestamp) {
					return false
				}
			} else {
				return false
			}
		case "created_before":
			if timestamp, ok := filterValue.(float64); ok {
				if entry.Timestamp.Unix() > int64(timestamp) {
					return false
				}
			} else {
				return false
			}
		case "has_ttl":
			if hasTTL, ok := filterValue.(bool); ok {
				if hasTTL && entry.TTL == nil {
					return false
				}
				if !hasTTL && entry.TTL != nil {
					return false
				}
			} else {
				return false
			}
		case "size_min":
			if minSize, ok := filterValue.(float64); ok {
				if int64(len(entry.Value)) < int64(minSize) {
					return false
				}
			} else {
				return false
			}
		case "size_max":
			if maxSize, ok := filterValue.(float64); ok {
				if int64(len(entry.Value)) > int64(maxSize) {
					return false
				}
			} else {
				return false
			}
		default:
			// Unknown filter, skip
		}
	}
	return true
}

// applySorting applies sorting to the keys list
func (s *StorageBackend) applySorting(keys []string, sortBy, sortOrder string) {
	// Default sort order is ascending
	ascending := sortOrder != "desc"

	switch sortBy {
	case "key":
		sort.Slice(keys, func(i, j int) bool {
			if ascending {
				return keys[i] < keys[j]
			}
			return keys[i] > keys[j]
		})
	case "timestamp":
		sort.Slice(keys, func(i, j int) bool {
			entryI := s.storage[keys[i]]
			entryJ := s.storage[keys[j]]
			if ascending {
				return entryI.Timestamp.Before(entryJ.Timestamp)
			}
			return entryI.Timestamp.After(entryJ.Timestamp)
		})
	case "size":
		sort.Slice(keys, func(i, j int) bool {
			sizeI := len(s.storage[keys[i]].Value)
			sizeJ := len(s.storage[keys[j]].Value)
			if ascending {
				return sizeI < sizeJ
			}
			return sizeI > sizeJ
		})
	default:
		// Default to key sorting
		sort.Slice(keys, func(i, j int) bool {
			if ascending {
				return keys[i] < keys[j]
			}
			return keys[i] > keys[j]
		})
	}
}

// HealthCheck performs a health check
func (s *StorageBackend) HealthCheck() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Test basic operations
	testKey := "__health_check__"
	testData := []byte("test")

	err := s.Store(testKey, testData, nil)
	if err != nil {
		return NewStorageError("health check store failed", err)
	}

	retrieved, err := s.Retrieve(testKey)
	if err != nil {
		return NewStorageError("health check retrieve failed", err)
	}

	if string(retrieved) != "test" {
		return NewStorageError("health check data mismatch", nil)
	}

	s.Delete(testKey)
	return nil
}

// Close closes the storage backend
func (s *StorageBackend) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.storage = make(map[string]*StorageEntry)
	return nil
}

// CleanupExpired removes expired entries
func (s *StorageBackend) CleanupExpired() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().Unix()
	for key, entry := range s.storage {
		if entry.TTL != nil && now > *entry.TTL {
			delete(s.storage, key)
		}
	}

	return nil
}

// StorageStats represents storage statistics
type StorageStats struct {
	TotalKeys int    `json:"total_keys"`
	TotalSize int64  `json:"total_size"`
	Backend   string `json:"backend"`
}
