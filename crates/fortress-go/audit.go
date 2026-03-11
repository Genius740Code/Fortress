package fortress

import (
	"encoding/json"
	"sync"
	"time"
)

// AuditLogger manages audit logging
type AuditLogger struct {
	config  *Config
	entries []*AuditEntry
	mu      sync.RWMutex
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config *Config) *AuditLogger {
	return &AuditLogger{
		config:  config,
		entries: make([]*AuditEntry, 0),
	}
}

// Log logs an audit entry
func (a *AuditLogger) Log(entry *AuditEntry) error {
	if !a.config.Audit.Enabled {
		return nil
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Generate ID if not provided
	if entry.ID == "" {
		id, err := GenerateRandomString(16)
		if err != nil {
			return err
		}
		entry.ID = id
	}

	// Set timestamp if not provided
	if entry.Timestamp.IsZero() {
		entry.Timestamp = time.Now()
	}

	a.entries = append(a.entries, entry)

	// Batch flush if needed
	if len(a.entries) >= a.config.Audit.BatchSize {
		return a.Flush()
	}

	return nil
}

// LogSuccess logs a successful operation
func (a *AuditLogger) LogSuccess(tenantID, userID, action string, resource *Resource, metadata map[string]interface{}) error {
	return a.Log(&AuditEntry{
		TenantID: tenantID,
		UserID:   userID,
		Action:   action,
		Resource: *resource,
		Result:   "success",
		Metadata: metadata,
	})
}

// LogFailure logs a failed operation
func (a *AuditLogger) LogFailure(tenantID, userID, action string, resource *Resource, errorMsg string, metadata map[string]interface{}) error {
	return a.Log(&AuditEntry{
		TenantID: tenantID,
		UserID:   userID,
		Action:   action,
		Resource: *resource,
		Result:   "failure",
		Error:    errorMsg,
		Metadata: metadata,
	})
}

// Query queries audit entries with optional filters
func (a *AuditLogger) Query(options *AuditQueryOptions) ([]*AuditEntry, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	entries := make([]*AuditEntry, len(a.entries))
	copy(entries, a.entries)

	// Filter by tenant
	if options != nil && options.TenantID != "" {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.TenantID == options.TenantID {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Filter by user
	if options != nil && options.UserID != "" {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.UserID == options.UserID {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Filter by action
	if options != nil && options.Action != "" {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.Action == options.Action {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Filter by resource type
	if options != nil && options.ResourceType != "" {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.Resource.Type == options.ResourceType {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Filter by result
	if options != nil && options.Result != "" {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.Result == options.Result {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Filter by date range
	if options != nil && options.StartDate != nil {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.Timestamp.After(*options.StartDate) || entry.Timestamp.Equal(*options.StartDate) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	if options != nil && options.EndDate != nil {
		var filtered []*AuditEntry
		for _, entry := range entries {
			if entry.Timestamp.Before(*options.EndDate) || entry.Timestamp.Equal(*options.EndDate) {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Sort by timestamp (newest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].Timestamp.Before(entries[j].Timestamp) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Apply pagination
	if options != nil && options.Offset > 0 {
		if options.Offset >= len(entries) {
			return []*AuditEntry{}, nil
		}
		entries = entries[options.Offset:]
	}

	if options != nil && options.Limit > 0 && options.Limit < len(entries) {
		entries = entries[:options.Limit]
	}

	return entries, nil
}

// GetStats returns audit statistics
func (a *AuditLogger) GetStats(options *AuditStatsOptions) (*AuditStats, error) {
	entries, err := a.Query(&AuditQueryOptions{
		TenantID: options.TenantID,
		UserID:   options.UserID,
		Action:   options.Action,
	})
	if err != nil {
		return nil, NewAuditError("failed to query entries for stats", err)
	}

	stats := &AuditStats{
		TotalEntries:         len(entries),
		SuccessfulOperations: 0,
		FailedOperations:     0,
		UniqueUsers:          0,
		UniqueResources:      0,
		UniqueActions:        make(map[string]bool),
		Actions:              make(map[string]int),
		HourlyStats:          make([]int, 24),
	}

	// Track unique users and resources
	uniqueUsers := make(map[string]bool)
	uniqueResources := make(map[string]bool)

	if len(entries) > 0 {
		stats.TimeRange.Start = entries[len(entries)-1].Timestamp
		stats.TimeRange.End = entries[0].Timestamp
	}

	for _, entry := range entries {
		if entry.Result == "success" {
			stats.SuccessfulOperations++
		} else {
			stats.FailedOperations++
		}

		if entry.UserID != "" {
			if !uniqueUsers[entry.UserID] {
				uniqueUsers[entry.UserID] = true
				stats.UniqueUsers++
			}
		}

		if entry.Resource.ID != "" {
			if !uniqueResources[entry.Resource.ID] {
				uniqueResources[entry.Resource.ID] = true
				stats.UniqueResources++
			}
		}

		stats.UniqueActions[entry.Action] = true
		stats.Actions[entry.Action]++
	}

	return stats, nil
}

// Flush flushes audit entries to storage
func (a *AuditLogger) Flush() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.entries) == 0 {
		return nil
	}

	// TODO: Implement actual storage flush
	// For now, just clear the entries
	a.entries = make([]*AuditEntry, 0)
	return nil
}

// Cleanup removes old audit entries based on retention policy
func (a *AuditLogger) Cleanup() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	retentionDays := a.config.Audit.RetentionDays
	if retentionDays <= 0 {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	var remaining []*AuditEntry

	for _, entry := range a.entries {
		if entry.Timestamp.After(cutoff) {
			remaining = append(remaining, entry)
		}
	}

	a.entries = remaining
	return nil
}

// GetEntryCount returns the number of entries
func (a *AuditLogger) GetEntryCount() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries)
}

// Clear clears all audit entries
func (a *AuditLogger) Clear() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = make([]*AuditEntry, 0)
	return nil
}

// ExportToJSON exports audit entries to JSON
func (a *AuditLogger) ExportToJSON() ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return json.MarshalIndent(a.entries, "", "  ")
}

// ImportFromJSON imports audit entries from JSON
func (a *AuditLogger) ImportFromJSON(data []byte) error {
	var entries []*AuditEntry
	err := json.Unmarshal(data, &entries)
	if err != nil {
		return NewAuditError("failed to import from JSON", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	a.entries = append(a.entries, entries...)
	return nil
}
