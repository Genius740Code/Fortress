package fortress

import (
	"fmt"
)

// FortressError represents an error in the Fortress system
type FortressError struct {
	Code        string
	Message     string
	Kind        string
	Source      error
	IsRetryable bool
	IsTemporary bool
}

// Error implements the error interface
func (e *FortressError) Error() string {
	if e.Source != nil {
		return fmt.Sprintf("%s: %s (caused by: %v)", e.Code, e.Message, e.Source)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *FortressError) Unwrap() error {
	return e.Source
}

// NewFortressError creates a new FortressError
func NewFortressError(code, message string, source error) *FortressError {
	return &FortressError{
		Code:        code,
		Message:     message,
		Kind:        determineKind(code),
		Source:      source,
		IsRetryable: isRetryable(code),
		IsTemporary: isTemporary(code),
	}
}

// determineKind determines the error kind from the error code
func determineKind(code string) string {
	switch {
	case len(code) >= 10 && code[:10] == "ENCRYPTION":
		return "Encryption"
	case len(code) >= 3 && code[:3] == "KEY":
		return "KeyManagement"
	case len(code) >= 7 && code[:7] == "STORAGE":
		return "Storage"
	case len(code) >= 6 && code[:6] == "POLICY":
		return "Policy"
	case len(code) >= 5 && code[:5] == "AUDIT":
		return "Audit"
	case len(code) >= 6 && code[:6] == "TENANT":
		return "Tenant"
	case len(code) >= 6 && code[:6] == "CONFIG":
		return "Configuration"
	case len(code) >= 6 && code[:6] == "NETWORK":
		return "Network"
	case len(code) >= 10 && code[:10] == "VALIDATION":
		return "Validation"
	case len(code) >= 10 && code[:10] == "PERMISSION":
		return "Permission"
	case len(code) >= 10 && code[:10] == "RATE_LIMIT":
		return "RateLimit"
	case len(code) >= 6 && code[:6] == "TIMEOUT":
		return "Timeout"
	default:
		return "Unknown"
	}
}

// isRetryable determines if an error is retryable
func isRetryable(code string) bool {
	retryableCodes := []string{
		"STORAGE_ERROR",
		"NETWORK_ERROR",
		"AUDIT_ERROR",
		"RATE_LIMIT_ERROR",
		"TIMEOUT_ERROR",
	}

	for _, retryableCode := range retryableCodes {
		if code == retryableCode {
			return true
		}
	}
	return false
}

// isTemporary determines if an error is temporary
func isTemporary(code string) bool {
	temporaryCodes := []string{
		"NETWORK_ERROR",
		"RATE_LIMIT_ERROR",
		"TIMEOUT_ERROR",
	}

	for _, temporaryCode := range temporaryCodes {
		if code == temporaryCode {
			return true
		}
	}
	return false
}

// Predefined error constructors
func NewEncryptionError(message string, source error) *FortressError {
	return NewFortressError("ENCRYPTION_ERROR", message, source)
}

func NewKeyManagementError(message string, source error) *FortressError {
	return NewFortressError("KEY_MANAGEMENT_ERROR", message, source)
}

func NewStorageError(message string, source error) *FortressError {
	return NewFortressError("STORAGE_ERROR", message, source)
}

func NewPolicyError(message string, source error) *FortressError {
	return NewFortressError("POLICY_ERROR", message, source)
}

func NewAuditError(message string, source error) *FortressError {
	return NewFortressError("AUDIT_ERROR", message, source)
}

func NewTenantError(message string, source error) *FortressError {
	return NewFortressError("TENANT_ERROR", message, source)
}

func NewConfigurationError(message string, source error) *FortressError {
	return NewFortressError("CONFIG_ERROR", message, source)
}

func NewNetworkError(message string, source error) *FortressError {
	return NewFortressError("NETWORK_ERROR", message, source)
}

func NewValidationError(message string, source error) *FortressError {
	return NewFortressError("VALIDATION_ERROR", message, source)
}

func NewPermissionError(message string, source error) *FortressError {
	return NewFortressError("PERMISSION_ERROR", message, source)
}

func NewRateLimitError(message string, source error) *FortressError {
	return NewFortressError("RATE_LIMIT_ERROR", message, source)
}

func NewTimeoutError(message string, source error) *FortressError {
	return NewFortressError("TIMEOUT_ERROR", message, source)
}

func NewInitializationError(message string, source error) *FortressError {
	return NewFortressError("INITIALIZATION_ERROR", message, source)
}

func NewShutdownError(message string, source error) *FortressError {
	return NewFortressError("SHUTDOWN_ERROR", message, source)
}

// Predefined error instances
var (
	ErrNotInitialized = NewInitializationError("Fortress is not initialized", nil)
	ErrKeyNotFound    = NewKeyManagementError("Key not found", nil)
	ErrKeyIDRequired  = NewValidationError("Key ID is required", nil)
	ErrInvalidKey     = NewValidationError("Invalid key", nil)
	ErrTenantNotFound  = NewTenantError("Tenant not found", nil)
	ErrPolicyNotFound  = NewPolicyError("Policy not found", nil)
	ErrAccessDenied    = NewPermissionError("Access denied", nil)
)
