package fortress

import (
	"fmt"
	"sync"
	"time"
)

// PolicyEngine manages access policies
type PolicyEngine struct {
	config  *Config
	policies map[string]*PolicyConfig
	mu      sync.RWMutex
}

// NewPolicyEngine creates a new policy engine
func NewPolicyEngine(config *Config) *PolicyEngine {
	return &PolicyEngine{
		config:  config,
		policies: make(map[string]*PolicyConfig),
	}
}

// AddPolicy adds a policy
func (p *PolicyEngine) AddPolicy(policy *PolicyConfig) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.policies[policy.Name] = policy
}

// RemovePolicy removes a policy
func (p *PolicyEngine) RemovePolicy(name string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, exists := p.policies[name]
	if exists {
		delete(p.policies, name)
		return true
	}
	return false
}

// GetPolicy retrieves a policy by name
func (p *PolicyEngine) GetPolicy(name string) *PolicyConfig {
	p.mu.RLock()
	defer p.mu.RUnlock()

	policy, exists := p.policies[name]
	if !exists {
		return nil
	}
	return policy
}

// ListPolicies returns all policy names
func (p *PolicyEngine) ListPolicies() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var names []string
	for name := range p.policies {
		names = append(names, name)
	}
	return names
}

// EvaluatePermission evaluates if a user has permission for an action on a resource
func (p *PolicyEngine) EvaluatePermission(userID string, resource *Resource, action string, context map[string]interface{}) (bool, error) {
	p.mu.RLock()
	policies := make([]*PolicyConfig, 0, len(p.policies))
	for _, policy := range p.policies {
		policies = append(policies, policy)
	}
	p.mu.RUnlock()

	for _, policy := range policies {
		result, err := p.evaluatePolicy(policy, userID, resource, action, context)
		if err != nil {
			return false, NewPolicyError("policy evaluation failed", err)
		}

		if policy.EvaluationMode == "any" && result {
			return true, nil
		}

		if policy.EvaluationMode == "all" && !result {
			return false, nil
		}
	}

	// Return default action if no policies matched
	return p.config.Policy.DefaultAction == "allow", nil
}

// evaluatePolicy evaluates a single policy
func (p *PolicyEngine) evaluatePolicy(policy *PolicyConfig, userID string, resource *Resource, action string, context map[string]interface{}) (bool, error) {
	// Sort rules by priority (higher priority first)
	sortedRules := make([]*PolicyRule, len(policy.Rules))
	copy(sortedRules, policy.Rules)

	// Simple sort by priority (higher first)
	for i := 0; i < len(sortedRules)-1; i++ {
		for j := i + 1; j < len(sortedRules); j++ {
			if sortedRules[i].Priority < sortedRules[j].Priority {
				sortedRules[i], sortedRules[j] = sortedRules[j], sortedRules[i]
			}
		}
	}

	for _, rule := range sortedRules {
		if !rule.Enabled {
			continue
		}

		matches, err := p.evaluateRule(rule, userID, resource, action, context)
		if err != nil {
			return false, err
		}

		if matches {
			return rule.Action == "allow", nil
		}
	}

	return policy.DefaultAction == "allow", nil
}

// evaluateRule evaluates a single rule
func (p *PolicyEngine) evaluateRule(rule *PolicyRule, userID string, resource *Resource, action string, context map[string]interface{}) (bool, error) {
	// Check if action matches
	permissionMatches := false
	for _, permission := range rule.Permissions {
		if permission.Resource.Type == resource.Type && 
		   (permission.Resource.ID == "" || permission.Resource.ID == resource.ID) {
			for _, allowedAction := range permission.Actions {
				if allowedAction == action {
					permissionMatches = true
					break
				}
			}
		}
	}

	if !permissionMatches {
		return false, nil
	}

	// Evaluate conditions
	for _, condition := range rule.Conditions {
		matches, err := p.evaluateCondition(condition, userID, resource, action, context)
		if err != nil {
			return false, err
		}

		if !matches {
			return false, nil
		}
	}

	return true, nil
}

// evaluateCondition evaluates a single condition
func (p *PolicyEngine) evaluateCondition(condition Condition, userID string, resource *Resource, action string, context map[string]interface{}) (bool, error) {
	fieldValue := p.getFieldValue(condition.Field, userID, resource, action, context)

	switch condition.Operator {
	case "eq":
		return p.compareValues(fieldValue, condition.Value, "==")
	case "ne":
		return !p.compareValues(fieldValue, condition.Value, "==")
	case "gt":
		return p.compareValues(fieldValue, condition.Value, ">")
	case "gte":
		return p.compareValues(fieldValue, condition.Value, ">=")
	case "lt":
		return p.compareValues(fieldValue, condition.Value, "<")
	case "lte":
		return p.compareValues(fieldValue, condition.Value, "<=")
	case "in":
		return p.valueInArray(fieldValue, condition.Value)
	case "contains":
		return p.stringContains(fieldValue, condition.Value)
	default:
		return false, NewPolicyError(fmt.Sprintf("unknown operator: %s", condition.Operator), nil)
	}
}

// getFieldValue gets the value of a field for evaluation
func (p *PolicyEngine) getFieldValue(field string, userID string, resource *Resource, action string, context map[string]interface{}) interface{} {
	switch field {
	case "user.id":
		return userID
	case "resource.type":
		return resource.Type
	case "resource.id":
		return resource.ID
	case "action":
		return action
	default:
		// Try to get from context
		if context != nil {
			if value, exists := context[field]; exists {
				return value
			}
		}
		return nil
	}
}

// compareValues compares two values based on an operator
func (p *PolicyEngine) compareValues(fieldValue, conditionValue interface{}, operator string) bool {
	switch operator {
	case "==":
		return fieldValue == conditionValue
	case ">":
		return p.compareNumeric(fieldValue, conditionValue, func(a, b float64) bool { return a > b })
	case ">=":
		return p.compareNumeric(fieldValue, conditionValue, func(a, b float64) bool { return a >= b })
	case "<":
		return p.compareNumeric(fieldValue, conditionValue, func(a, b float64) bool { return a < b })
	case "<=":
		return p.compareNumeric(fieldValue, conditionValue, func(a, b float64) bool { return a <= b })
	default:
		return false
	}
}

// compareNumeric compares two numeric values
func (p *PolicyEngine) compareNumeric(a, b interface{}, compareFunc func(float64, float64) bool) bool {
	aFloat, aOk := p.toFloat64(a)
	bFloat, bOk := p.toFloat64(b)

	if !aOk || !bOk {
		return false
	}

	return compareFunc(aFloat, bFloat)
}

// toFloat64 converts a value to float64
func (p *PolicyEngine) toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case float32:
		return float64(v), true
	case float64:
		return v, true
	default:
		return 0, false
	}
}

// valueInArray checks if a value exists in an array
func (p *PolicyEngine) valueInArray(value, array interface{}) bool {
	arr, ok := array.([]interface{})
	if !ok {
		return false
	}

	for _, item := range arr {
		if p.compareValues(value, item, "==") {
			return true
		}
	}
	return false
}

// stringContains checks if a string contains another string
func (p *PolicyEngine) stringContains(value, substr interface{}) bool {
	valueStr, ok := value.(string)
	substrStr, ok := substr.(string)

	if !ok || !ok {
		return false
	}

	for i := 0; i <= len(valueStr)-len(substrStr); i++ {
		if valueStr[i:i+len(substrStr)] == substrStr {
			return true
		}
	}
	return false
}

// CreatePermission creates a new permission
func (p *PolicyEngine) CreatePermission(resource *Resource, actions []string) *Permission {
	return &Permission{
		ID:       GenerateRandomString(8),
		Resource: *resource,
		Actions:  actions,
	}
}

// CreateRule creates a new policy rule
func (p *PolicyEngine) CreateRule(name string, conditions []Condition, action string, priority int) *PolicyRule {
	return &PolicyRule{
		ID:         GenerateRandomString(8),
		Name:       name,
		Conditions: conditions,
		Action:     action,
		Priority:   priority,
		Enabled:    true,
	}
}
