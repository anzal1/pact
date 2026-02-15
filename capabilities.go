package pact

import (
	"fmt"
	"strconv"
	"strings"
)

// Capability represents a parsed capability URI.
//
// Format: resource:action,constraint=value,constraint=value
//
// Examples:
//
//	"github:pr:create,repo=myorg/*"
//	"flights:book<500USD"
//	"email:send,to=*@mycompany.com"
//	"github:*"                        (wildcard — all github actions)
//	"*"                               (full access — dangerous, explicit)
type Capability struct {
	// Resource is the hierarchical resource path (e.g., "github:pr" or "flights").
	Resource string `json:"resource"`

	// Action is the specific operation (e.g., "create", "book", "*").
	Action string `json:"action"`

	// Constraints are key=value pairs that further restrict the capability.
	Constraints map[string]string `json:"constraints,omitempty"`

	// Raw is the original capability string.
	Raw string `json:"raw"`
}

// ParseCapability parses a capability URI string into a structured Capability.
//
// Supported formats:
//
//	"resource:action"
//	"resource:action,key=value,key=value"
//	"resource:sub:action,key=value"
//	"resource:*"                         (wildcard action)
//	"*"                                  (full access)
func ParseCapability(raw string) (*Capability, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("pact: empty capability string")
	}

	// Full wildcard
	if raw == "*" {
		return &Capability{
			Resource: "*",
			Action:   "*",
			Raw:      raw,
		}, nil
	}

	// Split off constraints (everything after the first comma that follows the resource:action)
	var resourceAction string
	var constraintStr string

	// Find the first comma — constraints start there
	commaIdx := strings.Index(raw, ",")
	if commaIdx >= 0 {
		resourceAction = raw[:commaIdx]
		constraintStr = raw[commaIdx+1:]
	} else {
		// Check for < constraint (e.g., "flights:book<500USD")
		ltIdx := strings.Index(raw, "<")
		if ltIdx >= 0 {
			resourceAction = raw[:ltIdx]
			constraintStr = "max=" + raw[ltIdx+1:]
		} else {
			resourceAction = raw
		}
	}

	// Parse resource:action (may have multiple colon-separated segments)
	parts := strings.Split(resourceAction, ":")
	if len(parts) < 1 {
		return nil, fmt.Errorf("pact: invalid capability format: %q", raw)
	}

	var resource, action string
	if len(parts) == 1 {
		// Just a resource with implied wildcard action
		resource = parts[0]
		action = "*"
	} else {
		// Last part is the action, everything before is the resource path
		action = parts[len(parts)-1]
		resource = strings.Join(parts[:len(parts)-1], ":")
	}

	if resource == "" {
		return nil, fmt.Errorf("pact: empty resource in capability: %q", raw)
	}

	// Parse constraints
	constraints := make(map[string]string)
	if constraintStr != "" {
		for _, c := range strings.Split(constraintStr, ",") {
			c = strings.TrimSpace(c)
			if c == "" {
				continue
			}
			eqIdx := strings.Index(c, "=")
			if eqIdx < 0 {
				return nil, fmt.Errorf("pact: invalid constraint (no '='): %q in capability %q", c, raw)
			}
			key := c[:eqIdx]
			value := c[eqIdx+1:]
			if key == "" {
				return nil, fmt.Errorf("pact: empty constraint key in capability %q", raw)
			}
			constraints[key] = value
		}
	}

	return &Capability{
		Resource:    resource,
		Action:      action,
		Constraints: constraints,
		Raw:         raw,
	}, nil
}

// Covers checks whether this capability covers (is a superset of) another.
// A parent capability covers a child if:
//   - The parent resource matches the child resource (including wildcards)
//   - The parent action matches the child action (including wildcards)
//   - All parent constraints are satisfied by the child's constraints
//
// This is the core of narrowing-only delegation: a delegated capability
// must be covered by the delegator's capability.
func (c *Capability) Covers(child *Capability) bool {
	// Full wildcard covers everything
	if c.Resource == "*" && c.Action == "*" {
		return true
	}

	// Check resource match
	if !resourceMatches(c.Resource, child.Resource) {
		return false
	}

	// Check action match
	if c.Action != "*" && c.Action != child.Action {
		return false
	}

	// Check constraints — parent's constraints must be satisfied by child
	for key, parentVal := range c.Constraints {
		childVal, exists := child.Constraints[key]
		if !exists {
			// Child doesn't have this constraint — parent is more restrictive
			// BUT: if parent has a "max" constraint, child must also have one
			return false
		}
		if !constraintSatisfied(key, parentVal, childVal) {
			return false
		}
	}

	return true
}

// resourceMatches checks if a parent resource pattern matches a child resource.
// Supports hierarchical matching: "github" matches "github:pr", "github:issue", etc.
// Supports wildcards: "github:*" matches any github sub-resource.
func resourceMatches(parent, child string) bool {
	if parent == child {
		return true
	}

	// Parent "github" covers "github:pr", "github:issue", etc.
	if strings.HasPrefix(child, parent+":") {
		return true
	}

	// Wildcard in parent resource
	if strings.HasSuffix(parent, ":*") {
		prefix := parent[:len(parent)-2]
		return child == prefix || strings.HasPrefix(child, prefix+":")
	}

	return false
}

// constraintSatisfied checks if a child constraint value satisfies a parent constraint.
// Handles numeric comparisons (for "max" constraints) and pattern matching.
func constraintSatisfied(key, parentVal, childVal string) bool {
	// Numeric max constraint: child's value must be <= parent's value
	if key == "max" {
		parentNum := extractNumber(parentVal)
		childNum := extractNumber(childVal)
		if parentNum >= 0 && childNum >= 0 {
			return childNum <= parentNum
		}
	}

	// Pattern matching for glob-like constraints (e.g., repo=myorg/*)
	if strings.Contains(parentVal, "*") {
		return globMatch(parentVal, childVal)
	}

	// Exact match
	return parentVal == childVal
}

// extractNumber pulls a leading integer from a string like "500USD".
func extractNumber(s string) int64 {
	numStr := ""
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			numStr += string(ch)
		} else {
			break
		}
	}
	if numStr == "" {
		return -1
	}
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return -1
	}
	return n
}

// globMatch does simple glob matching where * matches any substring.
func globMatch(pattern, value string) bool {
	// Simple implementation: split pattern on *, check prefix/suffix
	if pattern == "*" {
		return true
	}

	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		// No wildcard — exact match
		return pattern == value
	}

	// Check prefix
	if parts[0] != "" && !strings.HasPrefix(value, parts[0]) {
		return false
	}

	// Check suffix
	last := parts[len(parts)-1]
	if last != "" && !strings.HasSuffix(value, last) {
		return false
	}

	// Check middle parts appear in order
	remaining := value
	for _, part := range parts {
		if part == "" {
			continue
		}
		idx := strings.Index(remaining, part)
		if idx < 0 {
			return false
		}
		remaining = remaining[idx+len(part):]
	}

	return true
}

// CapabilitySet is an ordered list of capabilities.
// Used in delegation chains to specify what an agent is allowed to do.
type CapabilitySet []Capability

// ParseCapabilitySet parses a list of capability strings.
func ParseCapabilitySet(raw []string) (CapabilitySet, error) {
	caps := make(CapabilitySet, 0, len(raw))
	for _, r := range raw {
		cap, err := ParseCapability(r)
		if err != nil {
			return nil, err
		}
		caps = append(caps, *cap)
	}
	return caps, nil
}

// Covers checks if this capability set covers all capabilities in the child set.
// Every child capability must be covered by at least one parent capability.
func (cs CapabilitySet) Covers(child CapabilitySet) bool {
	for _, childCap := range child {
		covered := false
		for _, parentCap := range cs {
			if parentCap.Covers(&childCap) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// Strings returns the raw string representations of all capabilities.
func (cs CapabilitySet) Strings() []string {
	result := make([]string, len(cs))
	for i, cap := range cs {
		result[i] = cap.Raw
	}
	return result
}
