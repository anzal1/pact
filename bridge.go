package pact

import (
	"fmt"
	"time"
)

// CredentialBridge converts a verified Pact delegation chain into credentials
// that existing systems understand. This is the adoption bridge — providers
// don't need to change their backend, they just need a bridge at the edge.
//
// Implementations might produce:
//   - Short-lived OAuth2 access tokens (most common)
//   - API keys scoped to the verified capabilities
//   - JWTs with Pact claims embedded
//   - Session cookies for web-based providers
type CredentialBridge interface {
	// Exchange takes a verified Pact result and produces a credential
	// the downstream system understands.
	Exchange(result *VerificationResult) (*BridgedCredential, error)
}

// BridgedCredential is the output of a credential bridge.
type BridgedCredential struct {
	// Type is the credential type (e.g., "bearer", "api-key", "jwt").
	Type string `json:"type"`

	// Token is the credential value.
	Token string `json:"token"`

	// ExpiresAt is when the bridged credential expires.
	// Should be <= the delegation chain's expiry (whichever is sooner).
	ExpiresAt time.Time `json:"expires_at"`

	// Scopes are the provider-native scopes derived from Pact capabilities.
	Scopes []string `json:"scopes,omitempty"`

	// Metadata carries additional provider-specific information.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// CapabilityMapper translates Pact capability URIs into provider-native scopes.
// This solves the disconnect between Pact's capability system and provider APIs.
//
// Example: a GitHub mapper might translate:
//
//	"github:pr:create,repo=myorg/*" → "repo:write"
//	"github:issue:read"             → "repo:read"
//
// Each provider implements their own mapper.
type CapabilityMapper interface {
	// Map translates a Pact capability URI into provider-native scopes.
	// Returns empty slice if the capability has no provider mapping.
	Map(capability string) []string

	// Supported returns true if this mapper can handle the given capability's resource.
	Supported(capability string) bool
}

// StaticCapabilityMapper is a simple map-based capability mapper.
// Good for providers with a fixed set of capability-to-scope mappings.
//
// Usage:
//
//	mapper := pact.NewStaticCapabilityMapper(map[string][]string{
//	    "api:read":         {"read"},
//	    "api:write":        {"read", "write"},
//	    "deploy:create":    {"deploy"},
//	    "github:pr:create": {"repo:write"},
//	})
type StaticCapabilityMapper struct {
	mappings map[string][]string
}

// NewStaticCapabilityMapper creates a capability mapper from a static mapping table.
func NewStaticCapabilityMapper(mappings map[string][]string) *StaticCapabilityMapper {
	return &StaticCapabilityMapper{mappings: mappings}
}

// Map translates a Pact capability to provider scopes.
func (m *StaticCapabilityMapper) Map(capability string) []string {
	cap, err := ParseCapability(capability)
	if err != nil {
		return nil
	}

	// Try exact match first
	if scopes, ok := m.mappings[capability]; ok {
		return scopes
	}

	// Try resource:action without constraints
	key := cap.Resource + ":" + cap.Action
	if scopes, ok := m.mappings[key]; ok {
		return scopes
	}

	// Try resource:* (wildcard action)
	key = cap.Resource + ":*"
	if scopes, ok := m.mappings[key]; ok {
		return scopes
	}

	return nil
}

// Supported checks if this mapper handles the capability's resource.
func (m *StaticCapabilityMapper) Supported(capability string) bool {
	return len(m.Map(capability)) > 0
}

// MapAllCapabilities translates all capabilities in a verification result
// to provider-native scopes using the given mapper. Deduplicates.
func MapAllCapabilities(result *VerificationResult, mapper CapabilityMapper) []string {
	seen := make(map[string]bool)
	var scopes []string

	for _, cap := range result.Capabilities {
		for _, scope := range mapper.Map(cap) {
			if !seen[scope] {
				seen[scope] = true
				scopes = append(scopes, scope)
			}
		}
	}

	return scopes
}

// ScopedTokenBridge is a simple credential bridge that produces short-lived
// tokens with mapped scopes. Providers supply a token generator function.
//
// Usage:
//
//	bridge := pact.NewScopedTokenBridge(
//	    mapper,
//	    15*time.Minute,
//	    func(scopes []string, agentID string) (string, error) {
//	        // Generate a short-lived token in your auth system
//	        return myAuthSystem.CreateToken(scopes, agentID)
//	    },
//	)
type ScopedTokenBridge struct {
	mapper    CapabilityMapper
	tokenTTL  time.Duration
	generator func(scopes []string, agentID string) (string, error)
}

// NewScopedTokenBridge creates a credential bridge that maps Pact capabilities
// to provider scopes and generates a token.
func NewScopedTokenBridge(
	mapper CapabilityMapper,
	tokenTTL time.Duration,
	generator func(scopes []string, agentID string) (string, error),
) *ScopedTokenBridge {
	return &ScopedTokenBridge{
		mapper:    mapper,
		tokenTTL:  tokenTTL,
		generator: generator,
	}
}

// Exchange converts a Pact verification result into a bridged credential.
func (b *ScopedTokenBridge) Exchange(result *VerificationResult) (*BridgedCredential, error) {
	if !result.Valid {
		return nil, fmt.Errorf("pact: cannot bridge invalid verification result")
	}

	scopes := MapAllCapabilities(result, b.mapper)
	if len(scopes) == 0 {
		return nil, fmt.Errorf("pact: no provider scopes mapped from capabilities %v", result.Capabilities)
	}

	// Token TTL is the minimum of bridge TTL and chain expiry
	expiresAt := time.Now().UTC().Add(b.tokenTTL)
	if !result.ExpiresAt.IsZero() && result.ExpiresAt.Before(expiresAt) {
		expiresAt = result.ExpiresAt
	}

	token, err := b.generator(scopes, result.AgentID)
	if err != nil {
		return nil, fmt.Errorf("pact: token generation failed: %w", err)
	}

	return &BridgedCredential{
		Type:      "bearer",
		Token:     token,
		ExpiresAt: expiresAt,
		Scopes:    scopes,
		Metadata: map[string]string{
			"agent_id":       result.AgentID,
			"root_authority": result.RootAuthority,
		},
	}, nil
}
