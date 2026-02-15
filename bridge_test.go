package pact

import (
	"testing"
	"time"
)

func TestStaticCapabilityMapper(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{
		"api:read":         {"read"},
		"api:write":        {"read", "write"},
		"deploy:create":    {"deploy"},
		"github:pr:create": {"repo:write"},
		"github:*":         {"repo:read"},
	})

	tests := []struct {
		capability string
		want       []string
	}{
		{"api:read", []string{"read"}},
		{"api:write", []string{"read", "write"}},
		{"deploy:create", []string{"deploy"}},
		{"github:pr:create", []string{"repo:write"}},
		{"unknown:action", nil},
	}

	for _, tt := range tests {
		t.Run(tt.capability, func(t *testing.T) {
			got := mapper.Map(tt.capability)
			if tt.want == nil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			for i, scope := range got {
				if scope != tt.want[i] {
					t.Fatalf("scope %d: expected %q, got %q", i, tt.want[i], scope)
				}
			}
		})
	}
}

func TestMapAllCapabilities(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{
		"api:read":  {"read"},
		"api:write": {"read", "write"},
	})

	result := &VerificationResult{
		Valid:        true,
		Capabilities: []string{"api:read", "api:write"},
	}

	scopes := MapAllCapabilities(result, mapper)

	// Should deduplicate "read" (appears in both mappings)
	expected := map[string]bool{"read": true, "write": true}
	if len(scopes) != len(expected) {
		t.Fatalf("expected %d scopes, got %d: %v", len(expected), len(scopes), scopes)
	}
	for _, scope := range scopes {
		if !expected[scope] {
			t.Fatalf("unexpected scope %q", scope)
		}
	}
}

func TestScopedTokenBridge(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{
		"api:read": {"read"},
	})

	bridge := NewScopedTokenBridge(
		mapper,
		15*time.Minute,
		func(scopes []string, agentID string) (string, error) {
			return "test-token-" + agentID[:10], nil
		},
	)

	result := &VerificationResult{
		Valid:         true,
		AgentID:       "sha256:abcdef1234567890",
		RootAuthority: "sha256:root123456",
		Capabilities:  []string{"api:read"},
		ExpiresAt:     time.Now().Add(1 * time.Hour),
	}

	cred, err := bridge.Exchange(result)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	if cred.Type != "bearer" {
		t.Fatalf("expected bearer type, got %s", cred.Type)
	}
	if cred.Token != "test-token-sha256:abc" {
		t.Fatalf("unexpected token: %s", cred.Token)
	}
	if len(cred.Scopes) != 1 || cred.Scopes[0] != "read" {
		t.Fatalf("expected [read] scopes, got %v", cred.Scopes)
	}
	if cred.Metadata["agent_id"] != result.AgentID {
		t.Fatalf("agent_id metadata mismatch")
	}
}

func TestScopedTokenBridgeRejectsInvalid(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{})
	bridge := NewScopedTokenBridge(mapper, 15*time.Minute, nil)

	result := &VerificationResult{Valid: false, Error: "bad chain"}
	_, err := bridge.Exchange(result)
	if err == nil {
		t.Fatal("should reject invalid result")
	}
}

func TestScopedTokenBridgeRespectsChainExpiry(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{
		"api:read": {"read"},
	})

	// Chain expires in 2 minutes, but bridge TTL is 15 minutes
	// Bridged credential should expire in 2 minutes
	chainExpiry := time.Now().Add(2 * time.Minute)

	bridge := NewScopedTokenBridge(
		mapper,
		15*time.Minute,
		func(scopes []string, agentID string) (string, error) {
			return "tok", nil
		},
	)

	result := &VerificationResult{
		Valid:        true,
		AgentID:      "sha256:test",
		Capabilities: []string{"api:read"},
		ExpiresAt:    chainExpiry,
	}

	cred, err := bridge.Exchange(result)
	if err != nil {
		t.Fatalf("exchange failed: %v", err)
	}

	// Credential should expire near chain expiry, not bridge TTL
	if cred.ExpiresAt.After(chainExpiry.Add(time.Second)) {
		t.Fatalf("credential should not outlive chain: cred=%v, chain=%v",
			cred.ExpiresAt, chainExpiry)
	}
}

func TestCapabilityMapperSupported(t *testing.T) {
	mapper := NewStaticCapabilityMapper(map[string][]string{
		"api:read": {"read"},
	})

	if !mapper.Supported("api:read") {
		t.Fatal("api:read should be supported")
	}
	if mapper.Supported("unknown:thing") {
		t.Fatal("unknown:thing should not be supported")
	}
}
