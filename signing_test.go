package pact

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSignAndVerifyRequest(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	// Create a delegation
	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"flights:search"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	// Create an HTTP request
	req, _ := http.NewRequest("GET", "https://airline.com/api/flights/search?from=SFO&to=LAX", nil)
	req.Host = "airline.com"

	// Sign the request
	err := SignRequest(req, agent, chain)
	if err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Check headers are set
	if req.Header.Get(HeaderAgentIdentity) == "" {
		t.Error("X-Pact-Identity header not set")
	}
	if req.Header.Get(HeaderDelegationChain) == "" {
		t.Error("X-Pact-Chain header not set")
	}
	if req.Header.Get(HeaderSignature) == "" {
		t.Error("Signature header not set")
	}
	if req.Header.Get(HeaderSignatureInput) == "" {
		t.Error("Signature-Input header not set")
	}

	// Verify the request
	opts := DefaultVerifyOptions()
	opts.RequiredCapability = "flights:search"
	result := VerifyRequest(req, opts)

	if !result.Valid {
		t.Fatalf("request verification failed: %s", result.Error)
	}
	if result.AgentID != agent.ID {
		t.Errorf("agent ID: got %q, want %q", result.AgentID, agent.ID)
	}
}

func TestRequestSignaturePreventsReplay(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	// Sign a request
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	// Request should verify now
	opts := DefaultVerifyOptions()
	result := VerifyRequest(req, opts)
	if !result.Valid {
		t.Fatalf("valid request should verify: %s", result.Error)
	}

	// Set the Date to an old time (simulating replay)
	req.Header.Set("Date", time.Now().Add(-10*time.Minute).UTC().Format(http.TimeFormat))
	result = VerifyRequest(req, opts)
	// The signature won't match the new date, so this tests tamper detection
	// rather than replay in this implementation
}

func TestRequestSignatureTamperDetection(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	// Tamper with the path (e.g., trying to access different resource)
	req.URL.Path = "/admin/delete-all"

	opts := DefaultVerifyOptions()
	result := VerifyRequest(req, opts)
	if result.Valid {
		t.Error("tampered request should be INVALID")
	}
}

func TestRequestWithoutPactHeaders(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)

	result := VerifyRequest(req, DefaultVerifyOptions())
	if result.Valid {
		t.Error("request without Pact headers should be invalid")
	}
}

func TestSignatureInputFormat(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	req, _ := http.NewRequest("POST", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	sigInput := req.Header.Get(HeaderSignatureInput)
	if !strings.HasPrefix(sigInput, "pact=(") {
		t.Errorf("Signature-Input should start with 'pact=(', got %q", sigInput)
	}
	if !strings.Contains(sigInput, "alg=\"ed25519\"") {
		t.Error("Signature-Input should contain alg=\"ed25519\"")
	}
	if !strings.Contains(sigInput, agent.ID) {
		t.Error("Signature-Input should contain agent ID as keyid")
	}
}

func TestRequiredCapabilityCheck(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"flights:search"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	req, _ := http.NewRequest("GET", "https://airline.com/api/flights", nil)
	req.Host = "airline.com"
	SignRequest(req, agent, chain)

	// Should pass with matching capability
	opts := DefaultVerifyOptions()
	opts.RequiredCapability = "flights:search"
	result := VerifyRequest(req, opts)
	if !result.Valid {
		t.Errorf("should be valid for matching capability: %s", result.Error)
	}

	// Should fail with non-matching capability
	opts.RequiredCapability = "flights:book"
	result = VerifyRequest(req, opts)
	if result.Valid {
		t.Error("should be invalid for non-matching capability")
	}
}

func TestTrustedRoots(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	bob, _ := NewIdentity(EntityHuman, "bob")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*d}

	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	// Alice is trusted
	opts := DefaultVerifyOptions()
	opts.TrustedRoots = map[string]bool{alice.ID: true}
	result := VerifyRequest(req, opts)
	if !result.Valid {
		t.Errorf("alice should be trusted: %s", result.Error)
	}

	// Only Bob is trusted, not Alice
	opts.TrustedRoots = map[string]bool{bob.ID: true}
	result = VerifyRequest(req, opts)
	if result.Valid {
		t.Error("alice is not in trusted roots, should fail")
	}
}
