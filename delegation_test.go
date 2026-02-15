package pact

import (
	"testing"
	"time"
)

func TestNewDelegation(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "my-agent")

	d, err := NewDelegation(DelegationRequest{
		From:          alice,
		To:            agent,
		Capabilities:  []string{"github:pr:create,repo=myorg/*"},
		TTL:           1 * time.Hour,
		MaxChainDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewDelegation failed: %v", err)
	}

	if d.Type != "delegation" {
		t.Errorf("type: got %q, want 'delegation'", d.Type)
	}
	if d.Version != "1.0" {
		t.Errorf("version: got %q, want '1.0'", d.Version)
	}
	if d.From.ID != alice.ID {
		t.Errorf("from ID: got %q, want %q", d.From.ID, alice.ID)
	}
	if d.To.ID != agent.ID {
		t.Errorf("to ID: got %q, want %q", d.To.ID, agent.ID)
	}
	if d.Signature == "" {
		t.Error("signature is empty")
	}
	if d.Constraints.MaxChainDepth != 2 {
		t.Errorf("max chain depth: got %d, want 2", d.Constraints.MaxChainDepth)
	}
}

func TestDelegationSignatureVerification(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "my-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"github:*"},
		TTL:          1 * time.Hour,
	})

	// Verify the signature using the verification pipeline
	chain := DelegationChain{*d}
	result := VerifyChain(chain, DefaultVerifyOptions())

	if !result.Valid {
		t.Fatalf("delegation chain should be valid: %s", result.Error)
	}
	if result.AgentID != agent.ID {
		t.Errorf("agent ID: got %q, want %q", result.AgentID, agent.ID)
	}
	if result.RootAuthority != alice.ID {
		t.Errorf("root authority: got %q, want %q", result.RootAuthority, alice.ID)
	}
}

func TestDelegationTamperDetection(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "my-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"github:pr:create"},
		TTL:          1 * time.Hour,
	})

	// Tamper with capabilities (privilege escalation attempt)
	d.Capabilities = []string{"github:*"}

	chain := DelegationChain{*d}
	result := VerifyChain(chain, DefaultVerifyOptions())

	if result.Valid {
		t.Error("tampered delegation should be INVALID")
	}
}

func TestSubDelegation(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "primary-agent")
	subAgent, _ := NewIdentity(EntityAgent, "sub-agent")

	// Alice delegates to primary agent
	d, _ := NewDelegation(DelegationRequest{
		From:          alice,
		To:            agent,
		Capabilities:  []string{"github:pr:create,repo=myorg/*", "github:pr:merge,repo=myorg/*"},
		TTL:           2 * time.Hour,
		MaxChainDepth: 3,
	})

	chain := DelegationChain{*d}

	// Primary agent sub-delegates (narrowing) to sub-agent
	_, newChain, err := chain.SubDelegate(
		agent,
		subAgent,
		[]string{"github:pr:create,repo=myorg/app"}, // narrower
		30*time.Minute,
	)
	if err != nil {
		t.Fatalf("SubDelegate failed: %v", err)
	}

	if len(newChain) != 2 {
		t.Fatalf("expected 2-link chain, got %d", len(newChain))
	}

	// Verify the extended chain
	result := VerifyChain(newChain, DefaultVerifyOptions())
	if !result.Valid {
		t.Fatalf("sub-delegated chain should be valid: %s", result.Error)
	}
	if result.AgentID != subAgent.ID {
		t.Errorf("terminal agent should be sub-agent")
	}
	if result.ChainDepth != 2 {
		t.Errorf("chain depth: got %d, want 2", result.ChainDepth)
	}
}

func TestSubDelegationNarrowingViolation(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "primary-agent")
	subAgent, _ := NewIdentity(EntityAgent, "sub-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:          alice,
		To:            agent,
		Capabilities:  []string{"github:pr:create,repo=myorg/*"},
		TTL:           1 * time.Hour,
		MaxChainDepth: 3,
	})

	chain := DelegationChain{*d}

	// Try to sub-delegate with WIDER capabilities (should fail)
	_, _, err := chain.SubDelegate(
		agent,
		subAgent,
		[]string{"github:*"}, // wider than parent — violation!
		30*time.Minute,
	)
	if err == nil {
		t.Error("sub-delegation with wider capabilities should fail")
	}
}

func TestSubDelegationDepthLimit(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "agent")
	sub, _ := NewIdentity(EntityAgent, "sub")

	d, _ := NewDelegation(DelegationRequest{
		From:          alice,
		To:            agent,
		Capabilities:  []string{"github:*"},
		TTL:           1 * time.Hour,
		MaxChainDepth: 1, // No sub-delegation allowed
	})

	chain := DelegationChain{*d}

	_, _, err := chain.SubDelegate(agent, sub, []string{"github:pr:create"}, 30*time.Minute)
	if err == nil {
		t.Error("sub-delegation should fail when max depth is 1")
	}
}

func TestDelegationExpiry(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"github:*"},
		TTL:          1 * time.Millisecond, // expires almost immediately
	})

	// Wait for it to expire
	time.Sleep(10 * time.Millisecond)

	chain := DelegationChain{*d}
	result := VerifyChain(chain, DefaultVerifyOptions())

	if result.Valid {
		t.Error("expired delegation should be invalid")
	}
}

func TestDelegationRequiresCapabilities(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "agent")

	_, err := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{}, // no capabilities
		TTL:          1 * time.Hour,
	})
	if err == nil {
		t.Error("delegation with no capabilities should fail")
	}
}

func TestChainContinuityCheck(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent1, _ := NewIdentity(EntityAgent, "agent1")
	agent2, _ := NewIdentity(EntityAgent, "agent2")
	agent3, _ := NewIdentity(EntityAgent, "agent3")

	// Create two delegations that DON'T chain properly
	d1, _ := NewDelegation(DelegationRequest{
		From:          alice,
		To:            agent1,
		Capabilities:  []string{"github:*"},
		TTL:           1 * time.Hour,
		MaxChainDepth: 3,
	})

	// This delegation is from agent2, not agent1 — broken chain
	d2, _ := NewDelegation(DelegationRequest{
		From:         agent2,
		To:           agent3,
		Capabilities: []string{"github:pr:create"},
		TTL:          30 * time.Minute,
	})

	brokenChain := DelegationChain{*d1, *d2}
	result := VerifyChain(brokenChain, DefaultVerifyOptions())

	if result.Valid {
		t.Error("broken chain should be invalid")
	}
}
