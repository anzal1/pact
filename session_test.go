package pact

import (
	"net/http"
	"testing"
	"time"
)

// setupSessionTestChain creates a human → agent root delegation chain for testing.
func setupSessionTestChain(t *testing.T, ttl time.Duration, caps []string, maxDepth int) (DelegationChain, *Identity, *Identity) {
	t.Helper()

	human, err := NewIdentity(EntityHuman, "test-human")
	if err != nil {
		t.Fatalf("failed to create human identity: %v", err)
	}

	root, err := NewIdentity(EntityAgent, "test-root-agent")
	if err != nil {
		t.Fatalf("failed to create root agent identity: %v", err)
	}

	delegation, err := NewDelegation(DelegationRequest{
		From:          human,
		To:            root,
		Capabilities:  caps,
		TTL:           ttl,
		MaxChainDepth: maxDepth,
	})
	if err != nil {
		t.Fatalf("failed to create delegation: %v", err)
	}

	chain := DelegationChain{*delegation}
	return chain, human, root
}

func TestNewSession(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"storage:read", "storage:write"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Session should be valid
	if !session.IsValid() {
		t.Error("new session should be valid")
	}

	// Chain depth should be 2: human→root + root→session
	if session.ChainDepth() != 2 {
		t.Errorf("expected chain depth 2, got %d", session.ChainDepth())
	}

	// Session identity should be different from root
	if session.SessionIdentity().ID == session.RootIdentity().ID {
		t.Error("session identity should differ from root identity")
	}

	// Capabilities should be inherited
	caps := session.Capabilities()
	if len(caps) != 2 {
		t.Errorf("expected 2 capabilities, got %d", len(caps))
	}
}

func TestSessionSignRequest(t *testing.T) {
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Create and sign an HTTP request
	req, err := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := session.SignRequest(req); err != nil {
		t.Fatalf("SignRequest failed: %v", err)
	}

	// Verify the signed request
	result := VerifyRequest(req, VerifyOptions{
		TrustedRoots: map[string]bool{human.ID: true},
	})
	if !result.Valid {
		t.Fatalf("verification failed: %s", result.Error)
	}

	// The agent ID should be the session identity, not the root
	if result.AgentID != session.SessionIdentity().ID {
		t.Errorf("expected agent ID %s, got %s", session.SessionIdentity().ID, result.AgentID)
	}

	// Chain depth should reflect full chain
	if result.ChainDepth != 2 {
		t.Errorf("expected chain depth 2, got %d", result.ChainDepth)
	}
}

func TestSessionCapabilityNarrowing(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"storage:read", "storage:write", "api:read"}, 3)

	// Session requests only a subset of capabilities
	session, err := NewSession(chain, root, SessionConfig{
		TTL:          1 * time.Hour,
		Capabilities: []string{"storage:read"},
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	caps := session.Capabilities()
	if len(caps) != 1 || caps[0] != "storage:read" {
		t.Errorf("expected [storage:read], got %v", caps)
	}
}

func TestSessionCapabilityEscalationRejected(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"storage:read"}, 3)

	// Session requests capabilities not in parent chain — should fail
	_, err := NewSession(chain, root, SessionConfig{
		TTL:          1 * time.Hour,
		Capabilities: []string{"storage:write"},
	})
	if err == nil {
		t.Fatal("expected error for capability escalation, got nil")
	}
}

func TestSessionSubDelegate(t *testing.T) {
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"storage:read", "storage:write"}, 4)

	session, err := NewSession(chain, root, SessionConfig{
		TTL:           1 * time.Hour,
		MaxChainDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Create a sub-agent
	subAgent, err := NewIdentity(EntityAgent, "sub-agent")
	if err != nil {
		t.Fatalf("failed to create sub-agent: %v", err)
	}

	// Sub-delegate with narrowed capabilities
	_, subChain, err := session.SubDelegate(subAgent, []string{"storage:read"}, 30*time.Minute)
	if err != nil {
		t.Fatalf("SubDelegate failed: %v", err)
	}

	// Chain should be: human→root + root→session + session→sub-agent
	if len(subChain) != 3 {
		t.Errorf("expected chain length 3, got %d", len(subChain))
	}

	// Verify the sub-agent's chain
	result := VerifyChain(subChain, VerifyOptions{
		TrustedRoots: map[string]bool{human.ID: true},
	})
	if !result.Valid {
		t.Fatalf("sub-agent chain verification failed: %s", result.Error)
	}

	// Terminal entity should be the sub-agent
	if result.AgentID != subAgent.ID {
		t.Errorf("expected terminal agent %s, got %s", subAgent.ID, result.AgentID)
	}
}

func TestSessionRenew(t *testing.T) {
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	oldSessionID := session.SessionIdentity().ID

	// Renew the session
	if err := session.Renew(); err != nil {
		t.Fatalf("Renew failed: %v", err)
	}

	newSessionID := session.SessionIdentity().ID

	// New session should have a different identity
	if oldSessionID == newSessionID {
		t.Error("renewed session should have a different identity")
	}

	// Session should still be valid
	if !session.IsValid() {
		t.Error("renewed session should be valid")
	}

	// Signing with renewed session should work
	req, err := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	if err := session.SignRequest(req); err != nil {
		t.Fatalf("SignRequest after renewal failed: %v", err)
	}

	result := VerifyRequest(req, VerifyOptions{
		TrustedRoots: map[string]bool{human.ID: true},
	})
	if !result.Valid {
		t.Fatalf("verification after renewal failed: %s", result.Error)
	}
}

func TestSessionClose(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Close the session
	session.Close()

	if !session.IsClosed() {
		t.Error("session should be closed")
	}
	if session.IsValid() {
		t.Error("closed session should not be valid")
	}

	// Signing should fail
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := session.SignRequest(req); err == nil {
		t.Error("expected error signing with closed session")
	}

	// Sub-delegation should fail
	to, _ := NewIdentity(EntityAgent, "sub")
	_, _, err = session.SubDelegate(to, []string{"api:read"}, 30*time.Minute)
	if err == nil {
		t.Error("expected error sub-delegating from closed session")
	}

	// Renew should fail
	if err := session.Renew(); err == nil {
		t.Error("expected error renewing closed session")
	}

	// Closing again should be idempotent
	session.Close()
}

func TestSessionKeyZeroization(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}

	// Get a reference to the private key bytes before closing
	// (In Go this is best-effort since GC can copy)
	sessionKey := session.session.PrivateKey

	session.Close()

	// Check the key was zeroized
	allZero := true
	for _, b := range sessionKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("session private key was not zeroized after Close()")
	}
}

func TestSessionRenewZeroizesOldKey(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Capture old key
	oldKey := session.session.PrivateKey

	// Renew
	if err := session.Renew(); err != nil {
		t.Fatalf("Renew failed: %v", err)
	}

	// Old key should be zeroized
	allZero := true
	for _, b := range oldKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if !allZero {
		t.Error("old session key was not zeroized after Renew()")
	}
}

func TestSessionWithKeyStore(t *testing.T) {
	store := NewMemoryKeyStore()

	// Create and store a root identity
	root, err := NewIdentity(EntityAgent, "my-agent")
	if err != nil {
		t.Fatalf("failed to create root: %v", err)
	}
	if err := store.Store(root); err != nil {
		t.Fatalf("failed to store root: %v", err)
	}

	// Create parent chain (human → root)
	human, err := NewIdentity(EntityHuman, "user")
	if err != nil {
		t.Fatalf("failed to create human: %v", err)
	}
	delegation, err := NewDelegation(DelegationRequest{
		From:          human,
		To:            root,
		Capabilities:  []string{"api:read", "api:write"},
		TTL:           24 * time.Hour,
		MaxChainDepth: 3,
	})
	if err != nil {
		t.Fatalf("failed to create delegation: %v", err)
	}
	chain := DelegationChain{*delegation}

	// Open session from KeyStore
	session, err := OpenSession(chain, store, "my-agent", SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("OpenSession failed: %v", err)
	}
	defer session.Close()

	if !session.IsValid() {
		t.Error("session should be valid")
	}

	// Root identity should match what we stored
	if session.RootIdentity().ID != root.ID {
		t.Errorf("root identity mismatch: %s != %s", session.RootIdentity().ID, root.ID)
	}
}

func TestSessionFullChainVerification(t *testing.T) {
	// This is the key test: verify that a 3-hop chain
	// (human → root → session) verifies end-to-end with offline verification.
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"email:send", "email:read"}, 4)

	session, err := NewSession(chain, root, SessionConfig{
		TTL:           30 * time.Minute,
		Capabilities:  []string{"email:read"},
		MaxChainDepth: 2,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Verify the full chain offline
	fullChain := session.Chain()
	result := VerifyChain(fullChain, VerifyOptions{
		TrustedRoots:       map[string]bool{human.ID: true},
		RequiredCapability: "email:read",
	})
	if !result.Valid {
		t.Fatalf("full chain verification failed: %s", result.Error)
	}

	// Root authority should be the human
	if result.RootAuthority != human.ID {
		t.Errorf("expected root authority %s, got %s", human.ID, result.RootAuthority)
	}

	// Agent ID should be the session (terminal entity)
	if result.AgentID != session.SessionIdentity().ID {
		t.Errorf("expected agent %s, got %s", session.SessionIdentity().ID, result.AgentID)
	}

	// Capabilities should be narrowed to email:read
	if len(result.Capabilities) != 1 || result.Capabilities[0] != "email:read" {
		t.Errorf("expected [email:read], got %v", result.Capabilities)
	}

	// Should fail for capabilities the session doesn't have
	resultBad := VerifyChain(fullChain, VerifyOptions{
		TrustedRoots:       map[string]bool{human.ID: true},
		RequiredCapability: "email:send",
	})
	if resultBad.Valid {
		t.Error("verification should fail for capability the session doesn't have")
	}
}

func TestSessionTTLClampedToParent(t *testing.T) {
	// Parent chain expires in 30 minutes
	chain, _, root := setupSessionTestChain(t, 30*time.Minute, []string{"api:read"}, 3)

	// Request 1 hour TTL — should be clamped to ~30 minutes
	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Session should expire before or at parent expiry
	remaining := session.TimeRemaining()
	if remaining > 31*time.Minute {
		t.Errorf("session TTL should be clamped to parent, got %v remaining", remaining)
	}
}

func TestSessionChainDepthExceeded(t *testing.T) {
	// Parent chain with max depth 1 (no sub-delegation allowed)
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 1)

	// Session creation should fail — chain is already at max depth
	_, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err == nil {
		t.Fatal("expected error when chain depth is exceeded")
	}
}

func TestSessionDefaultConfig(t *testing.T) {
	config := SessionConfig{}.withDefaults()

	if config.TTL != 1*time.Hour {
		t.Errorf("expected default TTL 1h, got %v", config.TTL)
	}
	if config.MaxChainDepth != 2 {
		t.Errorf("expected default MaxChainDepth 2, got %d", config.MaxChainDepth)
	}
}

func TestSessionNilRoot(t *testing.T) {
	chain, _, _ := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	_, err := NewSession(chain, nil, SessionConfig{})
	if err == nil {
		t.Fatal("expected error for nil root")
	}
}

func TestSessionRootMismatch(t *testing.T) {
	chain, _, _ := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	// Create a different root that doesn't match the chain terminal
	wrongRoot, _ := NewIdentity(EntityAgent, "wrong")

	_, err := NewSession(chain, wrongRoot, SessionConfig{})
	if err == nil {
		t.Fatal("expected error for root identity mismatch")
	}
}

func TestSessionEmptyChain(t *testing.T) {
	root, _ := NewIdentity(EntityAgent, "root")

	_, err := NewSession(DelegationChain{}, root, SessionConfig{})
	if err == nil {
		t.Fatal("expected error for empty chain")
	}
}

func TestSessionTimeRemaining(t *testing.T) {
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	remaining := session.TimeRemaining()
	if remaining <= 0 || remaining > 1*time.Hour {
		t.Errorf("unexpected time remaining: %v", remaining)
	}
}

func TestSessionMultipleRenewals(t *testing.T) {
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Renew 3 times — each time should produce a new session identity
	ids := make(map[string]bool)
	ids[session.SessionIdentity().ID] = true

	for i := 0; i < 3; i++ {
		if err := session.Renew(); err != nil {
			t.Fatalf("Renew %d failed: %v", i, err)
		}

		newID := session.SessionIdentity().ID
		if ids[newID] {
			t.Errorf("renewal %d produced duplicate identity", i)
		}
		ids[newID] = true

		// Each renewal should produce valid chains
		req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
		if err := session.SignRequest(req); err != nil {
			t.Fatalf("SignRequest after renewal %d failed: %v", i, err)
		}

		result := VerifyRequest(req, VerifyOptions{
			TrustedRoots: map[string]bool{human.ID: true},
		})
		if !result.Valid {
			t.Fatalf("verification after renewal %d failed: %s", i, result.Error)
		}
	}

	if len(ids) != 4 {
		t.Errorf("expected 4 unique session IDs, got %d", len(ids))
	}
}

func TestSessionSubDelegateToSubAgent(t *testing.T) {
	// Full 4-hop scenario: human → root → session → sub-agent
	chain, human, root := setupSessionTestChain(t, 24*time.Hour, []string{"storage:read", "storage:write"}, 5)

	session, err := NewSession(chain, root, SessionConfig{
		TTL:           1 * time.Hour,
		MaxChainDepth: 3,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Create sub-agent and delegate
	subAgent, _ := NewIdentity(EntityAgent, "indexer")
	_, subChain, err := session.SubDelegate(subAgent, []string{"storage:read"}, 15*time.Minute)
	if err != nil {
		t.Fatalf("SubDelegate failed: %v", err)
	}

	// Sub-agent should be able to sign and verify
	req, _ := http.NewRequest("GET", "https://storage.example.com/bucket/file.txt", nil)
	if err := SignRequest(req, subAgent, subChain); err != nil {
		t.Fatalf("sub-agent SignRequest failed: %v", err)
	}

	result := VerifyRequest(req, VerifyOptions{
		TrustedRoots:       map[string]bool{human.ID: true},
		RequiredCapability: "storage:read",
	})
	if !result.Valid {
		t.Fatalf("sub-agent request verification failed: %s", result.Error)
	}

	// Chain should trace back to human
	if result.RootAuthority != human.ID {
		t.Errorf("expected root authority %s, got %s", human.ID, result.RootAuthority)
	}

	// Terminal entity should be the sub-agent
	if result.AgentID != subAgent.ID {
		t.Errorf("expected terminal %s, got %s", subAgent.ID, result.AgentID)
	}
}

func TestSessionExpiry(t *testing.T) {
	// Create a chain with very short remaining TTL
	// We can't easily test actual expiry in unit tests without time mocking,
	// but we can test the TTL clamping and validation
	chain, _, root := setupSessionTestChain(t, 24*time.Hour, []string{"api:read"}, 3)

	session, err := NewSession(chain, root, SessionConfig{
		TTL: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	defer session.Close()

	// Manually set expiry to the past to test expiry behavior
	session.mu.Lock()
	session.expiresAt = time.Now().Add(-1 * time.Minute)
	session.mu.Unlock()

	if session.IsValid() {
		t.Error("expired session should not be valid")
	}

	if session.TimeRemaining() != 0 {
		t.Error("expired session should have 0 time remaining")
	}

	// Signing should fail
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	if err := session.SignRequest(req); err == nil {
		t.Error("expected error signing with expired session")
	}

	// Sub-delegation should fail
	to, _ := NewIdentity(EntityAgent, "sub")
	_, _, err = session.SubDelegate(to, []string{"api:read"}, 30*time.Minute)
	if err == nil {
		t.Error("expected error sub-delegating from expired session")
	}
}
