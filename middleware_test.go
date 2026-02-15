package pact

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareVerifiesValidRequest(t *testing.T) {
	// Setup: create identities and delegation
	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	// Create a handler that checks the context
	var gotResult *VerificationResult
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotResult = FromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with middleware
	protected := Middleware(MiddlewareConfig{
		VerifyOptions: VerifyOptions{
			RequiredCapability: "api:read",
		},
	})(handler)

	// Create and sign a request
	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	if err := SignRequest(req, agent, chain); err != nil {
		t.Fatalf("failed to sign request: %v", err)
	}

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if gotResult == nil {
		t.Fatal("expected verification result in context")
	}
	if !gotResult.Valid {
		t.Fatalf("expected valid result, got error: %s", gotResult.Error)
	}
	if gotResult.AgentID != agent.ID {
		t.Fatalf("expected agent ID %s, got %s", agent.ID, gotResult.AgentID)
	}
	if gotResult.RootAuthority != human.ID {
		t.Fatalf("expected root %s, got %s", human.ID, gotResult.RootAuthority)
	}
}

func TestMiddlewareRejectsUnsignedRequest(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for unsigned request")
	})

	protected := Middleware(MiddlewareConfig{})(handler)

	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestMiddlewareOptionalPassthrough(t *testing.T) {
	var handlerCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		result := FromContext(r.Context())
		if result != nil {
			t.Fatal("expected no verification result for unsigned request in optional mode")
		}
		w.WriteHeader(http.StatusOK)
	})

	protected := Middleware(MiddlewareConfig{
		Optional: true,
	})(handler)

	// Request without Pact headers
	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if !handlerCalled {
		t.Fatal("handler should be called in optional mode")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}

func TestMiddlewareRejectsInsufficientCapability(t *testing.T) {
	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler should not be called for insufficient capability")
	})

	// Require write capability, but delegation only grants read
	protected := Middleware(MiddlewareConfig{
		VerifyOptions: VerifyOptions{
			RequiredCapability: "api:write",
		},
	})(handler)

	req := httptest.NewRequest("POST", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "lacks required capability") {
		t.Fatalf("expected capability error, got: %s", rr.Body.String())
	}
}

func TestMiddlewareDynamicCapability(t *testing.T) {
	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read", "api:write"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	protected := Middleware(MiddlewareConfig{
		CapabilityForRequest: func(r *http.Request) string {
			if r.Method == "GET" {
				return "api:read"
			}
			return "api:write"
		},
	})(handler)

	// GET should work (requires read, has read)
	getReq := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	getReq.Host = "api.example.com"
	SignRequest(getReq, agent, chain)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, getReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	// POST should work (requires write, has write)
	postReq := httptest.NewRequest("POST", "https://api.example.com/data", strings.NewReader("body"))
	postReq.Host = "api.example.com"
	SignRequest(postReq, agent, chain)

	rr = httptest.NewRecorder()
	protected.ServeHTTP(rr, postReq)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareOnFailedCallback(t *testing.T) {
	var failedCalled bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should be called because OnFailed returns true (permissive mode)
		result := FromContext(r.Context())
		if result == nil {
			t.Fatal("expected result in context even in permissive failure")
		}
		w.WriteHeader(http.StatusOK)
	})

	protected := Middleware(MiddlewareConfig{
		VerifyOptions: VerifyOptions{
			RequiredCapability: "admin:nuke",
		},
		OnFailed: func(w http.ResponseWriter, r *http.Request, result *VerificationResult) bool {
			failedCalled = true
			// Return true = continue to handler anyway (permissive/audit mode)
			return true
		},
	})(handler)

	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")
	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if !failedCalled {
		t.Fatal("OnFailed should have been called")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 in permissive mode, got %d", rr.Code)
	}
}

func TestMiddlewareOnVerifiedCallback(t *testing.T) {
	var verifiedAgent string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	protected := Middleware(MiddlewareConfig{
		OnVerified: func(r *http.Request, result *VerificationResult) {
			verifiedAgent = result.AgentID
		},
	})(handler)

	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")
	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"*"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if verifiedAgent != agent.ID {
		t.Fatalf("OnVerified should have captured agent ID %s, got %s", agent.ID, verifiedAgent)
	}
}

func TestRequireCapabilityShorthand(t *testing.T) {
	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"deploy:create"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	protected := RequireCapability("deploy:create")(handler)

	req := httptest.NewRequest("POST", "https://api.example.com/deploy", nil)
	req.Host = "api.example.com"
	SignRequest(req, agent, chain)

	rr := httptest.NewRecorder()
	protected.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestMiddlewareEndToEndWithServer(t *testing.T) {
	// Full end-to-end: real HTTP server with Pact middleware
	human, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	delegation, _ := NewDelegation(DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := DelegationChain{*delegation}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := MustFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "agent="+result.AgentID)
	})

	protected := Middleware(MiddlewareConfig{
		VerifyOptions: VerifyOptions{
			RequiredCapability: "api:read",
			TrustedRoots:       map[string]bool{human.ID: true},
		},
	})(handler)

	server := httptest.NewServer(protected)
	defer server.Close()

	// Create a signed request to the test server
	req, _ := http.NewRequest("GET", server.URL+"/data", nil)
	req.Host = "api.example.com" // Override for consistent signing
	if err := SignRequest(req, agent, chain); err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(body))
	}
	if !strings.Contains(string(body), agent.ID) {
		t.Fatalf("expected agent ID in response, got: %s", string(body))
	}
}
