package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	pact "github.com/anzal1/pact"
)

var store struct {
	human      *pact.Identity
	delegation *pact.Delegation
}

func main() {
	addr := ":8090"
	if a := os.Getenv("PACT_DEMO_ADDR"); a != "" {
		addr = a
	}

	human, err := pact.NewIdentity(pact.EntityHuman, "alice")
	if err != nil {
		log.Fatalf("creating human identity: %v", err)
	}
	store.human = human
	log.Printf("Human identity: %s", human.ID)

	mux := http.NewServeMux()
	mux.HandleFunc("/setup/delegate", handleSetupDelegate)

	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/api/data", handleData)
	protectedMux.HandleFunc("/api/deploy", handleDeploy)

	protected := pact.Middleware(pact.MiddlewareConfig{
		VerifyOptions: pact.VerifyOptions{
			MaxClockSkew: 30 * time.Second,
		},
		CapabilityForRequest: func(r *http.Request) string {
			switch {
			case r.URL.Path == "/api/data" && r.Method == "GET":
				return "api:read"
			case r.URL.Path == "/api/data" && r.Method == "POST":
				return "api:write"
			case r.URL.Path == "/api/deploy":
				return "deploy:create"
			default:
				return ""
			}
		},
		OnVerified: func(r *http.Request, result *pact.VerificationResult) {
			log.Printf("verified: agent=%s root=%s caps=%v depth=%d",
				result.AgentID, result.RootAuthority,
				result.Capabilities, result.ChainDepth)
		},
		OnFailed: func(w http.ResponseWriter, r *http.Request, result *pact.VerificationResult) bool {
			log.Printf("rejected: %s %s - %s", r.Method, r.URL.Path, result.Error)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]string{
				"error":   "unauthorized",
				"details": result.Error,
			})
			return false
		},
	})(protectedMux)

	mux.Handle("/api/", protected)

	log.Printf("Pact demo server listening on %s", addr)
	log.Printf("  POST /setup/delegate  - get a delegation chain")
	log.Printf("  GET  /api/data        - requires api:read")
	log.Printf("  POST /api/data        - requires api:write")
	log.Printf("  POST /api/deploy      - requires deploy:create")
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("server: %v", err)
	}
}

func handleSetupDelegate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, `{"error":"method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		AgentPublicKey string   `json:"agent_public_key"`
		AgentName      string   `json:"agent_name"`
		Capabilities   []string `json:"capabilities"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid request body"}`, http.StatusBadRequest)
		return
	}
	if req.AgentPublicKey == "" || req.AgentName == "" {
		http.Error(w, `{"error":"agent_public_key and agent_name required"}`, http.StatusBadRequest)
		return
	}
	if len(req.Capabilities) == 0 {
		req.Capabilities = []string{"api:read"}
	}

	pubKeyBytes, err := base64.RawURLEncoding.DecodeString(req.AgentPublicKey)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"invalid public key encoding: %v"}`, err), http.StatusBadRequest)
		return
	}

	agent := pact.IdentityFromPublicKey(pact.EntityAgent, ed25519.PublicKey(pubKeyBytes))

	delegation, err := pact.NewDelegation(pact.DelegationRequest{
		From:          store.human,
		To:            agent,
		Capabilities:  req.Capabilities,
		TTL:           time.Hour,
		MaxChainDepth: 3,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"delegation failed: %v"}`, err), http.StatusInternalServerError)
		return
	}
	store.delegation = delegation

	log.Printf("Delegated to agent %s (name=%s): %v", agent.ID, req.AgentName, req.Capabilities)

	chain := pact.DelegationChain{*delegation}
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		http.Error(w, `{"error":"serialization failed"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"delegation_chain": json.RawMessage(chainJSON),
		"human_id":         store.human.ID,
		"agent_id":         agent.ID,
	})
}

func handleData(w http.ResponseWriter, r *http.Request) {
	result := pact.MustFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")

	if r.Method == "POST" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message":  "Data accepted",
			"agent":    result.AgentID,
			"root":     result.RootAuthority,
			"verified": true,
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":  "Hello from Pact-protected API!",
		"agent":    result.AgentID,
		"root":     result.RootAuthority,
		"verified": true,
		"data": []map[string]string{
			{"id": "1", "name": "Project Alpha"},
			{"id": "2", "name": "Project Beta"},
		},
	})
}

func handleDeploy(w http.ResponseWriter, r *http.Request) {
	result := pact.MustFromContext(r.Context())
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message":      "Deployment initiated",
		"agent":        result.AgentID,
		"root":         result.RootAuthority,
		"capabilities": result.Capabilities,
		"verified":     true,
	})
}
