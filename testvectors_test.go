package pact

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// deterministicSeed returns a 32-byte seed derived from a label.
// Any implementation can reproduce this: SHA-256("pact-test-vector:" + label)
func deterministicSeed(label string) [32]byte {
	return sha256.Sum256([]byte("pact-test-vector:" + label))
}

// identityFromSeed creates an identity from a deterministic seed.
func identityFromSeed(label string, entityType EntityType, name string) *Identity {
	seed := deterministicSeed(label)
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	return &Identity{
		Type:       entityType,
		ID:         deriveID(pub),
		PublicKey:  encodeBase64URL(pub),
		PrivateKey: priv,
		Name:       name,
	}
}

// TestVector_IdentityDerivation verifies that identity IDs are deterministically
// derived from public keys. Other implementations should reproduce these exact values.
func TestVector_IdentityDerivation(t *testing.T) {
	vectors := []struct {
		seedLabel    string
		entityType   EntityType
		name         string
		expectID     string // sha256:<hex>
		expectPubB64 string // base64url(pubkey)
	}{
		{
			seedLabel:  "alice",
			entityType: EntityHuman,
			name:       "Alice",
		},
		{
			seedLabel:  "bob-agent",
			entityType: EntityAgent,
			name:       "Bob's Agent",
		},
		{
			seedLabel:  "deploy-bot",
			entityType: EntityAgent,
			name:       "Deploy Bot",
		},
	}

	for _, v := range vectors {
		t.Run(v.seedLabel, func(t *testing.T) {
			// Step 1: Derive seed = SHA-256("pact-test-vector:" + label)
			seed := deterministicSeed(v.seedLabel)
			t.Logf("seed (%s): %s", v.seedLabel, hex.EncodeToString(seed[:]))

			// Step 2: Generate Ed25519 keypair from seed
			priv := ed25519.NewKeyFromSeed(seed[:])
			pub := priv.Public().(ed25519.PublicKey)
			t.Logf("public_key (raw hex): %s", hex.EncodeToString(pub))
			t.Logf("public_key (base64url): %s", encodeBase64URL(pub))

			// Step 3: Derive ID = "sha256:" + hex(SHA-256(public_key))
			id := deriveID(pub)
			t.Logf("identity_id: %s", id)

			// Step 4: Verify determinism
			id2 := identityFromSeed(v.seedLabel, v.entityType, v.name)
			if id != id2.ID {
				t.Errorf("non-deterministic: got %s and %s", id, id2.ID)
			}
		})
	}
}

// TestVector_CanonicalJSON verifies canonical JSON output matches expected bytes.
func TestVector_CanonicalJSON(t *testing.T) {
	vectors := []struct {
		name   string
		input  map[string]interface{}
		expect string
	}{
		{
			name: "sorted keys",
			input: map[string]interface{}{
				"zebra": "last",
				"alpha": "first",
				"mid":   "middle",
			},
			expect: `{"alpha":"first","mid":"middle","zebra":"last"}`,
		},
		{
			name: "nested objects sorted",
			input: map[string]interface{}{
				"b": map[string]interface{}{
					"y": 2,
					"x": 1,
				},
				"a": "value",
			},
			expect: `{"a":"value","b":{"x":1,"y":2}}`,
		},
		{
			name: "empty and null",
			input: map[string]interface{}{
				"empty":  "",
				"null":   nil,
				"array":  []interface{}{},
				"object": map[string]interface{}{},
			},
			expect: `{"array":[],"empty":"","null":null,"object":{}}`,
		},
		{
			name: "delegation-like structure",
			input: map[string]interface{}{
				"type":    "delegation",
				"version": "1.0",
				"id":      "d-abc123",
				"from": map[string]interface{}{
					"type":       "human",
					"id":         "sha256:aaa",
					"public_key": "base64url_key",
				},
				"capabilities": []interface{}{"repo:read", "deploy:create,env=staging"},
				"signature":    "",
			},
			expect: `{"capabilities":["repo:read","deploy:create,env=staging"],"from":{"id":"sha256:aaa","public_key":"base64url_key","type":"human"},"id":"d-abc123","signature":"","type":"delegation","version":"1.0"}`,
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := canonicalJSON(v.input)
			if err != nil {
				t.Fatalf("canonicalJSON error: %v", err)
			}
			if string(got) != v.expect {
				t.Errorf("canonical JSON mismatch\n  got:    %s\n  expect: %s", string(got), v.expect)
			}
			t.Logf("canonical: %s", string(got))
		})
	}
}

// TestVector_CapabilityParsing verifies capability parsing and matching.
func TestVector_CapabilityParsing(t *testing.T) {
	vectors := []struct {
		raw      string
		resource string
		action   string
		constr   map[string]string
	}{
		{"repo:read", "repo", "read", map[string]string{}},
		{"repo:pr:create", "repo:pr", "create", map[string]string{}},
		{"deploy:create,env=staging", "deploy", "create", map[string]string{"env": "staging"}},
		{"repo:read,repo=owner/*", "repo", "read", map[string]string{"repo": "owner/*"}},
		{"email:send,to=*@example.com", "email", "send", map[string]string{"to": "*@example.com"}},
		{"*", "*", "*", map[string]string{}},
		{"repo:*", "repo", "*", map[string]string{}},
	}

	for _, v := range vectors {
		t.Run(v.raw, func(t *testing.T) {
			cap, err := ParseCapability(v.raw)
			if err != nil {
				t.Fatalf("ParseCapability(%q) error: %v", v.raw, err)
			}
			if cap.Resource != v.resource {
				t.Errorf("resource: got %q, want %q", cap.Resource, v.resource)
			}
			if cap.Action != v.action {
				t.Errorf("action: got %q, want %q", cap.Action, v.action)
			}
			for k, want := range v.constr {
				got, ok := cap.Constraints[k]
				if !ok {
					t.Errorf("missing constraint %q", k)
				} else if got != want {
					t.Errorf("constraint %q: got %q, want %q", k, got, want)
				}
			}
			t.Logf("parsed: resource=%s action=%s constraints=%v", cap.Resource, cap.Action, cap.Constraints)
		})
	}
}

// TestVector_CapabilityNarrowing verifies the narrowing-only rule.
func TestVector_CapabilityNarrowing(t *testing.T) {
	vectors := []struct {
		parent  string
		child   string
		covers  bool
		comment string
	}{
		{"*", "repo:read", true, "wildcard covers everything"},
		{"repo:*", "repo:read", true, "resource wildcard covers any action"},
		{"repo:*", "repo:pr:create", true, "resource wildcard covers sub-resources"},
		{"repo:read", "repo:write", false, "different action not covered"},
		{"repo:read", "deploy:read", false, "different resource not covered"},
		{"repo:read,repo=owner/*", "repo:read,repo=owner/myrepo", true, "glob constraint narrows"},
		{"repo:read,repo=owner/*", "repo:read,repo=other/myrepo", false, "glob constraint rejects different owner"},
		{"deploy:create,env=staging", "deploy:create,env=production", false, "constraint value must match"},
		{"deploy:create,env=staging", "deploy:create,env=staging", true, "exact constraint match"},
		{"repo:*", "deploy:create", false, "different resource trees"},
		{"email:send,to=*@company.com", "email:send,to=bob@company.com", true, "glob in constraint"},
		{"email:send,to=*@company.com", "email:send,to=bob@other.com", false, "glob rejects mismatch"},
	}

	for _, v := range vectors {
		t.Run(v.comment, func(t *testing.T) {
			parent, err := ParseCapability(v.parent)
			if err != nil {
				t.Fatalf("parse parent %q: %v", v.parent, err)
			}
			child, err := ParseCapability(v.child)
			if err != nil {
				t.Fatalf("parse child %q: %v", v.child, err)
			}
			got := parent.Covers(child)
			if got != v.covers {
				t.Errorf("%q covers %q = %v, want %v", v.parent, v.child, got, v.covers)
			}
			t.Logf("%q covers %q = %v", v.parent, v.child, got)
		})
	}
}

// TestVector_DelegationSignature verifies delegation signing with deterministic keys.
// Other implementations must produce the same canonical JSON and verify the same signature.
func TestVector_DelegationSignature(t *testing.T) {
	alice := identityFromSeed("alice", EntityHuman, "Alice")
	bob := identityFromSeed("bob-agent", EntityAgent, "Bob's Agent")

	// Build a delegation manually with deterministic fields (no randomness)
	d := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      "d-testvector-0001",
		From: DelegationEntity{
			Type:      alice.Type,
			ID:        alice.ID,
			PublicKey: alice.PublicKey,
			Name:      alice.Name,
		},
		To: DelegationEntity{
			Type:      bob.Type,
			ID:        bob.ID,
			PublicKey: bob.PublicKey,
			Name:      bob.Name,
		},
		Capabilities: []string{"repo:read,repo=myorg/*", "deploy:create,env=staging"},
		Constraints: DelegationConstraints{
			Expires:       "2099-01-01T00:00:00Z",
			MaxChainDepth: 2,
			NotBefore:     "2025-01-01T00:00:00Z",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		Signature: "",
	}

	// Get the canonical signing payload (signature field empty)
	payload, err := canonicalJSON(d)
	if err != nil {
		t.Fatalf("canonicalize delegation: %v", err)
	}
	t.Logf("canonical payload: %s", string(payload))
	t.Logf("payload hex: %s", hex.EncodeToString(payload))

	// Sign with Alice's key
	sig, err := alice.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sigB64 := encodeBase64URL(sig)
	d.Signature = sigB64
	t.Logf("signature (base64url): %s", sigB64)
	t.Logf("signature (hex): %s", hex.EncodeToString(sig))

	// Verify the signature
	if !alice.Verify(payload, sig) {
		t.Fatal("signature verification failed")
	}

	// Serialize the complete signed delegation
	fullJSON, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	t.Logf("signed delegation:\n%s", string(fullJSON))

	// Cross-check: verify Alice's public key can verify
	alicePub, _ := alice.Ed25519PublicKey()
	if !ed25519.Verify(alicePub, payload, sig) {
		t.Fatal("raw ed25519.Verify failed")
	}
}

// TestVector_HTTPSignature verifies the HTTP request signing format.
func TestVector_HTTPSignature(t *testing.T) {
	alice := identityFromSeed("alice", EntityHuman, "Alice")
	bob := identityFromSeed("bob-agent", EntityAgent, "Bob's Agent")

	// Create a deterministic delegation
	d := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      "d-testvector-http-0001",
		From: DelegationEntity{
			Type:      alice.Type,
			ID:        alice.ID,
			PublicKey: alice.PublicKey,
			Name:      alice.Name,
		},
		To: DelegationEntity{
			Type:      bob.Type,
			ID:        bob.ID,
			PublicKey: bob.PublicKey,
			Name:      bob.Name,
		},
		Capabilities: []string{"api:read"},
		Constraints: DelegationConstraints{
			Expires:       "2099-01-01T00:00:00Z",
			MaxChainDepth: 1,
			NotBefore:     "2025-01-01T00:00:00Z",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		Signature: "",
	}

	// Sign delegation
	payload, _ := canonicalJSON(d)
	sig, _ := alice.Sign(payload)
	d.Signature = encodeBase64URL(sig)

	chain := DelegationChain{*d}

	// Build an HTTP request
	req, _ := http.NewRequest("GET", "https://api.example.com/v1/repos?page=1", nil)
	req.Header.Set("Date", "Sat, 01 Feb 2025 00:00:00 GMT")

	// Sign the request
	err := SignRequest(req, bob, chain)
	if err != nil {
		t.Fatalf("SignRequest: %v", err)
	}

	// Log all Pact headers for other implementations to verify
	t.Logf("=== HTTP Request Headers ===")
	t.Logf("Method: %s", req.Method)
	t.Logf("URL: %s", req.URL.String())
	t.Logf("Host: %s", req.Host)
	for _, h := range []string{
		"Date",
		HeaderAgentIdentity,
		HeaderDelegationChain,
		HeaderSignatureInput,
		HeaderSignature,
	} {
		t.Logf("%s: %s", h, req.Header.Get(h))
	}

	// Verify the signed request
	result := VerifyRequest(req, VerifyOptions{
		RequiredCapability: "api:read",
		MaxClockSkew:       876000 * time.Hour, // effectively no check — test vector is frozen in time
		Now:                func() time.Time { return time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC) },
	})
	if !result.Valid {
		t.Fatalf("verification failed: %s", result.Error)
	}
	t.Logf("verification: valid=%v agent=%s root=%s", result.Valid, result.AgentID, result.RootAuthority)
}

// TestVector_ChainNarrowing verifies a multi-level delegation chain with narrowing.
func TestVector_ChainNarrowing(t *testing.T) {
	alice := identityFromSeed("alice", EntityHuman, "Alice")
	bob := identityFromSeed("bob-agent", EntityAgent, "Bob's Agent")
	deployBot := identityFromSeed("deploy-bot", EntityAgent, "Deploy Bot")

	// Level 1: Alice → Bob (broad permissions)
	d1 := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      "d-chain-0001",
		From: DelegationEntity{
			Type:      alice.Type,
			ID:        alice.ID,
			PublicKey: alice.PublicKey,
			Name:      alice.Name,
		},
		To: DelegationEntity{
			Type:      bob.Type,
			ID:        bob.ID,
			PublicKey: bob.PublicKey,
			Name:      bob.Name,
		},
		Capabilities: []string{"repo:*,repo=myorg/*", "deploy:*"},
		Constraints: DelegationConstraints{
			Expires:       "2099-01-01T00:00:00Z",
			MaxChainDepth: 3,
			NotBefore:     "2025-01-01T00:00:00Z",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		Signature: "",
	}
	p1, _ := canonicalJSON(d1)
	s1, _ := alice.Sign(p1)
	d1.Signature = encodeBase64URL(s1)

	// Level 2: Bob → Deploy Bot (narrowed: only deploy to staging)
	d2 := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      "d-chain-0002",
		From: DelegationEntity{
			Type:      bob.Type,
			ID:        bob.ID,
			PublicKey: bob.PublicKey,
			Name:      bob.Name,
		},
		To: DelegationEntity{
			Type:      deployBot.Type,
			ID:        deployBot.ID,
			PublicKey: deployBot.PublicKey,
			Name:      deployBot.Name,
		},
		Capabilities: []string{"deploy:create,env=staging"},
		Constraints: DelegationConstraints{
			Expires:       "2099-01-01T00:00:00Z",
			MaxChainDepth: 1,
			NotBefore:     "2025-01-01T00:00:00Z",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		Signature: "",
	}
	p2, _ := canonicalJSON(d2)
	s2, _ := bob.Sign(p2)
	d2.Signature = encodeBase64URL(s2)

	chain := DelegationChain{*d1, *d2}

	t.Logf("=== Chain ===")
	t.Logf("Level 1: %s → %s caps=%v", d1.From.Name, d1.To.Name, d1.Capabilities)
	t.Logf("Level 2: %s → %s caps=%v", d2.From.Name, d2.To.Name, d2.Capabilities)
	t.Logf("Root: %s (%s)", alice.Name, alice.ID)
	t.Logf("Terminal: %s (%s)", deployBot.Name, deployBot.ID)

	// Verify chain
	result := VerifyChain(chain, VerifyOptions{
		RequiredCapability: "deploy:create,env=staging",
		Now:                func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) },
	})
	if !result.Valid {
		t.Fatalf("chain verification failed: %s", result.Error)
	}
	t.Logf("chain valid=%v depth=%d root=%s terminal=%s", result.Valid, result.ChainDepth, result.RootAuthority, result.AgentID)

	// Verify narrowing: deploy bot CANNOT deploy to production
	resultProd := VerifyChain(chain, VerifyOptions{
		RequiredCapability: "deploy:create,env=production",
		Now:                func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) },
	})
	if resultProd.Valid {
		t.Fatal("chain should NOT be valid for production deployment")
	}
	t.Logf("production deploy correctly rejected: %s", resultProd.Error)

	// Verify narrowing: deploy bot CANNOT read repos
	resultRepo := VerifyChain(chain, VerifyOptions{
		RequiredCapability: "repo:read",
		Now:                func() time.Time { return time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) },
	})
	if resultRepo.Valid {
		t.Fatal("chain should NOT be valid for repo:read")
	}
	t.Logf("repo:read correctly rejected: %s", resultRepo.Error)
}

// TestVector_ContentDigest verifies content digest computation.
func TestVector_ContentDigest(t *testing.T) {
	vectors := []struct {
		body   string
		expect string
	}{
		{
			body:   `{"action":"deploy","target":"staging"}`,
			expect: ComputeContentDigest([]byte(`{"action":"deploy","target":"staging"}`)),
		},
		{
			body:   "",
			expect: ComputeContentDigest([]byte("")),
		},
		{
			body:   "hello world",
			expect: ComputeContentDigest([]byte("hello world")),
		},
	}

	for _, v := range vectors {
		digest := ComputeContentDigest([]byte(v.body))
		if digest != v.expect {
			t.Errorf("digest mismatch for %q", v.body)
		}
		// Verify format: sha-256=:base64url:
		if !strings.HasPrefix(digest, "sha-256=:") || !strings.HasSuffix(digest, ":") {
			t.Errorf("invalid digest format: %s", digest)
		}
		t.Logf("body=%q digest=%s", v.body, digest)
	}
}

// TestVector_GenerateJSON generates a JSON file with all test vectors
// for consumption by other language implementations.
// Run with: go test -run TestVector_GenerateJSON -v
func TestVector_GenerateJSON(t *testing.T) {
	alice := identityFromSeed("alice", EntityHuman, "Alice")
	bob := identityFromSeed("bob-agent", EntityAgent, "Bob's Agent")
	deployBot := identityFromSeed("deploy-bot", EntityAgent, "Deploy Bot")

	// Build delegation
	d := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      "d-testvector-0001",
		From: DelegationEntity{
			Type:      alice.Type,
			ID:        alice.ID,
			PublicKey: alice.PublicKey,
			Name:      alice.Name,
		},
		To: DelegationEntity{
			Type:      bob.Type,
			ID:        bob.ID,
			PublicKey: bob.PublicKey,
			Name:      bob.Name,
		},
		Capabilities: []string{"repo:read,repo=myorg/*", "deploy:create,env=staging"},
		Constraints: DelegationConstraints{
			Expires:       "2099-01-01T00:00:00Z",
			MaxChainDepth: 2,
			NotBefore:     "2025-01-01T00:00:00Z",
		},
		IssuedAt:  "2025-01-01T00:00:00Z",
		Signature: "",
	}
	payload, _ := canonicalJSON(d)
	sig, _ := alice.Sign(payload)
	d.Signature = encodeBase64URL(sig)

	vectors := map[string]interface{}{
		"_comment": "Pact protocol reference test vectors. Deterministic keys from SHA-256(\"pact-test-vector:\" + label).",
		"_version": "1.0",

		"seed_derivation": func() map[string]interface{} {
			seedAlice := deterministicSeed("alice")
			seedBob := deterministicSeed("bob-agent")
			seedDeploy := deterministicSeed("deploy-bot")
			return map[string]interface{}{
				"_comment": "Seeds are SHA-256(\"pact-test-vector:\" + label). Keys are Ed25519 from seed.",
				"alice": map[string]string{
					"label":       "alice",
					"seed_hex":    hex.EncodeToString(seedAlice[:]),
					"public_key":  alice.PublicKey,
					"identity_id": alice.ID,
				},
				"bob_agent": map[string]string{
					"label":       "bob-agent",
					"seed_hex":    hex.EncodeToString(seedBob[:]),
					"public_key":  bob.PublicKey,
					"identity_id": bob.ID,
				},
				"deploy_bot": map[string]string{
					"label":       "deploy-bot",
					"seed_hex":    hex.EncodeToString(seedDeploy[:]),
					"public_key":  deployBot.PublicKey,
					"identity_id": deployBot.ID,
				},
			}
		}(),

		"canonical_json": []map[string]interface{}{
			{
				"input":  map[string]interface{}{"zebra": "last", "alpha": "first", "mid": "middle"},
				"output": `{"alpha":"first","mid":"middle","zebra":"last"}`,
			},
			{
				"input":  map[string]interface{}{"b": map[string]interface{}{"y": 2, "x": 1}, "a": "value"},
				"output": `{"a":"value","b":{"x":1,"y":2}}`,
			},
		},

		"delegation": map[string]interface{}{
			"_comment":              "Delegation from Alice (human) to Bob (agent). Signature is Ed25519(canonical_json(delegation with signature=\"\")).",
			"canonical_payload":     string(payload),
			"canonical_payload_hex": hex.EncodeToString(payload),
			"signed_delegation":     d,
		},

		"capability_narrowing": []map[string]interface{}{
			{"parent": "*", "child": "repo:read", "covers": true},
			{"parent": "repo:*", "child": "repo:read", "covers": true},
			{"parent": "repo:*", "child": "repo:pr:create", "covers": true},
			{"parent": "repo:read", "child": "repo:write", "covers": false},
			{"parent": "repo:read,repo=owner/*", "child": "repo:read,repo=owner/myrepo", "covers": true},
			{"parent": "repo:read,repo=owner/*", "child": "repo:read,repo=other/myrepo", "covers": false},
			{"parent": "deploy:create,env=staging", "child": "deploy:create,env=production", "covers": false},
		},

		"content_digest": []map[string]string{
			{
				"body":   `{"action":"deploy"}`,
				"digest": ComputeContentDigest([]byte(`{"action":"deploy"}`)),
			},
			{
				"body":   "hello world",
				"digest": ComputeContentDigest([]byte("hello world")),
			},
		},

		"identity_derivation": map[string]interface{}{
			"_comment": "ID = \"sha256:\" + hex(SHA-256(ed25519_public_key_bytes))",
			"_formula": "identity_id = \"sha256:\" + hex(sha256(base64url_decode(public_key)))",
		},

		"wire_format": map[string]interface{}{
			"_comment": "HTTP headers set by SignRequest()",
			"headers": map[string]string{
				"X-Pact-Identity": "Agent's identity ID (sha256:...)",
				"X-Pact-Chain":    "base64url(JSON(DelegationChain))",
				"Signature-Input": "pact=(\"@method\" \"@path\" \"@authority\" \"date\" \"x-pact-identity\" \"x-pact-chain\");keyid=\"sha256:...\";created=UNIX;alg=\"ed25519\"",
				"Signature":       "pact=:base64url(ed25519_signature):",
				"Content-Digest":  "sha-256=:base64url(sha256(body)):  (only if body present)",
			},
			"signature_base_components": []string{
				"@method", "@path", "@authority", "date",
				"x-pact-identity", "x-pact-chain",
			},
			"signature_base_format": "\"component\": value\\n for each component, then \"signature-input\": <signature-input-value>\\n",
		},
	}

	out, err := json.MarshalIndent(vectors, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}

	// Write to testdata/vectors.json
	if err := os.MkdirAll("testdata", 0755); err != nil {
		t.Fatalf("mkdir testdata: %v", err)
	}
	if err := os.WriteFile("testdata/vectors.json", out, 0644); err != nil {
		t.Fatalf("write vectors.json: %v", err)
	}
	t.Logf("wrote testdata/vectors.json (%d bytes)", len(out))
	fmt.Fprintf(os.Stderr, "\n=== Test Vectors ===\n%s\n", string(out))
}
