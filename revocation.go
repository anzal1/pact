package pact

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Revocation represents a signed statement that a delegation has been revoked.
// The revoker must be the "from" entity of the delegation being revoked.
type Revocation struct {
	// Type is always "revocation".
	Type string `json:"type"`

	// DelegationID is the ID of the delegation being revoked.
	DelegationID string `json:"delegation_id"`

	// RevokedBy is the identity of the entity revoking (must be the delegator).
	RevokedBy string `json:"revoked_by"`

	// RevokedAt is when the revocation was issued.
	RevokedAt string `json:"revoked_at"`

	// Reason is an optional human-readable reason for revocation.
	Reason string `json:"reason,omitempty"`

	// Signature is the revoker's Ed25519 signature over the canonical revocation.
	Signature string `json:"signature"`
}

// NewRevocation creates a signed revocation for a delegation.
// The revoker must be the "from" entity of the delegation and must hold the private key.
func NewRevocation(delegation *Delegation, revoker *Identity, reason string) (*Revocation, error) {
	if revoker.PrivateKey == nil {
		return nil, fmt.Errorf("pact: revoker must have a private key")
	}

	// Verify the revoker is the delegator
	if revoker.ID != delegation.From.ID {
		return nil, fmt.Errorf("pact: only the delegator (%s) can revoke, not %s", delegation.From.ID, revoker.ID)
	}

	rev := &Revocation{
		Type:         "revocation",
		DelegationID: delegation.ID,
		RevokedBy:    revoker.ID,
		RevokedAt:    time.Now().UTC().Format(time.RFC3339),
		Reason:       reason,
		Signature:    "",
	}

	// Sign the revocation
	payload, err := canonicalJSON(rev)
	if err != nil {
		return nil, fmt.Errorf("pact: failed to canonicalize revocation: %w", err)
	}

	sig, err := revoker.Sign(payload)
	if err != nil {
		return nil, err
	}
	rev.Signature = encodeBase64URL(sig)

	return rev, nil
}

// VerifyRevocation checks that a revocation is properly signed by the claimed revoker.
// The caller must provide the revoker's public key (from the delegation's "from" field).
func VerifyRevocation(rev *Revocation, revokerPublicKey string) (bool, error) {
	pubKeyBytes, err := decodeBase64URL(revokerPublicKey)
	if err != nil {
		return false, fmt.Errorf("pact: invalid revoker public key: %w", err)
	}

	// Verify the revoker ID matches the key
	expectedID := deriveID(pubKeyBytes)
	if expectedID != rev.RevokedBy {
		return false, fmt.Errorf("pact: revoker ID does not match public key")
	}

	// Decode signature
	sigBytes, err := decodeBase64URL(rev.Signature)
	if err != nil {
		return false, fmt.Errorf("pact: invalid revocation signature: %w", err)
	}

	// Reconstruct the signed payload
	revCopy := *rev
	revCopy.Signature = ""
	payload, err := canonicalJSON(&revCopy)
	if err != nil {
		return false, fmt.Errorf("pact: failed to canonicalize revocation for verification: %w", err)
	}

	return ed25519Verify(pubKeyBytes, payload, sigBytes), nil
}

// ed25519Verify wraps the verify call (imported via identity.go's package).
func ed25519Verify(pubKey, message, sig []byte) bool {
	id := IdentityFromPublicKey(EntityAgent, pubKey)
	return id.Verify(message, sig)
}

// RevocationStore is an interface for storing and checking revocations.
// Providers implement this to check incoming requests against known revocations.
type RevocationStore interface {
	// Add stores a verified revocation.
	Add(rev *Revocation) error

	// IsRevoked checks if a delegation ID has been revoked.
	IsRevoked(delegationID string) bool

	// List returns all known revocations.
	List() []*Revocation
}

// MemoryRevocationStore is a simple in-memory revocation store.
// Suitable for single-process providers. For distributed systems,
// use a shared store (Redis, database, etc.).
type MemoryRevocationStore struct {
	mu          sync.RWMutex
	revocations map[string]*Revocation
}

// NewMemoryRevocationStore creates a new in-memory revocation store.
func NewMemoryRevocationStore() *MemoryRevocationStore {
	return &MemoryRevocationStore{
		revocations: make(map[string]*Revocation),
	}
}

// Add stores a revocation.
func (s *MemoryRevocationStore) Add(rev *Revocation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revocations[rev.DelegationID] = rev
	return nil
}

// IsRevoked checks if a delegation ID has been revoked.
func (s *MemoryRevocationStore) IsRevoked(delegationID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, exists := s.revocations[delegationID]
	return exists
}

// List returns all known revocations.
func (s *MemoryRevocationStore) List() []*Revocation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]*Revocation, 0, len(s.revocations))
	for _, rev := range s.revocations {
		result = append(result, rev)
	}
	return result
}

// SerializeRevocation serializes a revocation to JSON for publishing.
func SerializeRevocation(rev *Revocation) ([]byte, error) {
	return json.MarshalIndent(rev, "", "  ")
}
