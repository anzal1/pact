package pact

import (
	"testing"
	"time"
)

func TestRevocation(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "test-agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"github:*"},
		TTL:          1 * time.Hour,
	})

	// Revoke the delegation
	rev, err := NewRevocation(d, alice, "agent compromised")
	if err != nil {
		t.Fatalf("NewRevocation failed: %v", err)
	}

	if rev.DelegationID != d.ID {
		t.Errorf("revocation should reference delegation ID")
	}
	if rev.RevokedBy != alice.ID {
		t.Errorf("revocation should reference revoker ID")
	}
	if rev.Reason != "agent compromised" {
		t.Errorf("reason: got %q", rev.Reason)
	}

	// Verify the revocation
	valid, err := VerifyRevocation(rev, alice.PublicKey)
	if err != nil {
		t.Fatalf("VerifyRevocation failed: %v", err)
	}
	if !valid {
		t.Error("revocation should be valid")
	}
}

func TestRevocationByNonDelegator(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	bob, _ := NewIdentity(EntityHuman, "bob")
	agent, _ := NewIdentity(EntityAgent, "agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"github:*"},
		TTL:          1 * time.Hour,
	})

	// Bob tries to revoke Alice's delegation — should fail
	_, err := NewRevocation(d, bob, "trying to be sneaky")
	if err == nil {
		t.Error("non-delegator should not be able to revoke")
	}
}

func TestRevocationStore(t *testing.T) {
	store := NewMemoryRevocationStore()

	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})

	// Not revoked initially
	if store.IsRevoked(d.ID) {
		t.Error("delegation should not be revoked initially")
	}

	// Revoke it
	rev, _ := NewRevocation(d, alice, "revoked")
	store.Add(rev)

	// Now it's revoked
	if !store.IsRevoked(d.ID) {
		t.Error("delegation should be revoked after adding revocation")
	}

	// Check list
	revocations := store.List()
	if len(revocations) != 1 {
		t.Errorf("expected 1 revocation, got %d", len(revocations))
	}
}

func TestVerificationWithRevocationChecker(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	agent, _ := NewIdentity(EntityAgent, "agent")

	d, _ := NewDelegation(DelegationRequest{
		From:         alice,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})

	chain := DelegationChain{*d}

	// Without revocation — valid
	result := VerifyChain(chain, DefaultVerifyOptions())
	if !result.Valid {
		t.Fatalf("should be valid without revocation: %s", result.Error)
	}

	// With revocation checker — invalid
	store := NewMemoryRevocationStore()
	rev, _ := NewRevocation(d, alice, "compromised")
	store.Add(rev)

	opts := DefaultVerifyOptions()
	opts.RevocationChecker = store.IsRevoked

	result = VerifyChain(chain, opts)
	if result.Valid {
		t.Error("should be invalid when delegation is revoked")
	}
}
