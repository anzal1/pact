package pact

import (
	"testing"
)

func TestNewIdentity(t *testing.T) {
	id, err := NewIdentity(EntityHuman, "alice")
	if err != nil {
		t.Fatalf("NewIdentity failed: %v", err)
	}

	if id.Type != EntityHuman {
		t.Errorf("expected type %q, got %q", EntityHuman, id.Type)
	}
	if id.Name != "alice" {
		t.Errorf("expected name 'alice', got %q", id.Name)
	}
	if id.ID == "" {
		t.Error("identity ID is empty")
	}
	if id.PublicKey == "" {
		t.Error("public key is empty")
	}
	if id.PrivateKey == nil {
		t.Error("private key is nil")
	}
	if len(id.ID) < 10 {
		t.Errorf("identity ID too short: %q", id.ID)
	}
	if id.ID[:7] != "sha256:" {
		t.Errorf("identity ID should start with 'sha256:', got %q", id.ID)
	}
}

func TestIdentityUniqueness(t *testing.T) {
	id1, _ := NewIdentity(EntityAgent, "agent1")
	id2, _ := NewIdentity(EntityAgent, "agent2")

	if id1.ID == id2.ID {
		t.Error("two identities have the same ID — collision should be astronomically unlikely")
	}
	if id1.PublicKey == id2.PublicKey {
		t.Error("two identities have the same public key")
	}
}

func TestSignAndVerify(t *testing.T) {
	id, _ := NewIdentity(EntityAgent, "test")
	message := []byte("hello, pact")

	sig, err := id.Sign(message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if !id.Verify(message, sig) {
		t.Error("Verify failed for valid signature")
	}

	// Tamper with message
	if id.Verify([]byte("tampered"), sig) {
		t.Error("Verify should fail for tampered message")
	}

	// Tamper with signature
	tampered := make([]byte, len(sig))
	copy(tampered, sig)
	tampered[0] ^= 0xff
	if id.Verify(message, tampered) {
		t.Error("Verify should fail for tampered signature")
	}
}

func TestSignWithoutPrivateKey(t *testing.T) {
	id, _ := NewIdentity(EntityAgent, "test")
	pubOnly := id.PublicIdentity()

	_, err := pubOnly.Sign([]byte("test"))
	if err == nil {
		t.Error("Sign should fail without private key")
	}
}

func TestPublicIdentity(t *testing.T) {
	id, _ := NewIdentity(EntityHuman, "alice")
	pub := id.PublicIdentity()

	if pub.PrivateKey != nil {
		t.Error("PublicIdentity should have nil private key")
	}
	if pub.ID != id.ID {
		t.Error("PublicIdentity should preserve ID")
	}
	if pub.PublicKey != id.PublicKey {
		t.Error("PublicIdentity should preserve public key")
	}
}

func TestKeyRotation(t *testing.T) {
	id, _ := NewIdentity(EntityAgent, "test-agent")

	newID, rotation, err := id.RotateKey()
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	if newID.ID == id.ID {
		t.Error("rotated identity should have different ID")
	}
	if rotation.PreviousID != id.ID {
		t.Error("rotation should reference old ID")
	}
	if rotation.NewID != newID.ID {
		t.Error("rotation should reference new ID")
	}

	// Verify rotation
	valid, err := VerifyRotation(rotation)
	if err != nil {
		t.Fatalf("VerifyRotation failed: %v", err)
	}
	if !valid {
		t.Error("rotation should be valid")
	}

	// Tamper with rotation
	tampered := *rotation
	tampered.NewID = "sha256:deadbeef"
	valid, err = VerifyRotation(&tampered)
	if err == nil && valid {
		t.Error("tampered rotation should be invalid")
	}
}

func TestCrossIdentityVerification(t *testing.T) {
	alice, _ := NewIdentity(EntityHuman, "alice")
	bob, _ := NewIdentity(EntityAgent, "bob")

	message := []byte("signed by alice")
	sig, _ := alice.Sign(message)

	// Bob should not verify Alice's signature
	if bob.Verify(message, sig) {
		t.Error("Bob should not verify Alice's signature")
	}

	// Alice should verify her own signature
	if !alice.Verify(message, sig) {
		t.Error("Alice should verify her own signature")
	}
}
