package pact

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileKeyStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	// Generate and store an identity
	identity, err := NewIdentity(EntityHuman, "alice")
	if err != nil {
		t.Fatalf("failed to create identity: %v", err)
	}

	if err := store.Store(identity); err != nil {
		t.Fatalf("failed to store identity: %v", err)
	}

	// Load it back
	loaded, err := store.Load("alice")
	if err != nil {
		t.Fatalf("failed to load identity: %v", err)
	}

	if loaded.ID != identity.ID {
		t.Fatalf("ID mismatch: got %s, want %s", loaded.ID, identity.ID)
	}
	if loaded.PublicKey != identity.PublicKey {
		t.Fatalf("public key mismatch")
	}
	if loaded.PrivateKey == nil {
		t.Fatal("private key should be present")
	}
	if loaded.Name != identity.Name {
		t.Fatalf("name mismatch: got %s, want %s", loaded.Name, identity.Name)
	}

	// The loaded identity should be able to sign
	msg := []byte("test message")
	sig, err := loaded.Sign(msg)
	if err != nil {
		t.Fatalf("loaded identity cannot sign: %v", err)
	}
	if !identity.Verify(msg, sig) {
		t.Fatal("original identity cannot verify signature from loaded identity")
	}
}

func TestFileKeyStorePublicOnly(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	identity, _ := NewIdentity(EntityAgent, "my-agent")
	store.Store(identity)

	pub, err := store.LoadPublic("my-agent")
	if err != nil {
		t.Fatalf("failed to load public identity: %v", err)
	}

	if pub.PrivateKey != nil {
		t.Fatal("public identity should not have private key")
	}
	if pub.ID != identity.ID {
		t.Fatalf("ID mismatch")
	}
	if pub.PublicKey != identity.PublicKey {
		t.Fatal("public key mismatch")
	}
}

func TestFileKeyStoreList(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	alice, _ := NewIdentity(EntityHuman, "alice")
	bob, _ := NewIdentity(EntityHuman, "bob")
	agent, _ := NewIdentity(EntityAgent, "my-agent")

	store.Store(alice)
	store.Store(bob)
	store.Store(agent)

	names, err := store.List()
	if err != nil {
		t.Fatalf("failed to list: %v", err)
	}

	if len(names) != 3 {
		t.Fatalf("expected 3 identities, got %d: %v", len(names), names)
	}

	nameSet := make(map[string]bool)
	for _, n := range names {
		nameSet[n] = true
	}
	for _, expected := range []string{"alice", "bob", "my-agent"} {
		if !nameSet[expected] {
			t.Fatalf("expected %q in list, got %v", expected, names)
		}
	}
}

func TestFileKeyStoreDelete(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	identity, _ := NewIdentity(EntityHuman, "alice")
	store.Store(identity)

	// Verify it exists
	_, err = store.Load("alice")
	if err != nil {
		t.Fatalf("identity should exist: %v", err)
	}

	// Delete it
	store.Delete("alice")

	// Verify it's gone
	_, err = store.Load("alice")
	if err == nil {
		t.Fatal("identity should be deleted")
	}
}

func TestFileKeyStorePermissions(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	identity, _ := NewIdentity(EntityHuman, "alice")
	store.Store(identity)

	// Check private key file permissions (should be 0600)
	privPath := filepath.Join(dir, "keys", "alice.json")
	info, err := os.Stat(privPath)
	if err != nil {
		t.Fatalf("private key file not found: %v", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("private key file should be 0600, got %o", perm)
	}

	// Check public key file permissions (should be 0644)
	pubPath := filepath.Join(dir, "keys", "alice.pub.json")
	info, err = os.Stat(pubPath)
	if err != nil {
		t.Fatalf("public key file not found: %v", err)
	}
	perm = info.Mode().Perm()
	if perm != 0644 {
		t.Fatalf("public key file should be 0644, got %o", perm)
	}
}

func TestMemoryKeyStoreRoundTrip(t *testing.T) {
	store := NewMemoryKeyStore()

	identity, _ := NewIdentity(EntityAgent, "my-agent")
	if err := store.Store(identity); err != nil {
		t.Fatalf("failed to store: %v", err)
	}

	loaded, err := store.Load("my-agent")
	if err != nil {
		t.Fatalf("failed to load: %v", err)
	}

	if loaded.ID != identity.ID {
		t.Fatalf("ID mismatch")
	}
}

func TestMemoryKeyStorePublicStripsPrivateKey(t *testing.T) {
	store := NewMemoryKeyStore()
	identity, _ := NewIdentity(EntityAgent, "my-agent")
	store.Store(identity)

	pub, err := store.LoadPublic("my-agent")
	if err != nil {
		t.Fatalf("failed to load public: %v", err)
	}
	if pub.PrivateKey != nil {
		t.Fatal("public identity should not have private key")
	}
}

func TestKeyStoreInterfaceCompliance(t *testing.T) {
	// Compile-time check that both stores implement KeyStore
	var _ KeyStore = &FileKeyStore{}
	var _ KeyStore = &MemoryKeyStore{}
}
