package pact

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// KeyStore is an interface for storing and retrieving Pact identities.
// Implementations handle the operational reality of key management:
// where keys live, how they're protected, and how they survive restarts.
type KeyStore interface {
	// Store saves an identity. The private key MUST be protected.
	Store(identity *Identity) error

	// Load retrieves the identity. Returns the full identity with private key.
	Load(name string) (*Identity, error)

	// LoadPublic retrieves only the public identity (safe to share).
	LoadPublic(name string) (*Identity, error)

	// List returns the names of all stored identities.
	List() ([]string, error)

	// Delete removes an identity.
	Delete(name string) error
}

// identityFile is the serialized form of an identity on disk.
type identityFile struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
}

// FileKeyStore stores identities as JSON files in a directory.
//
// Directory layout:
//
//	~/.pact/
//	├── keys/
//	│   ├── alice.json          (private identity — mode 0600)
//	│   ├── alice.pub.json      (public identity — mode 0644)
//	│   ├── my-agent.json
//	│   └── my-agent.pub.json
//
// This is the simplest key management option. For production agents,
// consider integrating with system keyrings (macOS Keychain, Linux Secret Service)
// or cloud KMS services.
type FileKeyStore struct {
	dir string
	mu  sync.RWMutex
}

// NewFileKeyStore creates a new file-based key store at the given directory.
// The directory is created with mode 0700 if it doesn't exist.
func NewFileKeyStore(dir string) (*FileKeyStore, error) {
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return nil, fmt.Errorf("pact: failed to create key store directory: %w", err)
	}
	return &FileKeyStore{dir: keysDir}, nil
}

// DefaultKeyStore creates a key store in the default location (~/.pact/keys/).
func DefaultKeyStore() (*FileKeyStore, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("pact: cannot determine home directory: %w", err)
	}
	return NewFileKeyStore(filepath.Join(home, ".pact"))
}

// Store saves an identity to disk. The private key file is mode 0600.
func (fs *FileKeyStore) Store(identity *Identity) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	name := identity.Name
	if name == "" {
		name = "default"
	}

	// Save private identity
	privFile := identityFile{
		Type:      string(identity.Type),
		ID:        identity.ID,
		PublicKey: identity.PublicKey,
		Name:      identity.Name,
		CreatedAt: identity.CreatedAt.Format(time.RFC3339),
	}
	if identity.PrivateKey != nil {
		privFile.PrivateKey = encodeBase64URL(identity.PrivateKey)
	}

	privData, err := json.MarshalIndent(privFile, "", "  ")
	if err != nil {
		return fmt.Errorf("pact: failed to serialize identity: %w", err)
	}

	privPath := filepath.Join(fs.dir, name+".json")
	if err := os.WriteFile(privPath, privData, 0600); err != nil {
		return fmt.Errorf("pact: failed to write identity: %w", err)
	}

	// Save public identity (safe to share)
	pubFile := identityFile{
		Type:      string(identity.Type),
		ID:        identity.ID,
		PublicKey: identity.PublicKey,
		Name:      identity.Name,
		CreatedAt: identity.CreatedAt.Format(time.RFC3339),
	}

	pubData, err := json.MarshalIndent(pubFile, "", "  ")
	if err != nil {
		return fmt.Errorf("pact: failed to serialize public identity: %w", err)
	}

	pubPath := filepath.Join(fs.dir, name+".pub.json")
	if err := os.WriteFile(pubPath, pubData, 0644); err != nil {
		return fmt.Errorf("pact: failed to write public identity: %w", err)
	}

	return nil
}

// Load retrieves the full identity (with private key) from disk.
func (fs *FileKeyStore) Load(name string) (*Identity, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if name == "" {
		name = "default"
	}

	privPath := filepath.Join(fs.dir, name+".json")
	data, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("pact: identity %q not found: %w", name, err)
	}

	var stored identityFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("pact: invalid identity file: %w", err)
	}

	identity := &Identity{
		Type:      EntityType(stored.Type),
		ID:        stored.ID,
		PublicKey: stored.PublicKey,
		Name:      stored.Name,
	}

	if stored.CreatedAt != "" {
		identity.CreatedAt, _ = time.Parse(time.RFC3339, stored.CreatedAt)
	}

	if stored.PrivateKey != "" {
		privKey, err := decodeBase64URL(stored.PrivateKey)
		if err != nil {
			return nil, fmt.Errorf("pact: invalid private key encoding: %w", err)
		}
		identity.PrivateKey = ed25519.PrivateKey(privKey)
	}

	return identity, nil
}

// LoadPublic retrieves only the public identity (no private key).
func (fs *FileKeyStore) LoadPublic(name string) (*Identity, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	if name == "" {
		name = "default"
	}

	pubPath := filepath.Join(fs.dir, name+".pub.json")
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("pact: public identity %q not found: %w", name, err)
	}

	var stored identityFile
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("pact: invalid public identity file: %w", err)
	}

	return &Identity{
		Type:      EntityType(stored.Type),
		ID:        stored.ID,
		PublicKey: stored.PublicKey,
		Name:      stored.Name,
	}, nil
}

// List returns the names of all stored identities.
func (fs *FileKeyStore) List() ([]string, error) {
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	entries, err := os.ReadDir(fs.dir)
	if err != nil {
		return nil, fmt.Errorf("pact: failed to list key store: %w", err)
	}

	seen := make(map[string]bool)
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		// Strip both .json and .pub.json suffixes
		if ext := filepath.Ext(name); ext == ".json" {
			name = name[:len(name)-len(ext)]
			if filepath.Ext(name) == ".pub" {
				name = name[:len(name)-4]
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}

	return names, nil
}

// Delete removes an identity (both private and public files).
func (fs *FileKeyStore) Delete(name string) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if name == "" {
		name = "default"
	}

	privPath := filepath.Join(fs.dir, name+".json")
	pubPath := filepath.Join(fs.dir, name+".pub.json")

	// Remove private key first (more sensitive)
	os.Remove(privPath)
	os.Remove(pubPath)

	return nil
}

// MemoryKeyStore stores identities in memory. Useful for testing
// and for short-lived agent processes that don't need persistence.
type MemoryKeyStore struct {
	mu         sync.RWMutex
	identities map[string]*Identity
}

// NewMemoryKeyStore creates a new in-memory key store.
func NewMemoryKeyStore() *MemoryKeyStore {
	return &MemoryKeyStore{
		identities: make(map[string]*Identity),
	}
}

// Store saves an identity in memory.
func (ms *MemoryKeyStore) Store(identity *Identity) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	name := identity.Name
	if name == "" {
		name = "default"
	}
	ms.identities[name] = identity
	return nil
}

// Load retrieves an identity from memory.
func (ms *MemoryKeyStore) Load(name string) (*Identity, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	if name == "" {
		name = "default"
	}
	id, ok := ms.identities[name]
	if !ok {
		return nil, fmt.Errorf("pact: identity %q not found in memory store", name)
	}
	return id, nil
}

// LoadPublic retrieves the public identity from memory.
func (ms *MemoryKeyStore) LoadPublic(name string) (*Identity, error) {
	id, err := ms.Load(name)
	if err != nil {
		return nil, err
	}
	return id.PublicIdentity(), nil
}

// List returns all identity names in the store.
func (ms *MemoryKeyStore) List() ([]string, error) {
	ms.mu.RLock()
	defer ms.mu.RUnlock()

	names := make([]string, 0, len(ms.identities))
	for name := range ms.identities {
		names = append(names, name)
	}
	return names, nil
}

// Delete removes an identity from memory.
func (ms *MemoryKeyStore) Delete(name string) error {
	ms.mu.Lock()
	defer ms.mu.Unlock()

	if name == "" {
		name = "default"
	}
	delete(ms.identities, name)
	return nil
}
