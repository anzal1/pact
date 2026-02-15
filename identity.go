package pact

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"
)

// Identity represents a Pact identity — a self-sovereign Ed25519 keypair.
// Identity = SHA-256(public_key), globally unique without any registry.
type Identity struct {
	// Type distinguishes humans from agents in delegation chains.
	Type EntityType `json:"type"`

	// ID is the SHA-256 hash of the public key, hex-encoded with "sha256:" prefix.
	ID string `json:"id"`

	// PublicKey is the Ed25519 public key, base64url-encoded (no padding).
	PublicKey string `json:"public_key"`

	// PrivateKey is the Ed25519 private key. NEVER serialized to JSON.
	// Only present when this identity was locally generated.
	PrivateKey ed25519.PrivateKey `json:"-"`

	// Name is an optional human-readable label (not used in crypto operations).
	Name string `json:"name,omitempty"`

	// CreatedAt is when this identity was generated.
	CreatedAt time.Time `json:"created_at"`
}

// EntityType distinguishes between humans and agents in the protocol.
type EntityType string

const (
	EntityHuman EntityType = "human"
	EntityAgent EntityType = "agent"
)

// NewIdentity generates a new Ed25519 identity.
// The identity is self-sovereign — no registration, no central authority.
func NewIdentity(entityType EntityType, name string) (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pact: failed to generate Ed25519 keypair: %w", err)
	}

	id := deriveID(pub)
	pubEncoded := encodeBase64URL(pub)

	return &Identity{
		Type:       entityType,
		ID:         id,
		PublicKey:  pubEncoded,
		PrivateKey: priv,
		Name:       name,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// IdentityFromPublicKey creates an Identity from an existing public key.
// Used when you have a peer's public key but not their private key.
func IdentityFromPublicKey(entityType EntityType, pubKey ed25519.PublicKey) *Identity {
	return &Identity{
		Type:      entityType,
		ID:        deriveID(pubKey),
		PublicKey: encodeBase64URL(pubKey),
	}
}

// Sign signs a message with this identity's private key.
// Returns an error if this identity has no private key (e.g., a remote peer).
func (i *Identity) Sign(message []byte) ([]byte, error) {
	if i.PrivateKey == nil {
		return nil, fmt.Errorf("pact: cannot sign — no private key for identity %s", i.ID)
	}
	return ed25519.Sign(i.PrivateKey, message), nil
}

// Verify checks that a signature was made by this identity's public key.
func (i *Identity) Verify(message, signature []byte) bool {
	pubKey, err := i.Ed25519PublicKey()
	if err != nil {
		return false
	}
	return ed25519.Verify(pubKey, message, signature)
}

// Ed25519PublicKey decodes and returns the raw Ed25519 public key.
func (i *Identity) Ed25519PublicKey() (ed25519.PublicKey, error) {
	return decodeBase64URL(i.PublicKey)
}

// PublicIdentity returns a copy of this identity with the private key stripped.
// Safe to serialize, share, embed in delegation chains.
func (i *Identity) PublicIdentity() *Identity {
	return &Identity{
		Type:      i.Type,
		ID:        i.ID,
		PublicKey: i.PublicKey,
		Name:      i.Name,
		CreatedAt: i.CreatedAt,
	}
}

// KeyRotation represents a signed key rotation — old key endorses new key.
// This provides identity continuity without any registry.
type KeyRotation struct {
	// PreviousID is the identity being rotated from.
	PreviousID string `json:"previous_id"`

	// PreviousPublicKey is the old public key (base64url).
	PreviousPublicKey string `json:"previous_public_key"`

	// NewID is the identity being rotated to.
	NewID string `json:"new_id"`

	// NewPublicKey is the new public key (base64url).
	NewPublicKey string `json:"new_public_key"`

	// RotatedAt is when the rotation occurred.
	RotatedAt time.Time `json:"rotated_at"`

	// Signature is the old key's signature over the rotation payload.
	Signature string `json:"signature"`
}

// RotateKey creates a new identity and signs the rotation with the old key.
// The old key vouches for the new key, providing identity continuity.
func (i *Identity) RotateKey() (*Identity, *KeyRotation, error) {
	if i.PrivateKey == nil {
		return nil, nil, fmt.Errorf("pact: cannot rotate — no private key for identity %s", i.ID)
	}

	// Generate new keypair
	newIdentity, err := NewIdentity(i.Type, i.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("pact: key rotation failed: %w", err)
	}

	rotation := &KeyRotation{
		PreviousID:        i.ID,
		PreviousPublicKey: i.PublicKey,
		NewID:             newIdentity.ID,
		NewPublicKey:      newIdentity.PublicKey,
		RotatedAt:         time.Now().UTC(),
	}

	// Sign the rotation with the old key
	payload, err := canonicalJSON(rotation)
	if err != nil {
		return nil, nil, fmt.Errorf("pact: failed to serialize rotation: %w", err)
	}

	sig, err := i.Sign(payload)
	if err != nil {
		return nil, nil, err
	}
	rotation.Signature = encodeBase64URL(sig)

	return newIdentity, rotation, nil
}

// VerifyRotation checks that a key rotation was properly signed by the old key.
func VerifyRotation(rotation *KeyRotation) (bool, error) {
	// Decode the previous public key
	prevPub, err := decodeBase64URL(rotation.PreviousPublicKey)
	if err != nil {
		return false, fmt.Errorf("pact: invalid previous public key: %w", err)
	}

	// Verify the ID matches the key
	expectedID := deriveID(prevPub)
	if expectedID != rotation.PreviousID {
		return false, fmt.Errorf("pact: previous ID does not match previous public key")
	}

	// Verify new ID matches new key
	newPub, err := decodeBase64URL(rotation.NewPublicKey)
	if err != nil {
		return false, fmt.Errorf("pact: invalid new public key: %w", err)
	}
	expectedNewID := deriveID(newPub)
	if expectedNewID != rotation.NewID {
		return false, fmt.Errorf("pact: new ID does not match new public key")
	}

	// Decode signature
	sig, err := decodeBase64URL(rotation.Signature)
	if err != nil {
		return false, fmt.Errorf("pact: invalid rotation signature: %w", err)
	}

	// Reconstruct the payload that was signed (without the signature field)
	rotationCopy := *rotation
	rotationCopy.Signature = ""
	payload, err := canonicalJSON(&rotationCopy)
	if err != nil {
		return false, fmt.Errorf("pact: failed to serialize rotation for verification: %w", err)
	}

	return ed25519.Verify(prevPub, payload, sig), nil
}

// ExportPublicKey exports the public identity as JSON (safe to share).
func (i *Identity) ExportPublicKey() ([]byte, error) {
	return json.Marshal(i.PublicIdentity())
}

// deriveID computes the identity from a public key: "sha256:" + hex(SHA-256(pubkey))
func deriveID(pub ed25519.PublicKey) string {
	hash := sha256.Sum256(pub)
	return fmt.Sprintf("sha256:%x", hash)
}
