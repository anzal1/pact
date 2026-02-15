package pact

import (
	"crypto/rand"
	"fmt"
	"time"
)

// Delegation represents a signed authorization from one entity to another.
// It is the core primitive of Pact — the cryptographic pact between delegator and delegate.
//
// A delegation says: "I (from) authorize you (to) to do these things (capabilities)
// within these bounds (constraints), and I sign this with my private key."
type Delegation struct {
	// Type is always "delegation".
	Type string `json:"type"`

	// Version is the protocol version.
	Version string `json:"version"`

	// ID is a unique identifier for this delegation.
	ID string `json:"id"`

	// From is the delegator's public identity.
	From DelegationEntity `json:"from"`

	// To is the delegate's public identity.
	To DelegationEntity `json:"to"`

	// Capabilities are the permissions being granted.
	Capabilities []string `json:"capabilities"`

	// Constraints bound the delegation.
	Constraints DelegationConstraints `json:"constraints"`

	// IssuedAt is when the delegation was created.
	IssuedAt string `json:"issued_at"`

	// Signature is the delegator's Ed25519 signature over the canonical form
	// of this delegation (with signature field empty).
	Signature string `json:"signature"`
}

// DelegationEntity is the public identity info embedded in a delegation.
type DelegationEntity struct {
	Type      EntityType `json:"type"`
	ID        string     `json:"id"`
	PublicKey string     `json:"public_key"`
	Name      string     `json:"name,omitempty"`
}

// DelegationConstraints define the bounds of a delegation.
type DelegationConstraints struct {
	// Expires is when this delegation becomes invalid (RFC 3339).
	Expires string `json:"expires"`

	// MaxChainDepth limits how many times this delegation can be sub-delegated.
	// 1 = no sub-delegation allowed. 2 = one level of sub-delegation. etc.
	MaxChainDepth int `json:"max_chain_depth"`

	// NotBefore is the earliest time this delegation is valid (optional, RFC 3339).
	NotBefore string `json:"not_before,omitempty"`
}

// DelegationChain is an ordered list of delegations forming a trust path
// from a root authority (typically human) to the acting agent.
//
// Chain order: [root delegation, sub-delegation, sub-sub-delegation, ...]
// The first delegation's "from" is the root authority.
// The last delegation's "to" is the acting agent.
type DelegationChain []Delegation

// DelegationRequest specifies the parameters for creating a new delegation.
type DelegationRequest struct {
	// From is the delegator (must have a private key for signing).
	From *Identity

	// To is the delegate (only public key needed).
	To *Identity

	// Capabilities are the permissions being granted.
	Capabilities []string

	// TTL is how long the delegation is valid.
	TTL time.Duration

	// MaxChainDepth limits sub-delegation depth. 0 means use default (1 = no sub-delegation).
	MaxChainDepth int

	// NotBefore is the earliest validity time. Zero means now.
	NotBefore time.Time
}

// NewDelegation creates and signs a new delegation.
//
// The delegator (from) signs the delegation with their private key,
// cryptographically binding themselves to the authorization.
func NewDelegation(req DelegationRequest) (*Delegation, error) {
	if req.From == nil {
		return nil, fmt.Errorf("pact: delegation requires a 'from' identity")
	}
	if req.To == nil {
		return nil, fmt.Errorf("pact: delegation requires a 'to' identity")
	}
	if req.From.PrivateKey == nil {
		return nil, fmt.Errorf("pact: delegator must have a private key to sign")
	}
	if len(req.Capabilities) == 0 {
		return nil, fmt.Errorf("pact: delegation requires at least one capability")
	}
	if req.TTL <= 0 {
		return nil, fmt.Errorf("pact: delegation requires a positive TTL")
	}

	maxDepth := req.MaxChainDepth
	if maxDepth <= 0 {
		maxDepth = 1
	}

	now := time.Now().UTC()
	notBefore := req.NotBefore
	if notBefore.IsZero() {
		notBefore = now
	}

	id, err := generateDelegationID()
	if err != nil {
		return nil, err
	}

	d := &Delegation{
		Type:    "delegation",
		Version: "1.0",
		ID:      id,
		From: DelegationEntity{
			Type:      req.From.Type,
			ID:        req.From.ID,
			PublicKey: req.From.PublicKey,
			Name:      req.From.Name,
		},
		To: DelegationEntity{
			Type:      req.To.Type,
			ID:        req.To.ID,
			PublicKey: req.To.PublicKey,
			Name:      req.To.Name,
		},
		Capabilities: req.Capabilities,
		Constraints: DelegationConstraints{
			Expires:       now.Add(req.TTL).Format(time.RFC3339),
			MaxChainDepth: maxDepth,
			NotBefore:     notBefore.Format(time.RFC3339),
		},
		IssuedAt:  now.Format(time.RFC3339),
		Signature: "",
	}

	// Sign the delegation
	if err := d.sign(req.From); err != nil {
		return nil, err
	}

	return d, nil
}

// SubDelegate creates a new delegation from this chain's terminal agent to a new agent.
// The new delegation's capabilities must be a subset of the parent's.
// The chain depth must not exceed the root's max_chain_depth.
func (chain DelegationChain) SubDelegate(agent *Identity, to *Identity, capabilities []string, ttl time.Duration) (*Delegation, DelegationChain, error) {
	if len(chain) == 0 {
		return nil, nil, fmt.Errorf("pact: cannot sub-delegate from empty chain")
	}

	last := chain[len(chain)-1]

	// Verify the agent is the terminal entity in the chain
	if agent.ID != last.To.ID {
		return nil, nil, fmt.Errorf("pact: agent identity %s does not match chain terminal %s", agent.ID, last.To.ID)
	}

	// Check chain depth
	root := chain[0]
	if len(chain) >= root.Constraints.MaxChainDepth {
		return nil, nil, fmt.Errorf("pact: sub-delegation would exceed max chain depth %d", root.Constraints.MaxChainDepth)
	}

	// Verify narrowing: new capabilities must be covered by parent capabilities
	parentCaps, err := ParseCapabilitySet(last.Capabilities)
	if err != nil {
		return nil, nil, fmt.Errorf("pact: invalid parent capabilities: %w", err)
	}
	childCaps, err := ParseCapabilitySet(capabilities)
	if err != nil {
		return nil, nil, fmt.Errorf("pact: invalid child capabilities: %w", err)
	}
	if !parentCaps.Covers(childCaps) {
		return nil, nil, fmt.Errorf("pact: sub-delegation capabilities exceed parent scope (narrowing-only violation)")
	}

	// TTL cannot exceed parent's remaining TTL
	parentExpires, err := time.Parse(time.RFC3339, last.Constraints.Expires)
	if err != nil {
		return nil, nil, fmt.Errorf("pact: invalid parent expiry: %w", err)
	}
	remaining := time.Until(parentExpires)
	if ttl > remaining {
		ttl = remaining
	}

	// Max chain depth for sub-delegation is parent's minus current depth
	newMaxDepth := root.Constraints.MaxChainDepth - len(chain)
	if newMaxDepth < 1 {
		newMaxDepth = 1
	}

	// Create the sub-delegation
	d, err := NewDelegation(DelegationRequest{
		From:          agent,
		To:            to,
		Capabilities:  capabilities,
		TTL:           ttl,
		MaxChainDepth: newMaxDepth,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("pact: sub-delegation failed: %w", err)
	}

	// Build the extended chain
	newChain := make(DelegationChain, len(chain)+1)
	copy(newChain, chain)
	newChain[len(chain)] = *d

	return d, newChain, nil
}

// TerminalEntity returns the identity ID of the last delegate in the chain
// (the entity currently authorized to act).
func (chain DelegationChain) TerminalEntity() string {
	if len(chain) == 0 {
		return ""
	}
	return chain[len(chain)-1].To.ID
}

// RootAuthority returns the identity ID of the root delegator
// (typically the human who started the chain).
func (chain DelegationChain) RootAuthority() string {
	if len(chain) == 0 {
		return ""
	}
	return chain[0].From.ID
}

// sign computes and sets the Ed25519 signature over the canonical form of the delegation.
func (d *Delegation) sign(signer *Identity) error {
	// Temporarily clear signature for signing
	d.Signature = ""

	payload, err := canonicalJSON(d)
	if err != nil {
		return fmt.Errorf("pact: failed to canonicalize delegation: %w", err)
	}

	sig, err := signer.Sign(payload)
	if err != nil {
		return err
	}

	d.Signature = encodeBase64URL(sig)
	return nil
}

// signingPayload returns the canonical bytes that were signed.
func (d *Delegation) signingPayload() ([]byte, error) {
	dCopy := *d
	dCopy.Signature = ""
	return canonicalJSON(&dCopy)
}

// generateDelegationID creates a random delegation ID.
func generateDelegationID() (string, error) {
	b := make([]byte, 16)
	_, err := randRead(b)
	if err != nil {
		return "", fmt.Errorf("pact: failed to generate delegation ID: %w", err)
	}
	return fmt.Sprintf("d-%x", b), nil
}

// randRead is a variable for testing — reads random bytes.
var randRead = randReadDefault

func randReadDefault(b []byte) (int, error) {
	return randReaderRead(b)
}

// We use a separate function to avoid import cycle issues with testing
func randReaderRead(b []byte) (int, error) {
	return _randReader.Read(b)
}

// _randReader uses crypto/rand
var _randReader = cryptoRandReader{}

type cryptoRandReader struct{}

func (cryptoRandReader) Read(b []byte) (int, error) {
	return randReadFromCryptoRand(b)
}

func randReadFromCryptoRand(b []byte) (int, error) {
	// imported at top: "crypto/rand"
	return rand.Read(b)
}
