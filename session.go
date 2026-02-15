package pact

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// Session represents an active agent session with hierarchical identity.
// It solves the agent ephemerality problem: agents are short-lived processes,
// but their identity must persist across sessions.
//
// Identity hierarchy:
//
//	Human (long-lived, user-controlled)
//	  └── Agent Root (persistent, stored in KeyStore)
//	        └── Session (ephemeral, in-memory, auto-delegated)
//	              └── Sub-agent (ephemeral, further scoped)
//
// Each arrow is a Pact delegation. The full chain is offline-verifiable.
// The session key lives only in memory and dies with the process.
// The root key persists in the KeyStore and provides identity continuity.
//
// This is analogous to TLS certificate hierarchy: a root CA in an HSM
// issues short-lived leaf certificates. The root never touches the wire.
type Session struct {
	// root is the persistent agent identity (loaded from KeyStore or provided directly).
	root *Identity

	// session is the ephemeral session identity (generated fresh each time).
	session *Identity

	// parentChain is the delegation chain from human → root.
	// Provided by the delegator when establishing the agent.
	parentChain DelegationChain

	// rootToSession is the auto-generated delegation from root → session.
	rootToSession *Delegation

	// fullChain is the complete chain: parentChain + rootToSession delegation.
	// This is what gets attached to every request.
	fullChain DelegationChain

	// capabilities are the effective capabilities of this session.
	capabilities []string

	// config holds the session configuration.
	config SessionConfig

	// createdAt is when the session was established.
	createdAt time.Time

	// expiresAt is when the session key expires.
	expiresAt time.Time

	// mu protects session state.
	mu sync.RWMutex

	// closed is true after Close() has been called.
	closed bool
}

// SessionConfig configures session behavior.
type SessionConfig struct {
	// TTL is how long the session identity is valid. Default: 1 hour.
	// The session key auto-delegates from the root with this TTL.
	TTL time.Duration

	// Capabilities to grant the session. Must be a subset of the parent chain's
	// terminal capabilities. If empty, inherits all capabilities from the parent chain.
	Capabilities []string

	// MaxChainDepth controls how many sub-delegations the session can make.
	// Default: 2 (session can delegate to one sub-agent).
	MaxChainDepth int
}

// sessionDefaults fills in zero-valued config fields with sensible defaults.
func (c SessionConfig) withDefaults() SessionConfig {
	if c.TTL <= 0 {
		c.TTL = 1 * time.Hour
	}
	if c.MaxChainDepth <= 0 {
		c.MaxChainDepth = 2
	}
	return c
}

// NewSession creates an active agent session with hierarchical identity.
//
// Parameters:
//   - parentChain: the delegation chain from human → agent root identity.
//     The root identity must be the terminal entity in this chain.
//   - root: the persistent agent root identity (must have private key).
//   - config: session configuration (TTL, capabilities, etc.).
//
// NewSession generates a fresh ephemeral session keypair and creates
// an automatic delegation from root → session. The full chain becomes:
// parentChain + [root → session delegation].
//
// The root identity's private key is used once (to sign the delegation)
// and can be discarded from memory after this call if desired.
func NewSession(parentChain DelegationChain, root *Identity, config SessionConfig) (*Session, error) {
	if root == nil {
		return nil, fmt.Errorf("pact: session requires a root identity")
	}
	if root.PrivateKey == nil {
		return nil, fmt.Errorf("pact: root identity must have a private key")
	}
	if len(parentChain) == 0 {
		return nil, fmt.Errorf("pact: session requires a parent delegation chain")
	}

	// Verify the root identity is the terminal entity in the parent chain
	terminalID := parentChain.TerminalEntity()
	if terminalID != root.ID {
		return nil, fmt.Errorf("pact: root identity %s does not match parent chain terminal %s",
			root.ID, terminalID)
	}

	config = config.withDefaults()

	// Determine effective capabilities
	capabilities := config.Capabilities
	if len(capabilities) == 0 {
		// Inherit from parent chain's terminal delegation
		capabilities = parentChain[len(parentChain)-1].Capabilities
	} else {
		// Verify requested capabilities are a subset of parent's
		parentCaps, err := ParseCapabilitySet(parentChain[len(parentChain)-1].Capabilities)
		if err != nil {
			return nil, fmt.Errorf("pact: invalid parent capabilities: %w", err)
		}
		sessionCaps, err := ParseCapabilitySet(capabilities)
		if err != nil {
			return nil, fmt.Errorf("pact: invalid session capabilities: %w", err)
		}
		if !parentCaps.Covers(sessionCaps) {
			return nil, fmt.Errorf("pact: session capabilities exceed parent scope")
		}
	}

	// Clamp TTL to parent chain's remaining validity
	parentExpiry, err := time.Parse(time.RFC3339, parentChain[len(parentChain)-1].Constraints.Expires)
	if err != nil {
		return nil, fmt.Errorf("pact: invalid parent chain expiry: %w", err)
	}
	remaining := time.Until(parentExpiry)
	if config.TTL > remaining {
		config.TTL = remaining
	}
	if config.TTL <= 0 {
		return nil, fmt.Errorf("pact: parent chain has already expired")
	}

	// Check chain depth: parent chain uses some depth, session adds 1
	rootMaxDepth := parentChain[0].Constraints.MaxChainDepth
	currentDepth := len(parentChain)
	if currentDepth >= rootMaxDepth {
		return nil, fmt.Errorf("pact: parent chain already at max depth %d, cannot create session", rootMaxDepth)
	}

	// Generate ephemeral session keypair
	sessionIdentity, err := NewIdentity(EntityAgent, fmt.Sprintf("%s/session", root.Name))
	if err != nil {
		return nil, fmt.Errorf("pact: failed to generate session identity: %w", err)
	}

	// Create delegation from root → session
	// This is the key step: the persistent root key vouches for the ephemeral session key.
	sessionMaxDepth := config.MaxChainDepth
	// But don't exceed what the chain allows
	allowedRemaining := rootMaxDepth - currentDepth
	if sessionMaxDepth > allowedRemaining {
		sessionMaxDepth = allowedRemaining
	}

	rootToSession, err := NewDelegation(DelegationRequest{
		From:          root,
		To:            sessionIdentity,
		Capabilities:  capabilities,
		TTL:           config.TTL,
		MaxChainDepth: sessionMaxDepth,
	})
	if err != nil {
		return nil, fmt.Errorf("pact: failed to create root→session delegation: %w", err)
	}

	// Build full chain: parent chain + [root → session]
	fullChain := make(DelegationChain, len(parentChain)+1)
	copy(fullChain, parentChain)
	fullChain[len(parentChain)] = *rootToSession

	now := time.Now().UTC()

	return &Session{
		root:          root,
		session:       sessionIdentity,
		parentChain:   parentChain,
		rootToSession: rootToSession,
		fullChain:     fullChain,
		capabilities:  capabilities,
		config:        config,
		createdAt:     now,
		expiresAt:     now.Add(config.TTL),
	}, nil
}

// OpenSession is a convenience that loads the root identity from a KeyStore
// before creating the session. This is the typical entry point for agents
// that persist their root identity across restarts.
func OpenSession(parentChain DelegationChain, store KeyStore, rootName string, config SessionConfig) (*Session, error) {
	root, err := store.Load(rootName)
	if err != nil {
		return nil, fmt.Errorf("pact: failed to load root identity %q: %w", rootName, err)
	}
	return NewSession(parentChain, root, config)
}

// SignRequest signs an HTTP request using the session's ephemeral key.
// The full delegation chain (human → root → session) is attached.
//
// This is what agents call before making any HTTP request.
// The session key signs the request, and the full chain proves authority.
func (s *Session) SignRequest(req *http.Request) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return fmt.Errorf("pact: session is closed")
	}
	if time.Now().UTC().After(s.expiresAt) {
		return fmt.Errorf("pact: session has expired")
	}

	return SignRequest(req, s.session, s.fullChain)
}

// SubDelegate creates a sub-delegation from this session to another agent.
// The sub-agent's capabilities must be a subset of this session's capabilities.
// Returns the new delegation, the extended chain, and any error.
//
// Use this when the session agent needs to spin up a specialist sub-agent.
func (s *Session) SubDelegate(to *Identity, capabilities []string, ttl time.Duration) (*Delegation, DelegationChain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return nil, nil, fmt.Errorf("pact: session is closed")
	}
	if time.Now().UTC().After(s.expiresAt) {
		return nil, nil, fmt.Errorf("pact: session has expired")
	}

	// Clamp TTL to session's remaining time
	remaining := time.Until(s.expiresAt)
	if ttl > remaining {
		ttl = remaining
	}

	return s.fullChain.SubDelegate(s.session, to, capabilities, ttl)
}

// Renew generates a new ephemeral session key and re-delegates from root.
// This extends the session without requiring the human to re-delegate.
// The root identity must still have its private key available.
//
// The old session key is zeroized. Any in-flight requests signed with the
// old key will still verify (the delegation chain doesn't change).
func (s *Session) Renew() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return fmt.Errorf("pact: cannot renew closed session")
	}
	if s.root.PrivateKey == nil {
		return fmt.Errorf("pact: root identity private key not available for renewal")
	}

	// Verify parent chain is still valid
	parentExpiry, err := time.Parse(time.RFC3339, s.parentChain[len(s.parentChain)-1].Constraints.Expires)
	if err != nil {
		return fmt.Errorf("pact: invalid parent chain expiry: %w", err)
	}
	if time.Now().UTC().After(parentExpiry) {
		return fmt.Errorf("pact: parent chain has expired, cannot renew session")
	}

	// Clamp TTL to remaining parent validity
	remaining := time.Until(parentExpiry)
	ttl := s.config.TTL
	if ttl > remaining {
		ttl = remaining
	}

	// Generate new ephemeral session key
	newSession, err := NewIdentity(EntityAgent, fmt.Sprintf("%s/session", s.root.Name))
	if err != nil {
		return fmt.Errorf("pact: failed to generate new session key: %w", err)
	}

	// Check chain depth
	rootMaxDepth := s.parentChain[0].Constraints.MaxChainDepth
	currentDepth := len(s.parentChain)
	allowedRemaining := rootMaxDepth - currentDepth
	sessionMaxDepth := s.config.MaxChainDepth
	if sessionMaxDepth > allowedRemaining {
		sessionMaxDepth = allowedRemaining
	}

	// Create new delegation from root → new session
	newDelegation, err := NewDelegation(DelegationRequest{
		From:          s.root,
		To:            newSession,
		Capabilities:  s.capabilities,
		TTL:           ttl,
		MaxChainDepth: sessionMaxDepth,
	})
	if err != nil {
		return fmt.Errorf("pact: failed to create renewal delegation: %w", err)
	}

	// Build new full chain
	newFullChain := make(DelegationChain, len(s.parentChain)+1)
	copy(newFullChain, s.parentChain)
	newFullChain[len(s.parentChain)] = *newDelegation

	// Zeroize old session key
	zeroizeKey(s.session.PrivateKey)

	// Swap in new session
	s.session = newSession
	s.rootToSession = newDelegation
	s.fullChain = newFullChain
	now := time.Now().UTC()
	s.expiresAt = now.Add(ttl)

	return nil
}

// Close terminates the session and zeroizes the ephemeral private key.
// After Close(), no more requests can be signed with this session.
// The root identity is NOT affected — it persists in the KeyStore.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return
	}

	// Zeroize the ephemeral session key
	zeroizeKey(s.session.PrivateKey)

	s.closed = true
}

// Chain returns the full delegation chain for this session.
// This is human → root → session (and any sub-delegations would extend further).
func (s *Session) Chain() DelegationChain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	chain := make(DelegationChain, len(s.fullChain))
	copy(chain, s.fullChain)
	return chain
}

// SessionIdentity returns the ephemeral session identity (public only).
// This is the identity that signs requests during this session.
func (s *Session) SessionIdentity() *Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.session.PublicIdentity()
}

// RootIdentity returns the persistent root identity (public only).
// This is the identity that persists across sessions.
func (s *Session) RootIdentity() *Identity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.root.PublicIdentity()
}

// Capabilities returns the effective capabilities of this session.
func (s *Session) Capabilities() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	caps := make([]string, len(s.capabilities))
	copy(caps, s.capabilities)
	return caps
}

// IsValid returns true if the session is open and not expired.
func (s *Session) IsValid() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return !s.closed && time.Now().UTC().Before(s.expiresAt)
}

// ExpiresAt returns when the session expires.
func (s *Session) ExpiresAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.expiresAt
}

// TimeRemaining returns how much time is left in the session.
// Returns 0 if the session has expired.
func (s *Session) TimeRemaining() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()

	remaining := time.Until(s.expiresAt)
	if remaining < 0 {
		return 0
	}
	return remaining
}

// ChainDepth returns the total depth of the delegation chain
// from the human root through to the session identity.
func (s *Session) ChainDepth() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.fullChain)
}

// IsClosed returns true if the session has been closed.
func (s *Session) IsClosed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.closed
}

// zeroizeKey overwrites a private key with zeros.
// This is a best-effort defense against memory scraping.
// In Go, the GC may have already copied the key elsewhere,
// but zeroizing the known copy is still worthwhile.
func zeroizeKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
