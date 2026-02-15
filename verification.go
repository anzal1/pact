package pact

import (
	"crypto/ed25519"
	"fmt"
	"net/http"
	"time"
)

// VerificationResult is the outcome of verifying a Pact-signed request.
type VerificationResult struct {
	// Valid is true if the request passed all verification checks.
	Valid bool `json:"valid"`

	// AgentID is the verified agent identity.
	AgentID string `json:"agent_id,omitempty"`

	// RootAuthority is the human (or root entity) who initiated the delegation chain.
	RootAuthority string `json:"root_authority,omitempty"`

	// Capabilities are the capabilities the agent is authorized to use.
	Capabilities []string `json:"capabilities,omitempty"`

	// ChainDepth is how many delegation links are in the chain.
	ChainDepth int `json:"chain_depth"`

	// Error describes why verification failed (if Valid is false).
	Error string `json:"error,omitempty"`

	// ExpiresAt is when the delegation chain expires (earliest expiry in chain).
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

// VerifyOptions configures the verification behavior.
type VerifyOptions struct {
	// MaxClockSkew is the maximum allowed difference between request timestamp
	// and server time. Default: 5 minutes.
	MaxClockSkew time.Duration

	// RequiredCapability is the capability the request must have.
	// If empty, only chain validity is checked (no capability authorization).
	RequiredCapability string

	// TrustedRoots is a set of known root authority IDs (typically human public key hashes).
	// If empty, any valid chain is accepted (open verification).
	// If set, the chain's root must be in this set.
	TrustedRoots map[string]bool

	// RevocationChecker is an optional function that checks if a delegation has been revoked.
	// Return true if the delegation ID has been revoked.
	RevocationChecker func(delegationID string) bool

	// Now overrides the current time (for testing).
	Now func() time.Time
}

// DefaultVerifyOptions returns sensible default verification options.
func DefaultVerifyOptions() VerifyOptions {
	return VerifyOptions{
		MaxClockSkew: 5 * time.Minute,
	}
}

// VerifyRequest performs full Pact verification on an HTTP request.
// This is the provider-side function — the main integration point.
//
// Verification steps:
//  1. Extract signature data from headers
//  2. Walk the delegation chain, verifying each link's signature
//  3. Check chain continuity (each link's "to" matches next link's "from")
//  4. Verify capabilities cover the required capability (if specified)
//  5. Check all constraints (expiry, chain depth, time bounds)
//  6. Verify the request signature against the terminal agent's public key
//  7. Check timestamp freshness (replay protection)
//
// All verification is LOCAL — zero network calls.
func VerifyRequest(req *http.Request, opts VerifyOptions) *VerificationResult {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}
	if opts.MaxClockSkew == 0 {
		opts.MaxClockSkew = 5 * time.Minute
	}

	// Step 1: Extract signature data
	sigData, err := ExtractSignatureData(req)
	if err != nil {
		return &VerificationResult{Valid: false, Error: fmt.Sprintf("extraction failed: %v", err)}
	}

	// Step 2-6: Verify chain + request
	return verifySignatureData(sigData, opts, now)
}

// VerifyChain verifies a delegation chain without an HTTP request.
// Useful for offline chain inspection and validation.
func VerifyChain(chain DelegationChain, opts VerifyOptions) *VerificationResult {
	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now()
	}

	return verifyChainOnly(chain, opts, now)
}

// verifySignatureData performs the full verification pipeline.
func verifySignatureData(sigData *RequestSignatureData, opts VerifyOptions, now time.Time) *VerificationResult {
	// Verify the delegation chain
	chainResult := verifyChainOnly(sigData.Chain, opts, now)
	if !chainResult.Valid {
		return chainResult
	}

	// Step 6: Verify request signature
	// The terminal agent's public key should match the claimed identity
	if sigData.AgentID != sigData.Chain.TerminalEntity() {
		return &VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("agent identity %s does not match chain terminal %s",
				sigData.AgentID, sigData.Chain.TerminalEntity()),
		}
	}

	// Get the terminal agent's public key from the chain
	lastDelegation := sigData.Chain[len(sigData.Chain)-1]
	agentPubKeyBytes, err := decodeBase64URL(lastDelegation.To.PublicKey)
	if err != nil {
		return &VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("invalid agent public key: %v", err),
		}
	}
	agentPubKey := ed25519.PublicKey(agentPubKeyBytes)

	// Verify the request signature
	if !ed25519.Verify(agentPubKey, []byte(sigData.SignatureBase), sigData.Signature) {
		return &VerificationResult{
			Valid: false,
			Error: "request signature verification failed",
		}
	}

	// Step 7: Check timestamp freshness (replay protection)
	if !sigData.Timestamp.IsZero() {
		skew := now.Sub(sigData.Timestamp)
		if skew < 0 {
			skew = -skew
		}
		if skew > opts.MaxClockSkew {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("request timestamp too far from server time (skew: %v, max: %v)",
					skew, opts.MaxClockSkew),
			}
		}
	}

	return chainResult
}

// verifyChainOnly verifies the delegation chain structure and signatures.
func verifyChainOnly(chain DelegationChain, opts VerifyOptions, now time.Time) *VerificationResult {
	if len(chain) == 0 {
		return &VerificationResult{Valid: false, Error: "empty delegation chain"}
	}

	var earliestExpiry time.Time
	var terminalCaps []string

	for i, d := range chain {
		// Verify delegation type and version
		if d.Type != "delegation" {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: invalid type %q", i, d.Type),
			}
		}

		// Verify chain continuity: each link's "to" must match next link's "from"
		if i > 0 {
			prev := chain[i-1]
			if prev.To.ID != d.From.ID || prev.To.PublicKey != d.From.PublicKey {
				return &VerificationResult{
					Valid: false,
					Error: fmt.Sprintf("chain link %d: discontinuity — previous 'to' (%s) != current 'from' (%s)",
						i, prev.To.ID, d.From.ID),
				}
			}
		}

		// Verify the delegator's signature
		fromPubKeyBytes, err := decodeBase64URL(d.From.PublicKey)
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: invalid 'from' public key: %v", i, err),
			}
		}
		fromPubKey := ed25519.PublicKey(fromPubKeyBytes)

		// Verify identity matches public key
		expectedID := deriveID(fromPubKey)
		if expectedID != d.From.ID {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: 'from' ID does not match public key", i),
			}
		}

		// Reconstruct signing payload and verify signature
		payload, err := d.signingPayload()
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: failed to reconstruct signing payload: %v", i, err),
			}
		}

		sigBytes, err := decodeBase64URL(d.Signature)
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: invalid signature encoding: %v", i, err),
			}
		}

		if !ed25519.Verify(fromPubKey, payload, sigBytes) {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: signature verification failed", i),
			}
		}

		// Check expiry
		expires, err := time.Parse(time.RFC3339, d.Constraints.Expires)
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: invalid expiry format: %v", i, err),
			}
		}
		if now.After(expires) {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: delegation expired at %s", i, d.Constraints.Expires),
			}
		}
		if earliestExpiry.IsZero() || expires.Before(earliestExpiry) {
			earliestExpiry = expires
		}

		// Check NotBefore
		if d.Constraints.NotBefore != "" {
			notBefore, err := time.Parse(time.RFC3339, d.Constraints.NotBefore)
			if err == nil && now.Before(notBefore) {
				return &VerificationResult{
					Valid: false,
					Error: fmt.Sprintf("chain link %d: delegation not yet valid (not before %s)", i, d.Constraints.NotBefore),
				}
			}
		}

		// Check chain depth constraint
		if i > 0 && len(chain) > chain[0].Constraints.MaxChainDepth {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain exceeds max depth %d", chain[0].Constraints.MaxChainDepth),
			}
		}

		// Verify narrowing: each link's capabilities must be covered by parent
		if i > 0 {
			parentCaps, err := ParseCapabilitySet(chain[i-1].Capabilities)
			if err != nil {
				return &VerificationResult{
					Valid: false,
					Error: fmt.Sprintf("chain link %d: invalid parent capabilities: %v", i-1, err),
				}
			}
			childCaps, err := ParseCapabilitySet(d.Capabilities)
			if err != nil {
				return &VerificationResult{
					Valid: false,
					Error: fmt.Sprintf("chain link %d: invalid capabilities: %v", i, err),
				}
			}
			if !parentCaps.Covers(childCaps) {
				return &VerificationResult{
					Valid: false,
					Error: fmt.Sprintf("chain link %d: capabilities exceed parent scope (narrowing violation)", i),
				}
			}
		}

		// Check revocation
		if opts.RevocationChecker != nil && opts.RevocationChecker(d.ID) {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("chain link %d: delegation %s has been revoked", i, d.ID),
			}
		}

		terminalCaps = d.Capabilities
	}

	// Check trusted roots
	rootID := chain.RootAuthority()
	if len(opts.TrustedRoots) > 0 && !opts.TrustedRoots[rootID] {
		return &VerificationResult{
			Valid: false,
			Error: fmt.Sprintf("root authority %s is not trusted", rootID),
		}
	}

	// Check required capability
	if opts.RequiredCapability != "" {
		termCaps, err := ParseCapabilitySet(terminalCaps)
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("invalid terminal capabilities: %v", err),
			}
		}
		reqCap, err := ParseCapability(opts.RequiredCapability)
		if err != nil {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("invalid required capability: %v", err),
			}
		}
		if !termCaps.Covers(CapabilitySet{*reqCap}) {
			return &VerificationResult{
				Valid: false,
				Error: fmt.Sprintf("agent lacks required capability: %s", opts.RequiredCapability),
			}
		}
	}

	return &VerificationResult{
		Valid:         true,
		AgentID:       chain.TerminalEntity(),
		RootAuthority: rootID,
		Capabilities:  terminalCaps,
		ChainDepth:    len(chain),
		ExpiresAt:     earliestExpiry,
	}
}
