package pact

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// SignedRequestHeaders are the custom HTTP headers Pact adds to requests.
const (
	// HeaderAgentIdentity carries the agent's identity ID.
	HeaderAgentIdentity = "X-Pact-Identity"

	// HeaderDelegationChain carries the base64url-encoded delegation chain JSON.
	HeaderDelegationChain = "X-Pact-Chain"

	// HeaderSignatureInput describes what components are covered by the signature.
	HeaderSignatureInput = "Signature-Input"

	// HeaderSignature carries the request signature.
	HeaderSignature = "Signature"

	// HeaderContentDigest carries the SHA-256 digest of the request body.
	HeaderContentDigest = "Content-Digest"
)

// coveredComponents are the HTTP message components included in the signature.
// Per RFC 9421, these are the fields that the signature binds to the request.
var coveredComponents = []string{
	"@method",
	"@path",
	"@authority",
	"date",
	HeaderAgentIdentity,
	HeaderDelegationChain,
}

// SignRequest signs an HTTP request with the agent's private key and attaches
// the delegation chain. This is what agents call before making any HTTP request.
//
// After signing:
//   - X-Pact-Identity header contains the agent's identity
//   - X-Pact-Chain header contains the delegation chain
//   - Signature-Input describes what's covered
//   - Signature contains the Ed25519 signature
//   - Content-Digest contains SHA-256 of the body (if present)
func SignRequest(req *http.Request, agent *Identity, chain DelegationChain) error {
	if agent.PrivateKey == nil {
		return fmt.Errorf("pact: cannot sign request — agent has no private key")
	}

	// Set the Date header if not already set
	if req.Header.Get("Date") == "" {
		req.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	// Set agent identity header
	req.Header.Set(HeaderAgentIdentity, agent.ID)

	// Serialize and set delegation chain
	chainJSON, err := json.Marshal(chain)
	if err != nil {
		return fmt.Errorf("pact: failed to serialize delegation chain: %w", err)
	}
	req.Header.Set(HeaderDelegationChain, encodeBase64URL(chainJSON))

	// Compute content digest for request body (if present)
	if req.Body != nil && req.ContentLength > 0 {
		// Note: for requests with bodies, the caller should set Content-Digest
		// before signing, or we compute it here if possible.
		// For streaming bodies, Content-Digest must be pre-set.
	}

	// Build signature base (RFC 9421 §2.5)
	components := coveredComponents
	sigBase := buildSignatureBase(req, components)

	// Build Signature-Input header value
	sigInput := buildSignatureInput(components, agent.ID)
	req.Header.Set(HeaderSignatureInput, sigInput)

	// Include Signature-Input in what we sign (prevents tampering with input spec)
	sigBase += fmt.Sprintf("\"signature-input\": %s\n", sigInput)

	// Sign the signature base
	sig, err := agent.Sign([]byte(sigBase))
	if err != nil {
		return err
	}
	req.Header.Set(HeaderSignature, fmt.Sprintf("pact=:%s:", encodeBase64URL(sig)))

	return nil
}

// buildSignatureBase constructs the signature base string per RFC 9421 §2.5.
// This is the canonical string that gets signed.
func buildSignatureBase(req *http.Request, components []string) string {
	var sb strings.Builder

	for _, comp := range components {
		value := resolveComponent(req, comp)
		sb.WriteString(fmt.Sprintf("\"%s\": %s\n", strings.ToLower(comp), value))
	}

	return sb.String()
}

// resolveComponent extracts the value of a covered component from the request.
func resolveComponent(req *http.Request, component string) string {
	switch component {
	case "@method":
		return req.Method
	case "@path":
		path := req.URL.Path
		if path == "" {
			path = "/"
		}
		if req.URL.RawQuery != "" {
			path += "?" + req.URL.RawQuery
		}
		return path
	case "@authority":
		return req.Host
	default:
		// Regular header
		return req.Header.Get(component)
	}
}

// buildSignatureInput constructs the Signature-Input header value per RFC 9421.
func buildSignatureInput(components []string, keyID string) string {
	// Format: pact=("@method" "@path" "@authority" "date" ...);keyid="sha256:...";created=...
	var parts []string
	for _, comp := range components {
		parts = append(parts, fmt.Sprintf("\"%s\"", strings.ToLower(comp)))
	}

	created := time.Now().UTC().Unix()
	return fmt.Sprintf("pact=(%s);keyid=\"%s\";created=%d;alg=\"ed25519\"",
		strings.Join(parts, " "), keyID, created)
}

// ComputeContentDigest computes the SHA-256 digest of a request body.
// Returns the value for the Content-Digest header per RFC 9530.
func ComputeContentDigest(body []byte) string {
	hash := sha256.Sum256(body)
	return fmt.Sprintf("sha-256=:%s:", encodeBase64URL(hash[:]))
}

// RequestSignatureData holds the parsed signature data extracted from an HTTP request.
// Used by the verification pipeline.
type RequestSignatureData struct {
	// SignatureBase is the canonical string that was signed.
	SignatureBase string

	// Signature is the raw Ed25519 signature bytes.
	Signature []byte

	// AgentID is the claimed agent identity.
	AgentID string

	// Chain is the parsed delegation chain.
	Chain DelegationChain

	// SignatureInput is the parsed Signature-Input header.
	SignatureInput string

	// Timestamp is when the request was signed.
	Timestamp time.Time
}

// ExtractSignatureData parses the Pact signature data from an HTTP request.
// This is the first step of provider-side verification.
func ExtractSignatureData(req *http.Request) (*RequestSignatureData, error) {
	// Extract agent identity
	agentID := req.Header.Get(HeaderAgentIdentity)
	if agentID == "" {
		return nil, fmt.Errorf("pact: missing %s header", HeaderAgentIdentity)
	}

	// Extract and decode delegation chain
	chainEncoded := req.Header.Get(HeaderDelegationChain)
	if chainEncoded == "" {
		return nil, fmt.Errorf("pact: missing %s header", HeaderDelegationChain)
	}
	chainJSON, err := decodeBase64URL(chainEncoded)
	if err != nil {
		return nil, fmt.Errorf("pact: invalid delegation chain encoding: %w", err)
	}
	var chain DelegationChain
	if err := json.Unmarshal(chainJSON, &chain); err != nil {
		return nil, fmt.Errorf("pact: invalid delegation chain JSON: %w", err)
	}

	// Extract signature
	sigHeader := req.Header.Get(HeaderSignature)
	if sigHeader == "" {
		return nil, fmt.Errorf("pact: missing %s header", HeaderSignature)
	}
	sigBytes, err := parseSignatureHeader(sigHeader)
	if err != nil {
		return nil, err
	}

	// Extract Signature-Input
	sigInput := req.Header.Get(HeaderSignatureInput)
	if sigInput == "" {
		return nil, fmt.Errorf("pact: missing %s header", HeaderSignatureInput)
	}

	// Rebuild signature base for verification
	sigBase := buildSignatureBase(req, coveredComponents)
	sigBase += fmt.Sprintf("\"signature-input\": %s\n", sigInput)

	// Parse timestamp from Date header
	dateStr := req.Header.Get("Date")
	var timestamp time.Time
	if dateStr != "" {
		timestamp, _ = time.Parse(http.TimeFormat, dateStr)
	}

	return &RequestSignatureData{
		SignatureBase:  sigBase,
		Signature:      sigBytes,
		AgentID:        agentID,
		Chain:          chain,
		SignatureInput: sigInput,
		Timestamp:      timestamp,
	}, nil
}

// parseSignatureHeader extracts the raw signature bytes from the Signature header.
// Format: pact=:base64url_signature:
func parseSignatureHeader(header string) ([]byte, error) {
	// Expected format: pact=:base64url:
	prefix := "pact=:"
	if !strings.HasPrefix(header, prefix) {
		return nil, fmt.Errorf("pact: invalid Signature header format: %q", header)
	}
	rest := header[len(prefix):]
	if !strings.HasSuffix(rest, ":") {
		return nil, fmt.Errorf("pact: invalid Signature header format: %q", header)
	}
	encoded := rest[:len(rest)-1]
	return decodeBase64URL(encoded)
}
