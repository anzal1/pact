package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	pact "github.com/anzal1/pact"
)

const (
	pactDir    = ".pact"
	keyFile    = "identity.json"
	versionStr = "0.1.0"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = cmdInit(os.Args[2:])
	case "identity":
		err = cmdIdentity(os.Args[2:])
	case "delegate":
		err = cmdDelegate(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "inspect":
		err = cmdInspect(os.Args[2:])
	case "revoke":
		err = cmdRevoke(os.Args[2:])
	case "version":
		fmt.Printf("pact %s\n", versionStr)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "pact: unknown command %q\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "pact: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`pact — Sovereign Agent Authentication Protocol

Usage:
  pact <command> [options]

Commands:
  init        Generate a new identity (Ed25519 keypair)
  identity    Show current identity
  delegate    Create a signed delegation to another entity
  verify      Verify a delegation chain
  inspect     Display a delegation chain in human-readable form
  revoke      Revoke a delegation
  version     Show version

Examples:
  pact init --name alice --type human
  pact init --name my-agent --type agent
  pact delegate --to agent.pub --capabilities "github:pr:create,repo=myorg/*" --ttl 1h
  pact verify --chain delegation.json
  pact inspect --chain delegation.json`)
}

type identityStorage struct {
	Type       string `json:"type"`
	ID         string `json:"id"`
	PublicKey  string `json:"public_key"`
	PrivateKey string `json:"private_key"`
	Name       string `json:"name"`
	CreatedAt  string `json:"created_at"`
}

func cmdInit(args []string) error {
	name := "default"
	entityType := pact.EntityAgent

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			i++
			if i < len(args) {
				name = args[i]
			}
		case "--type":
			i++
			if i < len(args) {
				switch args[i] {
				case "human":
					entityType = pact.EntityHuman
				case "agent":
					entityType = pact.EntityAgent
				default:
					return fmt.Errorf("invalid entity type %q (must be 'human' or 'agent')", args[i])
				}
			}
		}
	}

	identity, err := pact.NewIdentity(entityType, name)
	if err != nil {
		return err
	}

	dir := pactConfigDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	idData := identityStorage{
		Type:       string(identity.Type),
		ID:         identity.ID,
		PublicKey:  identity.PublicKey,
		PrivateKey: pact.ExportBase64URL(identity.PrivateKey),
		Name:       identity.Name,
		CreatedAt:  identity.CreatedAt.Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(idData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize identity: %w", err)
	}

	idPath := filepath.Join(dir, keyFile)
	if err := os.WriteFile(idPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write identity: %w", err)
	}

	pubData, err := identity.ExportPublicKey()
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}
	pubPath := filepath.Join(dir, name+".pub")
	if err := os.WriteFile(pubPath, pubData, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	fmt.Printf("Identity created.\n")
	fmt.Printf("  Name:       %s\n", name)
	fmt.Printf("  Type:       %s\n", entityType)
	fmt.Printf("  ID:         %s\n", identity.ID)
	fmt.Printf("  Public key: %s\n", pubPath)
	fmt.Printf("  Config:     %s\n", idPath)

	return nil
}

func cmdIdentity(_ []string) error {
	identity, err := loadIdentity()
	if err != nil {
		return err
	}

	fmt.Printf("Type:       %s\n", identity.Type)
	fmt.Printf("ID:         %s\n", identity.ID)
	fmt.Printf("Name:       %s\n", identity.Name)
	fmt.Printf("Public Key: %s\n", identity.PublicKey)
	fmt.Printf("Created:    %s\n", identity.CreatedAt.Format(time.RFC3339))

	return nil
}

func cmdDelegate(args []string) error {
	var toPubFile string
	var capabilities []string
	var ttlStr string
	maxDepth := 1

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--to":
			i++
			if i < len(args) {
				toPubFile = args[i]
			}
		case "--capabilities", "--caps":
			i++
			if i < len(args) {
				capabilities = splitCapabilities(args[i])
			}
		case "--ttl":
			i++
			if i < len(args) {
				ttlStr = args[i]
			}
		case "--max-depth":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &maxDepth)
			}
		}
	}

	if toPubFile == "" {
		return fmt.Errorf("--to is required (path to recipient's public key file)")
	}
	if len(capabilities) == 0 {
		return fmt.Errorf("--capabilities is required (semicolon-separated capability URIs)")
	}
	if ttlStr == "" {
		ttlStr = "15m"
	}

	ttl, err := time.ParseDuration(ttlStr)
	if err != nil {
		return fmt.Errorf("invalid TTL %q: %w", ttlStr, err)
	}

	from, err := loadIdentity()
	if err != nil {
		return err
	}

	to, err := loadPublicIdentity(toPubFile)
	if err != nil {
		return fmt.Errorf("failed to load recipient public key: %w", err)
	}

	delegation, err := pact.NewDelegation(pact.DelegationRequest{
		From:          from,
		To:            to,
		Capabilities:  capabilities,
		TTL:           ttl,
		MaxChainDepth: maxDepth,
	})
	if err != nil {
		return err
	}

	chain := pact.DelegationChain{*delegation}
	data, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize delegation: %w", err)
	}

	outFile := fmt.Sprintf("delegation-%s.json", delegation.ID[:14])
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write delegation: %w", err)
	}

	fmt.Printf("Delegation created.\n")
	fmt.Printf("  ID:           %s\n", delegation.ID)
	fmt.Printf("  From:         %s (%s...)\n", from.Name, from.ID[:20])
	fmt.Printf("  To:           %s (%s...)\n", to.Name, to.ID[:20])
	fmt.Printf("  Capabilities: %v\n", capabilities)
	fmt.Printf("  Expires:      %s\n", delegation.Constraints.Expires)
	fmt.Printf("  Max Depth:    %d\n", delegation.Constraints.MaxChainDepth)
	fmt.Printf("  File:         %s\n", outFile)

	return nil
}

func cmdVerify(args []string) error {
	var chainFile string
	var requiredCap string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--chain":
			i++
			if i < len(args) {
				chainFile = args[i]
			}
		case "--capability", "--cap":
			i++
			if i < len(args) {
				requiredCap = args[i]
			}
		}
	}

	if chainFile == "" {
		return fmt.Errorf("--chain is required (path to delegation chain file)")
	}

	chain, err := loadChain(chainFile)
	if err != nil {
		return err
	}

	opts := pact.DefaultVerifyOptions()
	opts.RequiredCapability = requiredCap

	result := pact.VerifyChain(chain, opts)

	if result.Valid {
		fmt.Printf("VALID\n")
		fmt.Printf("  Agent:         %s\n", result.AgentID)
		fmt.Printf("  Root:          %s\n", result.RootAuthority)
		fmt.Printf("  Depth:         %d\n", result.ChainDepth)
		fmt.Printf("  Capabilities:  %v\n", result.Capabilities)
		fmt.Printf("  Expires:       %s\n", result.ExpiresAt.Format(time.RFC3339))
	} else {
		fmt.Printf("INVALID\n")
		fmt.Printf("  Error: %s\n", result.Error)
		os.Exit(1)
	}

	return nil
}

func cmdInspect(args []string) error {
	var chainFile string

	for i := 0; i < len(args); i++ {
		if args[i] == "--chain" {
			i++
			if i < len(args) {
				chainFile = args[i]
			}
		}
	}

	if chainFile == "" {
		return fmt.Errorf("--chain is required")
	}

	chain, err := loadChain(chainFile)
	if err != nil {
		return err
	}

	fmt.Printf("Delegation Chain (%d links)\n", len(chain))
	fmt.Println("=======================================")

	for i, d := range chain {
		fmt.Printf("\n  Link %d: %s\n", i, d.ID)
		fmt.Printf("  ---------------------------\n")
		fmt.Printf("  From: %s %s\n", d.From.Type, truncateID(d.From.ID))
		if d.From.Name != "" {
			fmt.Printf("        (%s)\n", d.From.Name)
		}
		fmt.Printf("  To:   %s %s\n", d.To.Type, truncateID(d.To.ID))
		if d.To.Name != "" {
			fmt.Printf("        (%s)\n", d.To.Name)
		}
		fmt.Printf("  Capabilities:\n")
		for _, c := range d.Capabilities {
			fmt.Printf("    - %s\n", c)
		}
		fmt.Printf("  Expires:    %s\n", d.Constraints.Expires)
		fmt.Printf("  Max Depth:  %d\n", d.Constraints.MaxChainDepth)
		fmt.Printf("  Issued:     %s\n", d.IssuedAt)
	}

	fmt.Println()
	return nil
}

func cmdRevoke(args []string) error {
	var chainFile string
	var reason string
	linkIndex := 0

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--chain":
			i++
			if i < len(args) {
				chainFile = args[i]
			}
		case "--reason":
			i++
			if i < len(args) {
				reason = args[i]
			}
		case "--link":
			i++
			if i < len(args) {
				fmt.Sscanf(args[i], "%d", &linkIndex)
			}
		}
	}

	if chainFile == "" {
		return fmt.Errorf("--chain is required")
	}

	chain, err := loadChain(chainFile)
	if err != nil {
		return err
	}

	if linkIndex >= len(chain) {
		return fmt.Errorf("link index %d out of range (chain has %d links)", linkIndex, len(chain))
	}

	revoker, err := loadIdentity()
	if err != nil {
		return err
	}

	delegation := &chain[linkIndex]
	revocation, err := pact.NewRevocation(delegation, revoker, reason)
	if err != nil {
		return err
	}

	data, err := pact.SerializeRevocation(revocation)
	if err != nil {
		return fmt.Errorf("failed to serialize revocation: %w", err)
	}

	outFile := fmt.Sprintf("revocation-%s.json", delegation.ID[:14])
	if err := os.WriteFile(outFile, data, 0644); err != nil {
		return fmt.Errorf("failed to write revocation: %w", err)
	}

	fmt.Printf("Revocation created.\n")
	fmt.Printf("  Delegation: %s\n", delegation.ID)
	fmt.Printf("  Revoked by: %s\n", revoker.ID)
	fmt.Printf("  Reason:     %s\n", reason)
	fmt.Printf("  File:       %s\n", outFile)

	return nil
}

// --- Helpers ---

func pactConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", pactDir)
	}
	return filepath.Join(home, pactDir)
}

func loadIdentity() (*pact.Identity, error) {
	dir := pactConfigDir()
	idPath := filepath.Join(dir, keyFile)

	data, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("no identity found — run 'pact init' first (looked in %s)", idPath)
	}

	var stored identityStorage
	if err := json.Unmarshal(data, &stored); err != nil {
		return nil, fmt.Errorf("invalid identity file: %w", err)
	}

	privKey, err := pact.ImportBase64URL(stored.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	createdAt, _ := time.Parse(time.RFC3339, stored.CreatedAt)

	return &pact.Identity{
		Type:       pact.EntityType(stored.Type),
		ID:         stored.ID,
		PublicKey:  stored.PublicKey,
		PrivateKey: privKey,
		Name:       stored.Name,
		CreatedAt:  createdAt,
	}, nil
}

func loadPublicIdentity(path string) (*pact.Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	var id pact.Identity
	if err := json.Unmarshal(data, &id); err != nil {
		return nil, fmt.Errorf("invalid public key file: %w", err)
	}

	return &id, nil
}

func loadChain(path string) (pact.DelegationChain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read chain file: %w", err)
	}

	var chain pact.DelegationChain
	if err := json.Unmarshal(data, &chain); err != nil {
		return nil, fmt.Errorf("invalid chain file: %w", err)
	}

	return chain, nil
}

func splitCapabilities(s string) []string {
	var caps []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			c := trimStr(s[start:i])
			if c != "" {
				caps = append(caps, c)
			}
			start = i + 1
		}
	}
	c := trimStr(s[start:])
	if c != "" {
		caps = append(caps, c)
	}
	if len(caps) == 0 {
		return []string{s}
	}
	return caps
}

func trimStr(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}

func truncateID(id string) string {
	if len(id) > 24 {
		return id[:24] + "..."
	}
	return id
}
