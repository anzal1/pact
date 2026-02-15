package pact_test

import (
	"fmt"
	"net/http"
	"time"

	pact "github.com/anzal1/pact"
)

func ExampleNewIdentity() {
	// Create a human identity
	human, err := pact.NewIdentity(pact.EntityHuman, "alice")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Type: %s\n", human.Type)
	fmt.Printf("Name: %s\n", human.Name)
	fmt.Printf("ID starts with: sha256:\n")
	// Output:
	// Type: human
	// Name: alice
	// ID starts with: sha256:
}

func ExampleNewDelegation() {
	// Create identities
	human, _ := pact.NewIdentity(pact.EntityHuman, "alice")
	agent, _ := pact.NewIdentity(pact.EntityAgent, "my-agent")

	// Delegate capabilities from human to agent
	delegation, err := pact.NewDelegation(pact.DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"github:pr:create,repo=myorg/*"},
		TTL:          1 * time.Hour,
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("Type: %s\n", delegation.Type)
	fmt.Printf("Capabilities: %v\n", delegation.Capabilities)
	// Output:
	// Type: delegation
	// Capabilities: [github:pr:create,repo=myorg/*]
}

func ExampleVerifyChain() {
	// Create identities
	human, _ := pact.NewIdentity(pact.EntityHuman, "alice")
	agent, _ := pact.NewIdentity(pact.EntityAgent, "my-agent")

	// Create delegation
	delegation, _ := pact.NewDelegation(pact.DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"*"},
		TTL:          1 * time.Hour,
	})

	// Verify the chain
	chain := pact.DelegationChain{*delegation}
	result := pact.VerifyChain(chain, pact.DefaultVerifyOptions())

	fmt.Printf("Valid: %v\n", result.Valid)
	fmt.Printf("Depth: %d\n", result.ChainDepth)
	// Output:
	// Valid: true
	// Depth: 1
}

func ExampleSignRequest() {
	// Setup: create identities and delegation
	human, _ := pact.NewIdentity(pact.EntityHuman, "alice")
	agent, _ := pact.NewIdentity(pact.EntityAgent, "my-agent")

	delegation, _ := pact.NewDelegation(pact.DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := pact.DelegationChain{*delegation}

	// Sign an HTTP request
	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	err := pact.SignRequest(req, agent, chain)
	if err != nil {
		panic(err)
	}

	// The request now has Pact headers
	fmt.Printf("Has X-Pact-Identity: %v\n", req.Header.Get("X-Pact-Identity") != "")
	fmt.Printf("Has X-Pact-Chain: %v\n", req.Header.Get("X-Pact-Chain") != "")
	fmt.Printf("Has Signature: %v\n", req.Header.Get("Signature") != "")
	// Output:
	// Has X-Pact-Identity: true
	// Has X-Pact-Chain: true
	// Has Signature: true
}

func ExampleVerifyRequest() {
	// Setup: create identities, delegation, and sign a request
	human, _ := pact.NewIdentity(pact.EntityHuman, "alice")
	agent, _ := pact.NewIdentity(pact.EntityAgent, "my-agent")

	delegation, _ := pact.NewDelegation(pact.DelegationRequest{
		From:         human,
		To:           agent,
		Capabilities: []string{"api:read"},
		TTL:          1 * time.Hour,
	})
	chain := pact.DelegationChain{*delegation}

	req, _ := http.NewRequest("GET", "https://api.example.com/data", nil)
	req.Host = "api.example.com"
	pact.SignRequest(req, agent, chain)

	// Provider side: verify the request
	result := pact.VerifyRequest(req, pact.VerifyOptions{
		RequiredCapability: "api:read",
		MaxClockSkew:       30 * time.Second,
	})

	fmt.Printf("Valid: %v\n", result.Valid)
	// Output:
	// Valid: true
}

func ExampleParseCapability() {
	cap, err := pact.ParseCapability("github:pr:create,repo=myorg/*")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Resource: %s\n", cap.Resource)
	fmt.Printf("Action: %s\n", cap.Action)
	fmt.Printf("Repo constraint: %s\n", cap.Constraints["repo"])
	// Output:
	// Resource: github:pr
	// Action: create
	// Repo constraint: myorg/*
}
