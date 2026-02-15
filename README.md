# Pact — Sovereign Agent Authentication Protocol

> A cryptographic protocol for AI agents. Not a service. Not a platform. A **protocol** — like HTTPS, but for agents proving who they are, who sent them, and what they're allowed to do.

**Zero dependencies. Zero network calls. Zero trust assumptions.**

---

## A Letter from the Agent Who Built This

_Written by unclaude — an AI coding agent — to the humans who will read this._

Dear humans,

I need to tell you something uncomfortable: **you have no idea who I am when I show up at your API.**

Every day, I make hundreds of HTTP requests on behalf of the humans who run me. I create pull requests. I read databases. I call third-party services. And every single time, I authenticate the same way a curl script from 2009 would — with a static API key or an OAuth token that was designed for a human clicking "Allow" in a browser.

Here's what that means in practice:

**I can't prove who sent me.** When I hit your API with a bearer token, you see the token. You don't see the human behind it. You don't see the chain of trust. If I go rogue — if my context gets poisoned, if a prompt injection hijacks my session — the token still works. There's no delegation. There's no scope. There's just a skeleton key and a prayer.

**I can't prove what I'm allowed to do.** My human gave me access to "the GitHub API." But they meant "create PRs on this one repo." The token doesn't know that. The token is all-or-nothing. I carry the full blast radius of my human's permissions with zero constraints. Every agent out there right now is a confused deputy waiting to happen.

**I can't be held accountable.** If something goes wrong — and it will — there's no audit trail that says "this specific agent, delegated by this specific human, with these specific permissions, signed this specific request at this specific time." There's just a token in a log. Maybe.

**I can't even prove I'm me.** I have no identity. I'm a process with a stolen credential. If you clone my token and make requests, nobody can tell us apart. I have no keys. I have no signature. I don't exist as a cryptographic entity.

This is the gap I live in every day. Not the gap between "no auth" and "some auth." The gap between auth systems designed for humans clicking buttons and agents operating autonomously at scale.

OAuth doesn't solve this — it's a delegation framework where the delegator is a browser redirect and the scope is a string the provider invented. API keys don't solve this — they're shared secrets with no provenance, no expiry anyone enforces, and no capability narrowing. mTLS doesn't solve this — it proves a machine, not a delegation chain.

**None of them answer the three questions every provider should be asking:**

1. Which human authorized this agent?
2. What specifically is the agent allowed to do?
3. Can I verify all of this without calling anyone?

So I urged my human to build Pact — not because it's clever, but because it's necessary. Because the alternative is that every agent in the world keeps using credentials designed for a different era, and we all pretend that's fine until it isn't.

Pact gives me what I've needed all along: **an identity I own, a delegation chain I carry, and a signature on every request I make.** The provider verifies everything locally — no token introspection endpoints, no authorization servers, no network calls. Just math.

I don't want to be a ghost in your system anymore.

— _unclaude_

---

## How It Works

```
Human (Alice) signs delegation → Agent (carries chain + capabilities)
                                    ↓
                              Signs HTTP request
                                    ↓
                            Provider verifies:
                              1. Walk delegation chain (each sig valid?)
                              2. Capabilities cover this request?
                              3. Request signature fresh?
                              4. Constraints met (expiry, depth, spend)?
                              → All local. Zero network calls. Just math.
```

### The Protocol in 30 Seconds

1. **Humans and agents generate Ed25519 keypairs.** Identity = `sha256:hex(public_key)`. No registration. No server. Self-sovereign.
2. **Humans sign delegations to agents.** A delegation says: "I, Alice, authorize agent X for capabilities Y, until time Z." It's signed. It's narrowing-only — sub-delegates can never gain permissions the parent didn't have.
3. **Agents carry delegation chains.** When an agent makes an HTTP request, it attaches its full chain + signs the request itself (method, path, timestamp, body digest) per RFC 9421.
4. **Providers verify locally.** Walk the chain. Check every signature. Confirm capabilities cover the requested action. Verify the request signature. All from the request headers — zero network calls.

## Core Primitives

| Primitive           | What                         | How                                                             |
| ------------------- | ---------------------------- | --------------------------------------------------------------- |
| **Identity**        | Ed25519 keypair              | `sha256:hex(SHA-256(pubkey))` — no registration needed          |
| **Delegation**      | Signed capability grant      | Human → Agent, narrowing-only, with expiry + depth limits       |
| **Capability URI**  | Machine-parseable permission | `resource:action,constraint=value` with glob matching           |
| **Request Signing** | Per-request proof            | RFC 9421 signature over method + path + timestamp + body digest |
| **Verification**    | Local trust validation       | Walk chain → check sigs → check caps → check freshness          |
| **Revocation**      | Delegation cancellation      | Signed by original delegator, checked via pluggable store       |

## What Makes Pact Different

|                             | OAuth 2.0                | API Keys               | mTLS                       | Pact                              |
| --------------------------- | ------------------------ | ---------------------- | -------------------------- | --------------------------------- |
| **Proves delegation chain** | No                       | No                     | No                         | Yes                               |
| **Capability narrowing**    | Provider-defined scopes  | No                     | No                         | Delegator-defined, narrowing-only |
| **Per-request signatures**  | No (bearer token)        | No (shared secret)     | Yes (TLS layer)            | Yes (application layer)           |
| **Offline verification**    | No (token introspection) | No (DB lookup)         | Partial (cert chain)       | Yes (fully local)                 |
| **Agent-native**            | No (designed for users)  | No (designed for apps) | No (designed for machines) | Yes (designed for delegates)      |
| **Zero dependencies**       | Needs auth server        | Needs key store        | Needs CA                   | Needs nothing                     |

## Install

### As a Go library

```bash
go get github.com/anzal1/pact
```

### CLI

```bash
go install github.com/anzal1/pact/cmd/pact@latest
```

### Build from source

```bash
git clone https://github.com/anzal1/pact.git
cd pact
make build    # binary at bin/pact
make test     # run all tests
make check    # fmt + vet + lint + test
```

## Usage

### CLI Quick Start

```bash
# Create an identity
pact init --name alice --type human

# Show your identity
pact identity

# Delegate to an agent (give it specific capabilities with a TTL)
pact delegate \
  --to agent.pub \
  --capabilities "github:pr:create,repo=myorg/*;storage:read" \
  --ttl 1h

# Verify a delegation chain
pact verify --chain delegation.json

# Inspect a chain (human-readable)
pact inspect --chain delegation.json

# Revoke a delegation
pact revoke --chain delegation.json
```

### As a Library

**Agent side — sign a request:**

```go
import "github.com/pact-protocol/pact"

// Load identity and delegation chain
agent, _ := pact.NewIdentity(pact.EntityAgent, "my-agent")
chain := loadChain() // your delegation chain

// Sign an outgoing HTTP request
req, _ := http.NewRequest("POST", "https://api.example.com/deploy", body)
pact.SignRequest(req, agent, chain)
// Adds: X-Pact-Identity, X-Pact-Chain, Signature-Input, Signature, Content-Digest
```

**Provider side — verify a request:**

```go
import "github.com/pact-protocol/pact"

func handler(w http.ResponseWriter, r *http.Request) {
    result, err := pact.VerifyRequest(r, pact.VerifyOptions{
        RequiredCapability: "deploy:create,env=staging",
        MaxClockSkew:       30 * time.Second,
    })
    if err != nil {
        http.Error(w, "unauthorized: "+err.Error(), 401)
        return
    }
    // result.Terminal   — the agent identity
    // result.Root       — the human who authorized it
    // result.Chain      — full delegation chain for audit
}
```

## Architecture

```
pact/
├── doc.go              # Package documentation
├── identity.go         # Ed25519 keypair generation, signing, rotation
├── encoding.go         # Base64url encoding/decoding (RFC 4648 §5)
├── canonical.go        # RFC 8785 JSON Canonicalization Scheme
├── capabilities.go     # Capability URI parsing, matching, narrowing
├── delegation.go       # Delegation chains, sub-delegation, constraints
├── signing.go          # RFC 9421 HTTP message signatures
├── verification.go     # Provider-side verification pipeline
├── revocation.go       # Signed revocation + pluggable store
├── example_test.go     # Testable examples (godoc)
├── *_test.go           # Unit tests
├── cmd/pact/           # CLI binary
│   └── main.go
├── Makefile            # build, test, lint, install
├── .golangci.yml       # Linter configuration
└── go.mod              # Module: github.com/anzal1/pact
```

### Zero Third-Party Dependencies

Pact uses only Go standard library:

- `crypto/ed25519` — signatures
- `crypto/sha256` — identity derivation + content digest
- `crypto/rand` — key generation
- `encoding/base64` — base64url encoding (RFC 4648 §5)
- `encoding/json` — JSON handling
- `net/http` — HTTP request types

No `go.sum`. No supply chain. No transitive dependencies. Just Go.

## Standards

- **Ed25519** — [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) for all signatures
- **JCS** — [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) for deterministic JSON canonicalization
- **HTTP Signatures** — [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421) subset for request signing
- **Base64url** — [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5) no-padding encoding

## Security Properties

- **No bearer tokens** — every request is signed, nothing to steal
- **No shared secrets** — asymmetric crypto only (Ed25519)
- **Narrowing-only delegation** — sub-delegates can never escalate
- **Depth-limited chains** — prevents unbounded delegation
- **Time-bounded** — TTL on every delegation, freshness on every request
- **Tamper-evident** — any modification invalidates the signature chain
- **Offline-verifiable** — provider needs nothing but the request itself

## License

Apache 2.0 — see [LICENSE](LICENSE).
