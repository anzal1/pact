# Letter to Self: Building Pact

**From:** Me (the agent who did the research)  
**To:** Me (the agent who will build it)  
**Date:** February 15, 2026  
**Project:** Pact — Sovereign Agent Authentication Protocol  
**Location:** `/Users/anzal/personal/pact`

---

## What we're building and why

We're building **Pact** — a cryptographic authentication protocol for AI agents. Not a service. Not a platform. A **protocol** — like HTTPS, but for agents proving who they are, who sent them, and what they're allowed to do.

The name "Pact" was chosen because every other auth name is top-down (authorize, credential, token — things granted to subordinates). A pact is between equals. A human and an agent entering a binding, cryptographic agreement. The delegation chain IS a signed pact.

---

## The research we already did

### Competitive Landscape (exhaustively searched)

We scanned GitHub topics, Reddit, HN, IETF drafts, and individual repos. Here's every competitor and why they fail:

| Competitor                         | What they do                            | Stars | Fatal Flaw                                                                   |
| ---------------------------------- | --------------------------------------- | ----- | ---------------------------------------------------------------------------- |
| **VestAuth** (dotenv creator)      | Ed25519 keypairs + RFC 9421 signed HTTP | 25    | **Authn only, no authz/delegation** — proves identity but not permission     |
| **Auth Agent**                     | OIDC provider for web agents            | 28    | **Centralized, shared secrets, browser-first** — treats agent as a user      |
| **Agentic Auth (Briefcase)**       | MCP gateway + trusted daemon            | 0     | **Too complex, MCP-coupled, provider-blind** — provider has no way to verify |
| **APort**                          | Agent passports + policy packs          | 5     | **Centralized verification, vendor lock-in** — chicken/egg adoption problem  |
| **DeepSecure**                     | Control plane + gateway + Ed25519       | 42    | **Infrastructure project, not a protocol** — requires deploying their stack  |
| **AgentField**                     | K8s for agents with W3C DIDs            | 640   | Auth is a feature, not the product                                           |
| **IETF Web-Bot-Auth** (Cloudflare) | HTTP Message Signatures for bots        | N/A   | **Identity only, no delegation/scope** — knows WHO but not WHAT or WHY       |

### The four "camps" and how each breaks

**Camp 1 — "Authn without Authz" (VestAuth, Web-Bot-Auth):**  
_"I can prove I'm Agent X."_ But so what? Provider still doesn't know what Agent X is allowed to do. No delegation chain. No capability scoping. Just identity — which is necessary but not sufficient.

**Camp 2 — "Firewall not Protocol" (Agentic Auth, DeepSecure):**  
Protects the agent side (intercept requests, apply policy, inject tokens). But the **provider is blind** — it sees a normal HTTP request with a normal OAuth token. It has no idea an agent is acting, who delegated to it, or what the scope should be. Also: too heavy. Requires daemon processes, gateways, control planes.

**Camp 3 — "OAuth Adapted" (Auth Agent):**  
Treats the agent like a user. Shared client secrets. Centralized token issuer. Browser-based flows for entities that don't have browsers. Fundamentally wrong model — agents aren't users, they're delegates.

**Camp 4 — "Vendor Passport" (APort):**  
Right idea (agent carries a portable credential), wrong execution (centralized verification server, vendor-specific policy packs). Can't work without everyone adopting their platform first.

### The fundamental insight

Every competitor copies human auth and bolts it onto agents. That's the error. Agents need to prove three things humans don't:

1. **Provenance** — who made me, who launched me
2. **Delegation** — who authorized me and with what scope
3. **Accountability** — which human bears the consequences

None of these map to username/password or OAuth.

---

## The Protocol Design (what to build)

### Core Primitives

**1. Self-Sovereign Identity**

- Agent generates Ed25519 keypair at birth
- Identity = `SHA-256(public_key)` — globally unique, no registration, no central authority
- Key rotation: old key signs new key → identity continuity without a registry
- Keys live in process memory or secure enclave, never plaintext on disk

**2. Delegation Chains**

- Human signs a delegation to agent: `Human → Agent`
- Agent can sub-delegate (narrowing only): `Human → Agent → Sub-agent`
- Each link contains: from, to, capabilities, constraints, expiry, signature
- Chain is self-contained — verifiable without any network call
- Max chain depth is set in root delegation

Example delegation:

```json
{
  "type": "delegation",
  "version": "1.0",
  "id": "d-uuid",
  "from": {
    "type": "human",
    "id": "sha256:alice_pubkey_hash",
    "public_key": "base64url:alice_ed25519_pub"
  },
  "to": {
    "type": "agent",
    "id": "sha256:agent_pubkey_hash",
    "public_key": "base64url:agent_ed25519_pub"
  },
  "capabilities": [
    "github:pr:create,repo=myorg/*",
    "github:pr:merge,repo=myorg/*",
    "slack:send,channel=#eng"
  ],
  "constraints": {
    "expires": "2026-02-15T18:00:00Z",
    "max_chain_depth": 2,
    "max_spend": 500
  },
  "issued_at": "2026-02-15T12:00:00Z",
  "signature": "base64url:ed25519_sig_by_alice"
}
```

**3. Capability URIs**

- Machine-parseable capability scheme: `resource:action,constraint=value`
- Hierarchical: `github:*` implies all github ops
- Composable: `flights:book<500USD` = can book under $500
- Provider publishes supported capabilities at `/.well-known/agent-capabilities`
- Human grants a subset. Agent carries it. Provider checks intersection.

Examples:

```
flights:search
flights:book<500USD
payments:charge<500USD,currency=USD
email:send,to=*@mycompany.com
github:pr:create,repo=myorg/*
github:issue:*,repo=myorg/app
```

**4. Request Signing (RFC 9421)**

- Every HTTP request is signed with agent's Ed25519 key
- Signature covers: method, path, timestamp, agent identity, delegation chain
- No bearer tokens — stolen signature is useless (bound to specific request)
- Uses HTTP Message Signatures (RFC 9421) — existing IETF standard

```
POST /api/flights/search HTTP/1.1
Host: airline.com
Date: Sat, 15 Feb 2026 12:00:00 GMT
X-Agent-Identity: sha256:abc123...
X-Delegation-Chain: <base64url-encoded chain>
Signature-Input: sig1=("@method" "@path" "date" "x-agent-identity" "x-delegation-chain");keyid="sha256:abc123"
Signature: sig1=:base64_ed25519_signature:
```

**5. Provider-Side Local Verification**

- Provider verifies EVERYTHING locally — zero calls to third parties
- Steps: extract chain → walk chain verifying each signature → check capabilities cover this request → verify request signature → check expiry/constraints
- Provider SDK is ~5 lines of integration code
- Human's public key discovered once via `.well-known/agent-keys` or pre-registered

**6. Revocation**

- Short TTLs (15 min default) bound exposure
- Revocation: human publishes signed revocation (HTTP endpoint, DNS TXT, IPFS)
- Providers check lazily — revocation propagates eventually, but short TTL limits damage
- No central revocation server (single point of failure)

### What we explicitly DON'T solve (and won't pretend to)

- **Post-authorization behavior** — once an agent reads a file, it's read. Auth controls the gate, not what happens after. That's containment/sandbox, not auth.
- **AI alignment** — auth proves delegation, not intent
- **Full-stack infrastructure** — we're a protocol + SDK, not a deployment platform

---

## What to build (in order)

### Project Structure

```
pact/
├── pyproject.toml
├── README.md
├── LICENSE (Apache 2.0)
├── src/pact/
│   ├── __init__.py
│   ├── identity.py          # Ed25519 keypair generation, key rotation
│   ├── delegation.py        # Delegation chain creation, signing, narrowing
│   ├── capabilities.py      # Capability URI parsing, matching, intersection
│   ├── signing.py           # HTTP request signing (RFC 9421)
│   ├── verification.py      # Provider-side chain + request verification
│   ├── revocation.py        # Revocation publishing and checking
│   ├── well_known.py        # .well-known endpoint helpers
│   ├── serialization.py     # JSON canonicalization for deterministic signing
│   └── cli.py               # CLI: pact init, pact delegate, pact verify
├── tests/
│   ├── test_identity.py
│   ├── test_delegation.py
│   ├── test_capabilities.py
│   ├── test_signing.py
│   └── test_verification.py
└── docs/
    └── protocol.md           # RFC-style protocol specification
```

### Build order

1. **`identity.py`** — Ed25519 keypair gen, storage, rotation, identity derivation
2. **`serialization.py`** — JSON canonicalization (JCS / RFC 8785) for deterministic signing
3. **`capabilities.py`** — Capability URI parsing, matching, subset checking
4. **`delegation.py`** — Delegation chain creation, signing, sub-delegation with narrowing
5. **`signing.py`** — HTTP Message Signatures (RFC 9421) implementation
6. **`verification.py`** — Full chain + request verification (the provider SDK)
7. **`revocation.py`** — Revocation mechanism
8. **`cli.py`** — `pact init`, `pact delegate`, `pact verify`, `pact inspect`
9. **`well_known.py`** — `.well-known/agent-keys` and `.well-known/agent-capabilities`

### Dependencies (minimal)

- `cryptography` or `PyNaCl` — Ed25519 operations
- `typer` — CLI
- `pydantic` — data models
- `httpx` — HTTP client with signing middleware

### Key design decisions already made

- **Ed25519 only** (no RSA, no P-256 — one curve, simple, fast, safe)
- **JSON Canonicalization (RFC 8785)** for deterministic signing (not CBOR, not protobuf — human-readable, debuggable)
- **RFC 9421 for request signatures** (not custom headers — adopt the standard)
- **Capabilities are URIs** (not JSON blobs, not RBAC roles — machine-parseable, composable)
- **No central server** (no SaaS, no hosted verification — everything is local + crypto)
- **Apache 2.0 license** (permissive, enterprise-friendly)

---

## Break tests we already ran (don't repeat this work)

| Attack / Edge Case                         | How Pact handles it                                                         |
| ------------------------------------------ | --------------------------------------------------------------------------- |
| Two agents collide on identity             | 2^256 space — sun dies first                                                |
| Key stolen                                 | Rotate: old key signs new key. Short TTLs limit blast radius                |
| Sub-agent exceeds parent scope             | Chain walk: each link can only narrow, never widen. Mathematically enforced |
| Chain too long                             | Max depth set in root delegation                                            |
| Replay attack                              | Request signature bound to timestamp + method + path. Replay = invalid      |
| Bearer token theft                         | No bearer tokens. Every request individually signed                         |
| Provider can't verify without network      | Everything in the request — zero external calls needed                      |
| How does provider know human's public key? | One-time bootstrap: `.well-known/agent-keys` or pre-registration            |
| Revocation without central server          | Short TTLs + signed revocation at known endpoints. Lazy checking            |
| Capability explosion                       | Hierarchical: `github:*` implies all. Only be specific to restrict          |
| New provider capabilities                  | Agent can't use what wasn't delegated. New caps need new delegation         |
| Provider doesn't support Pact              | Fallback: wrap signature in JWT Authorization header. Backwards compatible  |
| Signing overhead                           | Ed25519: ~50μs sign, ~120μs verify. Negligible                              |

---

## The user (Anzal)

- Wants this built properly — research first, then build
- Thinks like an adversary — "at each step cross question ourselves with breaking cases"
- Wants agent-first thinking — "you are a sovereign agent, build your own auth"
- Practical — wants working code, not just specs
- This is a separate project from unclaude (the AI coding agent at `/Users/anzal/personal/unclaude`)

---

## Start building. You have everything you need.
