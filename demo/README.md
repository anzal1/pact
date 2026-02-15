# Pact Cross-Language Demo

This demo shows a **Python AI agent** authenticating against a **Go provider** using the Pact protocol — proving full cross-language compatibility.

## Architecture

```
┌─────────────────────┐         HTTP + Pact Headers         ┌──────────────────────┐
│   Python Agent      │ ───────────────────────────────────> │   Go Provider        │
│                     │                                      │                      │
│  • Creates Ed25519  │  X-Pact-Identity: <agent-id>         │  • Pact middleware    │
│    keypair          │  X-Pact-Chain: <delegation-chain>    │  • Verifies Ed25519   │
│  • Signs requests   │  Signature-Input: ...                │    signatures        │
│  • Manages sessions │  Signature: <ed25519-sig>            │  • Checks capability │
│                     │                                      │    authorization     │
│  sdk/python/pact    │                                      │  github.com/anzal1/  │
│                     │ <─────────────────────────────────── │  pact                │
│                     │         JSON Response                │                      │
└─────────────────────┘                                      └──────────────────────┘
```

## What It Demonstrates

1. **Identity creation** — Python agent generates an Ed25519 keypair
2. **Delegation** — Go server (as human) delegates capabilities to the Python agent
3. **Request signing** — Python SDK signs HTTP requests per RFC 9421
4. **Cross-language verification** — Go middleware verifies Python-generated signatures
5. **Capability enforcement** — Requests needing undelegated capabilities are rejected
6. **Sessions** — Ephemeral session identity with automatic key management
7. **Sub-delegation** — Agent delegates a subset of its capabilities to a sub-agent

## Running the Demo

### Prerequisites

- Go 1.21+
- Python 3.10+
- The `cryptography` Python package (`pip install cryptography`)

### Start the Go Server

```bash
# From the repository root
go run ./demo/server
```

You should see:

```
Human identity: sha256:abc123...
Pact demo server listening on :8090
  POST /setup/delegate  — get a delegation chain
  GET  /api/data        — requires api:read
  POST /api/data        — requires api:write
  POST /api/deploy      — requires deploy:create
```

### Run the Python Agent

In a separate terminal:

```bash
# From the repository root
cd sdk/python && pip install -e . && cd ../..
python demo/client/agent.py
```

Or with a custom server address:

```bash
python demo/client/agent.py --server http://localhost:8090
```

### Expected Output

The Python agent will:

1. ✓ Create an agent identity
2. ✓ Obtain a delegation (api:read, api:write) from the Go server
3. ✓ Successfully GET /api/data (has api:read)
4. ✓ Successfully POST /api/data (has api:write)
5. ✓ Get denied for POST /api/deploy (lacks deploy:create)
6. ✓ Use a session identity for ephemeral access
7. ✓ Sub-delegate to another agent and authenticate

## How It Works

### The Delegation Flow

```
Human (Go server)
  │
  │  new_delegation(human→agent, caps=["api:read","api:write"], ttl=1h)
  │
  ▼
Agent (Python client)
  │
  │  sign_request(req, agent, [delegation])
  │    → X-Pact-Identity: sha256:<agent-key-hash>
  │    → X-Pact-Chain: <base64url-encoded delegation chain>
  │    → Signature-Input: pact=("@method" "@path" ...)
  │    → Signature: pact=:<base64url-ed25519-sig>:
  │
  ▼
Provider (Go server)
  │
  │  pact.Middleware verifies:
  │    1. Delegation chain signatures (Ed25519)
  │    2. Chain continuity (each link's "to" matches next "from")
  │    3. Capability narrowing (no escalation)
  │    4. TTL / expiry
  │    5. Request signature (covers method, path, headers)
  │    6. Required capability for the endpoint
  │
  ▼
  Response with verified agent context
```

### What Makes This Work Cross-Language

- **Canonical JSON (RFC 8785)** — Both SDKs produce identical byte-level JSON
- **Ed25519 signatures** — Standard algorithm, same output everywhere
- **Base64url encoding** — No-padding variant, deterministic
- **Test vectors** — Shared `testdata/vectors.json` ensures byte-level compatibility
