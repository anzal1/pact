# pact-auth

**Sovereign Agent Authentication Protocol — Python SDK**

Cryptographic identity, delegation chains, and capability-based authorization for AI agents. Zero trust, zero registry — the public key IS the identity.

## Install

```bash
pip install pact-auth
```

## Quick Start

```python
import pact
from datetime import timedelta

# Create identities (Ed25519 keypairs)
human = pact.new_identity("human", "alice")
agent = pact.new_identity("agent", "my-agent")

# Delegate capabilities with expiry
delegation = pact.new_delegation(
    from_identity=human,
    to_identity=agent,
    capabilities=["storage:read", "storage:write"],
    ttl=timedelta(hours=24),
)

# Sign HTTP requests
req = pact.HttpRequest("GET", "https://api.example.com/data")
pact.sign_request(req, agent, [delegation])

# Verify (provider side)
result = pact.verify_request(req)
assert result.valid
```

## Features

- **Self-sovereign identity** — Ed25519 keypairs, `sha256:hex` IDs, no registry
- **Delegation chains** — Signed capability transfers with narrowing-only constraint
- **Capability URIs** — `resource:action,constraint=value` format with wildcard support
- **HTTP signing** — Content digest + signature headers compatible with RFC 9421
- **Session management** — Ephemeral session keys delegated from persistent root
- **Revocation** — Instant revocation with cryptographic proof
- **Zero dependencies** beyond `cryptography>=41.0`

## Protocol Spec

See [SPEC.md](https://github.com/anzal1/pact/blob/main/SPEC.md) for the full 968-line protocol specification.

## License

Apache 2.0
