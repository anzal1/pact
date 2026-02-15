# Pact Protocol Specification

**Version:** 1.0  
**Status:** Draft  
**Date:** 2026-02-15  
**Authors:** anzal1  
**License:** Apache 2.0

---

## Abstract

Pact is a decentralized authentication protocol for AI agents. It enables agents to prove their identity, the human who authorized them, and the specific actions they are permitted to perform — all without contacting any external service.

Pact achieves this through three primitives:

1. **Self-sovereign identity** — Ed25519 keypairs with deterministic IDs, no registration required.
2. **Signed delegation chains** — cryptographic authorization from human to agent, narrowing-only, with constraints.
3. **Per-request signatures** — every HTTP request is signed by the acting agent and carries the full delegation chain.

Verification is entirely local. A provider receiving a Pact-signed request can verify the delegation chain, check capabilities, and validate the request signature using only the data in the request headers. No token introspection. No authorization server. No network calls.

---

## Table of Contents

1. [Terminology](#1-terminology)
2. [Design Principles](#2-design-principles)
3. [Identity](#3-identity)
4. [Delegation](#4-delegation)
5. [Capability URIs](#5-capability-uris)
6. [Request Signing](#6-request-signing)
7. [Request Verification](#7-request-verification)
8. [Session Identity](#8-session-identity)
9. [Revocation](#9-revocation)
10. [Key Rotation](#10-key-rotation)
11. [Wire Format Reference](#11-wire-format-reference)
12. [Security Considerations](#12-security-considerations)
13. [Implementation Guidance](#13-implementation-guidance)
14. [Referenced Standards](#14-referenced-standards)

---

## 1. Terminology

| Term                 | Definition                                                                                            |
| -------------------- | ----------------------------------------------------------------------------------------------------- |
| **Identity**         | An Ed25519 keypair. The public key defines who the entity is. The private key proves it.              |
| **Entity**           | Any participant in the protocol: a human or an agent.                                                 |
| **Human**            | An entity of type `"human"` — the root of trust in a delegation chain.                                |
| **Agent**            | An entity of type `"agent"` — an AI agent acting on behalf of a human.                                |
| **Delegation**       | A signed statement granting capabilities from one entity (delegator) to another (delegate).           |
| **Delegation chain** | An ordered list of delegations forming a trust path from a root authority (human) to an acting agent. |
| **Capability**       | A structured permission string specifying what an agent is allowed to do.                             |
| **Narrowing**        | The property that each delegation in a chain can only grant a subset of its parent's capabilities.    |
| **Provider**         | A service that receives and verifies Pact-signed requests.                                            |
| **Session**          | An ephemeral identity derived from a persistent root identity via delegation.                         |
| **Root identity**    | A persistent agent identity stored in a key store, used to create session identities.                 |

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

---

## 2. Design Principles

1. **Agent sovereignty.** Agents generate their own keypairs. Identity is derived from the public key, not asserted by an external authority.

2. **Offline verifiability.** A provider MUST be able to verify a request using only data present in the request itself. No callbacks, no token introspection, no network dependencies.

3. **Narrowing only.** Delegation MUST be monotonically narrowing. A delegate can never gain capabilities the delegator does not hold. Each step in the chain can only reduce scope, reduce TTL, or reduce chain depth.

4. **Cryptographic binding.** Every delegation and every request is signed with Ed25519. Tampering with any field invalidates the signature.

5. **Zero dependencies.** Implementations SHOULD use only standard library cryptographic primitives. The protocol introduces no custom cryptographic constructions.

6. **Protocol, not platform.** Pact defines wire format and verification rules. It does not mandate key storage, transport mechanisms, or deployment topology.

---

## 3. Identity

### 3.1. Key Generation

An identity is an Ed25519 keypair as defined in RFC 8032.

- **Private key:** 64 bytes (Ed25519 expanded private key).
- **Public key:** 32 bytes.
- **Key generation:** Using a cryptographically secure random number generator (e.g., `/dev/urandom`, `crypto/rand`).

### 3.2. Identity ID

The identity ID is a deterministic, globally unique identifier derived from the public key:

```
ID = "sha256:" + hex(SHA-256(public_key))
```

Where:

- `SHA-256` is applied to the raw 32-byte public key.
- `hex()` is lowercase hexadecimal encoding.
- The prefix `"sha256:"` is literal.

**Example:**

```
sha256:a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

Two implementations MUST produce the same ID for the same public key. No registration is required — the ID is self-certifying.

### 3.3. Entity Types

Every identity has an entity type:

| Type  | Value     | Description                                                   |
| ----- | --------- | ------------------------------------------------------------- |
| Human | `"human"` | The root of trust. Typically a person or organizational role. |
| Agent | `"agent"` | An AI agent acting on behalf of a human.                      |

The entity type is embedded in delegations but is not part of the ID derivation. The same keypair always produces the same ID regardless of entity type.

### 3.4. Public Key Encoding

Public keys are encoded as base64url without padding, per RFC 4648 Section 5.

```
encoded_public_key = base64url_no_pad(raw_32_byte_public_key)
```

The alphabet is: `A-Z`, `a-z`, `0-9`, `-`, `_`. No `=` padding characters.

### 3.5. Identity Serialization

The public identity is serialized as a JSON object:

```json
{
  "type": "human",
  "id": "sha256:a7f3...",
  "public_key": "base64url_encoded_public_key",
  "name": "alice",
  "created_at": "2026-02-15T10:30:00Z"
}
```

| Field        | Type   | Required | Description                                                 |
| ------------ | ------ | -------- | ----------------------------------------------------------- |
| `type`       | string | REQUIRED | `"human"` or `"agent"`.                                     |
| `id`         | string | REQUIRED | `"sha256:" + hex(SHA-256(public_key))`.                     |
| `public_key` | string | REQUIRED | Base64url-encoded Ed25519 public key (no padding).          |
| `name`       | string | OPTIONAL | Human-readable label. Not used in cryptographic operations. |
| `created_at` | string | OPTIONAL | RFC 3339 timestamp of key generation.                       |

The private key MUST NOT be included in any serialized identity that is transmitted or stored in a shared location.

---

## 4. Delegation

A delegation is a signed statement from one entity (the delegator) granting specific capabilities to another entity (the delegate).

### 4.1. Delegation Object

```json
{
  "type": "delegation",
  "version": "1.0",
  "id": "d-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "from": {
    "type": "human",
    "id": "sha256:...",
    "public_key": "...",
    "name": "alice"
  },
  "to": {
    "type": "agent",
    "id": "sha256:...",
    "public_key": "...",
    "name": "my-agent"
  },
  "capabilities": ["storage:read", "storage:write,bucket=my-data"],
  "constraints": {
    "expires": "2026-02-15T11:30:00Z",
    "max_chain_depth": 3,
    "not_before": "2026-02-15T10:30:00Z"
  },
  "issued_at": "2026-02-15T10:30:00Z",
  "signature": "base64url_encoded_signature"
}
```

### 4.2. Delegation Fields

| Field          | Type             | Required | Description                                                                         |
| -------------- | ---------------- | -------- | ----------------------------------------------------------------------------------- |
| `type`         | string           | REQUIRED | MUST be `"delegation"`.                                                             |
| `version`      | string           | REQUIRED | Protocol version. Currently `"1.0"`.                                                |
| `id`           | string           | REQUIRED | Unique delegation identifier. Format: `"d-"` + 32 hex characters (16 random bytes). |
| `from`         | object           | REQUIRED | The delegator's public identity (see §4.3).                                         |
| `to`           | object           | REQUIRED | The delegate's public identity (see §4.3).                                          |
| `capabilities` | array of strings | REQUIRED | Capability URIs being granted (see §5). MUST contain at least one.                  |
| `constraints`  | object           | REQUIRED | Bounds on the delegation (see §4.4).                                                |
| `issued_at`    | string           | REQUIRED | RFC 3339 timestamp of when the delegation was created.                              |
| `signature`    | string           | REQUIRED | Base64url-encoded Ed25519 signature (see §4.5).                                     |

### 4.3. Delegation Entity

The `from` and `to` fields embed the entity's public identity:

| Field        | Type   | Required | Description                           |
| ------------ | ------ | -------- | ------------------------------------- |
| `type`       | string | REQUIRED | `"human"` or `"agent"`.               |
| `id`         | string | REQUIRED | Identity ID (`"sha256:"` + hex).      |
| `public_key` | string | REQUIRED | Base64url-encoded Ed25519 public key. |
| `name`       | string | OPTIONAL | Human-readable label.                 |

The `id` MUST match the `public_key` — that is, `id == "sha256:" + hex(SHA-256(decode(public_key)))`. Verification MUST reject delegations where this invariant is violated.

### 4.4. Delegation Constraints

| Field             | Type    | Required | Description                                                                                   |
| ----------------- | ------- | -------- | --------------------------------------------------------------------------------------------- |
| `expires`         | string  | REQUIRED | RFC 3339 timestamp after which the delegation is invalid.                                     |
| `max_chain_depth` | integer | REQUIRED | Maximum total chain length permitted. `1` = no sub-delegation. `2` = one sub-delegation. Etc. |
| `not_before`      | string  | OPTIONAL | RFC 3339 timestamp before which the delegation is invalid.                                    |

### 4.5. Delegation Signing

The delegation is signed by the delegator (`from` entity) as follows:

1. Set the `signature` field to the empty string `""`.
2. Serialize the entire delegation object to canonical JSON (see §4.6).
3. Sign the canonical JSON byte sequence with the delegator's Ed25519 private key.
4. Set the `signature` field to the base64url encoding (no padding) of the 64-byte signature.

### 4.6. Canonical JSON (RFC 8785)

All signing and verification operations use JSON Canonicalization Scheme (JCS) as defined in RFC 8785 to produce deterministic byte sequences.

JCS rules:

1. **Object keys** MUST be sorted lexicographically by Unicode code point value.
2. **No whitespace** between tokens (no spaces after `:` or `,`, no indentation, no newlines).
3. **Numbers** MUST be serialized per ECMAScript 2015 `Number.prototype.toString()`.
4. **Strings** MUST use standard JSON escaping per RFC 8259.
5. **No trailing commas.**
6. **`null`**, **`true`**, **`false`** use their literal forms.

Two implementations MUST produce byte-identical output for the same logical JSON value. This is the foundation of signature compatibility across languages.

**Example:** The delegation object:

```json
{
  "type": "delegation",
  "version": "1.0",
  "id": "d-abc123",
  "signature": ""
}
```

Canonical form:

```
{"id":"d-abc123","signature":"","type":"delegation","version":"1.0"}
```

Keys are sorted: `id` < `signature` < `type` < `version`.

### 4.7. Delegation Chain

A delegation chain is an ordered JSON array of delegation objects:

```json
[
  { "type": "delegation", "from": {"id": "sha256:human..."}, "to": {"id": "sha256:root-agent..."}, ... },
  { "type": "delegation", "from": {"id": "sha256:root-agent..."}, "to": {"id": "sha256:session..."}, ... }
]
```

**Chain rules:**

1. **Order:** Index 0 is the root delegation (from the root authority). Each subsequent delegation is signed by the previous delegation's delegate.
2. **Continuity:** For every pair of adjacent delegations at index `i` and `i+1`: delegation `i`'s `to.id` MUST equal delegation `i+1`'s `from.id`, and their `public_key` values MUST also match.
3. **Root authority:** The `from` entity of delegation 0 is the root authority (typically a human).
4. **Terminal entity:** The `to` entity of the last delegation is the acting agent.

### 4.8. Sub-Delegation

An agent at the end of a chain MAY create a new delegation to another agent (sub-delegation), subject to these constraints:

1. **Capability narrowing:** The sub-delegation's capabilities MUST be a subset of (or equal to) the parent delegation's capabilities. Every capability in the child MUST be covered by at least one capability in the parent (see §5.3).
2. **TTL narrowing:** The sub-delegation's `expires` MUST NOT be later than the parent delegation's `expires`.
3. **Chain depth:** The total chain length MUST NOT exceed the root delegation's `max_chain_depth`.
4. **Signing authority:** The sub-delegating agent MUST sign the new delegation with its own private key.

---

## 5. Capability URIs

Capabilities are structured permission strings that define what an agent is allowed to do.

### 5.1. Capability Format

```
resource:action,constraint=value,constraint=value
```

**Components:**

| Component   | Description                                 | Examples                                          |
| ----------- | ------------------------------------------- | ------------------------------------------------- |
| Resource    | Hierarchical resource path, colon-separated | `storage`, `github:pr`, `email`                   |
| Action      | The operation permitted                     | `read`, `write`, `create`, `send`, `*` (wildcard) |
| Constraints | Key-value pairs restricting scope           | `bucket=my-data`, `repo=myorg/*`, `max=500USD`    |

**Special forms:**

| Form                  | Meaning                                                                  |
| --------------------- | ------------------------------------------------------------------------ |
| `*`                   | Full wildcard — all resources, all actions. Dangerous; must be explicit. |
| `resource:*`          | All actions on a resource.                                               |
| `flights:book<500USD` | Shorthand for `flights:book,max=500USD`.                                 |

### 5.2. Parsing Rules

Given a raw capability string:

1. If the string is `"*"`, it represents full access: resource = `"*"`, action = `"*"`.
2. Check for a `<` character. If found, split at `<`: the left side is `resource:action`, the right side becomes `max=<right side>` constraint.
3. Check for a `,` character. If found, split at the first `,`: the left side is `resource:action`, the right side contains comma-separated `key=value` constraints.
4. Split the `resource:action` part on `:`. The last segment is the action. Everything before it (joined by `:`) is the resource. If there is only one segment, the action defaults to `"*"`.
5. Parse each constraint as `key=value`. The `key` MUST be non-empty. The `value` MAY contain any characters.

### 5.3. Capability Matching (Covers)

A parent capability **covers** a child capability if and only if:

1. **Resource match:** One of:
   - Parent resource equals child resource (exact match).
   - Child resource starts with `parent_resource + ":"` (hierarchical match — `github` covers `github:pr`).
   - Parent resource ends with `:*` and the child resource matches the prefix (wildcard — `github:*` covers `github:pr:create`).
   - Parent resource is `"*"` (full wildcard).

2. **Action match:** Parent action equals child action, or parent action is `"*"`.

3. **Constraint satisfaction:** For every constraint in the parent, the child MUST have a constraint with the same key, and:
   - For `max` constraints: the child's numeric value MUST be ≤ the parent's numeric value. Numbers are extracted as leading decimal digits (e.g., `"500USD"` → `500`).
   - For constraints containing `*`: glob-style pattern matching (e.g., `repo=myorg/*` matches `repo=myorg/frontend`).
   - For all other constraints: exact string match.

**Narrowing set rule:** A capability set `S_child` is covered by `S_parent` if and only if every capability in `S_child` is covered by at least one capability in `S_parent`.

---

## 6. Request Signing

When an agent makes an HTTP request, it signs the request and attaches its delegation chain.

### 6.1. HTTP Headers

Pact uses the following HTTP headers:

| Header            | Description                                              | Example                                                                         |
| ----------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `X-Pact-Identity` | The acting agent's identity ID.                          | `sha256:a7f3...`                                                                |
| `X-Pact-Chain`    | Base64url-encoded JSON of the delegation chain.          | `eyJ0eXBl...`                                                                   |
| `Signature-Input` | Describes which components are signed (per RFC 9421).    | `pact=("@method" "@path" ...);keyid="sha256:...";created=1739...;alg="ed25519"` |
| `Signature`       | The agent's Ed25519 signature over the signature base.   | `pact=:base64url_signature:`                                                    |
| `Content-Digest`  | SHA-256 digest of the request body (if body is present). | `sha-256=:base64url_hash:`                                                      |
| `Date`            | Standard HTTP date header, used for freshness.           | `Sat, 15 Feb 2026 10:30:00 GMT`                                                 |

### 6.2. Signing Procedure

An agent signs a request as follows:

**Step 1: Set headers.**

1. Set `Date` to the current UTC time in HTTP date format (RFC 7231 §7.1.1.2), if not already set.
2. Set `X-Pact-Identity` to the agent's identity ID.
3. Serialize the delegation chain as a JSON array, then base64url-encode it (no padding). Set `X-Pact-Chain` to this value.

**Step 2: Build the signature base.**

The covered components are, in order:

```
"@method"
"@path"
"@authority"
"date"
"x-pact-identity"
"x-pact-chain"
```

The signature base is a string constructed as follows. For each covered component, append a line:

```
"<component_name_lowercase>": <component_value>\n
```

Where component values are resolved as:

| Component         | Value                                                                                        |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `@method`         | The HTTP method, e.g., `GET`, `POST`.                                                        |
| `@path`           | The request path including query string, e.g., `/api/data?page=1`. Defaults to `/` if empty. |
| `@authority`      | The host, e.g., `api.example.com`.                                                           |
| `date`            | The `Date` header value.                                                                     |
| `x-pact-identity` | The `X-Pact-Identity` header value.                                                          |
| `x-pact-chain`    | The `X-Pact-Chain` header value.                                                             |

**Step 3: Build Signature-Input.**

```
pact=("<component1>" "<component2>" ...);keyid="<agent_id>";created=<unix_timestamp>;alg="ed25519"
```

Where:

- Components are the lowercase covered component names, each double-quoted, space-separated.
- `keyid` is the agent's identity ID.
- `created` is the current UTC Unix timestamp (integer seconds).
- `alg` is always `"ed25519"`.

**Step 4: Append Signature-Input to signature base.**

```
"signature-input": <signature_input_value>\n
```

Set the `Signature-Input` header to this value before appending.

**Step 5: Sign.**

Sign the complete signature base string (UTF-8 encoded bytes) with the agent's Ed25519 private key.

**Step 6: Set Signature header.**

```
pact=:<base64url_encoded_signature>:
```

The signature is 64 bytes, base64url-encoded without padding, wrapped in colons, prefixed with `pact=`.

### 6.3. Content Digest

If the request has a body:

```
Content-Digest: sha-256=:<base64url(SHA-256(body_bytes))>:
```

The body is the raw byte content. The SHA-256 hash is base64url-encoded without padding, wrapped in colons, prefixed with `sha-256=`.

Implementations SHOULD include `Content-Digest` in the covered components when the request has a body. The current version does not mandate this to simplify initial adoption.

### 6.4. Signature Base Example

For a request:

```
POST /api/deploy?env=staging HTTP/1.1
Host: api.example.com
Date: Sat, 15 Feb 2026 10:30:00 GMT
X-Pact-Identity: sha256:a7f3b2c1...
X-Pact-Chain: eyJ0eXBlIj...
```

The signature base (before appending Signature-Input) would be:

```
"@method": POST
"@path": /api/deploy?env=staging
"@authority": api.example.com
"date": Sat, 15 Feb 2026 10:30:00 GMT
"x-pact-identity": sha256:a7f3b2c1...
"x-pact-chain": eyJ0eXBlIj...
```

After Signature-Input is constructed and appended:

```
"@method": POST
"@path": /api/deploy?env=staging
"@authority": api.example.com
"date": Sat, 15 Feb 2026 10:30:00 GMT
"x-pact-identity": sha256:a7f3b2c1...
"x-pact-chain": eyJ0eXBlIj...
"signature-input": pact=("@method" "@path" "@authority" "date" "x-pact-identity" "x-pact-chain");keyid="sha256:a7f3b2c1...";created=1739612000;alg="ed25519"
```

This entire string is what gets signed.

---

## 7. Request Verification

A provider verifies a Pact-signed request as follows. All steps are local — no network calls.

### 7.1. Verification Steps

**Step 1: Extract headers.**

Extract `X-Pact-Identity`, `X-Pact-Chain`, `Signature-Input`, `Signature`, and `Date` from the request. If any required header is missing, reject the request.

**Step 2: Decode the delegation chain.**

Base64url-decode the `X-Pact-Chain` header. Parse the result as a JSON array of delegation objects.

**Step 3: Verify the delegation chain.**

For each delegation `d[i]` in the chain (index 0 to N-1):

1. **Type check:** `d[i].type` MUST be `"delegation"`.
2. **Identity integrity:** `d[i].from.id` MUST equal `"sha256:" + hex(SHA-256(decode(d[i].from.public_key)))`. If not, the public key has been tampered with. Reject.
3. **Signature verification:**
   - Copy the delegation object.
   - Set `signature` to `""`.
   - Serialize to canonical JSON (§4.6).
   - Decode `d[i].from.public_key` from base64url.
   - Decode `d[i].signature` from base64url.
   - Verify the Ed25519 signature over the canonical JSON using the `from` public key.
   - If verification fails, reject.
4. **Expiry:** Parse `d[i].constraints.expires` as RFC 3339. If the current time is after the expiry, reject.
5. **Not-before:** If `d[i].constraints.not_before` is present, parse as RFC 3339. If the current time is before this value, reject.
6. **Chain continuity** (for `i > 0`): `d[i-1].to.id` MUST equal `d[i].from.id` AND `d[i-1].to.public_key` MUST equal `d[i].from.public_key`. If not, the chain is broken. Reject.
7. **Chain depth:** The total chain length MUST NOT exceed `d[0].constraints.max_chain_depth`. If it does, reject.
8. **Capability narrowing** (for `i > 0`): Every capability in `d[i].capabilities` MUST be covered by at least one capability in `d[i-1].capabilities` (see §5.3). If any capability is not covered, it is a narrowing violation. Reject.
9. **Revocation** (if configured): Check if `d[i].id` has been revoked. If revoked, reject.

**Step 4: Verify request signature.**

1. Confirm `X-Pact-Identity` equals `d[N-1].to.id` (the terminal entity). If not, reject.
2. Reconstruct the signature base from the request (same algorithm as §6.2, Steps 2-4).
3. Decode `d[N-1].to.public_key` from base64url.
4. Decode the signature from the `Signature` header (strip the `pact=:` prefix and trailing `:`).
5. Verify the Ed25519 signature over the reconstructed signature base using the terminal agent's public key.
6. If verification fails, reject.

**Step 5: Verify timestamp freshness.**

1. Parse the `Date` header.
2. Compute the absolute difference between the request timestamp and the current server time.
3. If the difference exceeds the maximum allowed clock skew (default: 5 minutes), reject. This prevents replay attacks.

**Step 6: Check required capability (if configured).**

If the provider requires a specific capability for this endpoint:

1. Parse the required capability string (§5.2).
2. Parse the terminal delegation's capabilities as a capability set.
3. Verify the capability set covers the required capability (§5.3).
4. If not covered, reject.

**Step 7: Check trusted roots (if configured).**

If the provider maintains a set of trusted root authority IDs:

1. Extract the root authority ID: `d[0].from.id`.
2. If the root authority is not in the trusted set, reject.

### 7.2. Verification Result

After successful verification, the provider has:

| Field          | Value                                                              |
| -------------- | ------------------------------------------------------------------ |
| Agent ID       | The terminal agent's identity ID — who made this request.          |
| Root authority | The root human's identity ID — who authorized this agent.          |
| Capabilities   | The terminal delegation's capability list — what the agent can do. |
| Chain depth    | The number of delegation links.                                    |
| Expiry         | The earliest expiry across all delegations in the chain.           |

This information SHOULD be made available to the application handler for authorization decisions, audit logging, and access control.

---

## 8. Session Identity

Agents are often ephemeral processes. Session identity solves the problem of persistent identity for short-lived processes.

### 8.1. Identity Hierarchy

```
Human (long-lived keypair)
  └── Agent Root (persistent keypair, stored in key store)
        └── Session (ephemeral keypair, in-memory, auto-delegated)
              └── Sub-agent (ephemeral, further scoped)
```

Each arrow is a Pact delegation. The hierarchy is analogous to TLS certificate chains: a root CA (in an HSM) issues intermediate certificates, which issue short-lived leaf certificates.

### 8.2. Session Lifecycle

**Creation:**

1. Load the persistent root identity from a key store.
2. Verify the root identity is the terminal entity in the parent delegation chain (human → root).
3. Generate a fresh ephemeral Ed25519 keypair (the session identity).
4. Create a delegation from root → session, with:
   - Capabilities: inherited from parent, or an explicit subset.
   - TTL: clamped to the minimum of the requested TTL and the parent chain's remaining validity.
   - Max chain depth: clamped to the remaining depth budget from the parent chain.
5. Construct the full chain: `parent_chain + [root_to_session_delegation]`.

**Usage:**

- The session signs all outgoing requests with its ephemeral key.
- The full chain (human → root → session) is attached to every request.
- Providers verify the full chain. They see a 2+ hop chain but the verification is the same.

**Renewal:**

1. Generate a new ephemeral keypair.
2. Create a new delegation from root → new session.
3. Zeroize the old session key from memory.
4. Replace the session delegation in the full chain.

The root key signs again. The human is not involved.

**Closure:**

1. Zeroize the ephemeral session private key (overwrite with zeros).
2. Mark the session as closed. No further requests can be signed.

The root identity is NOT affected. It persists for the next session.

### 8.3. Sub-Delegation from Sessions

A session MAY sub-delegate to a sub-agent, creating a chain:

```
human → root → session → sub-agent
```

The sub-delegation follows all standard rules (§4.8): narrowing capabilities, clamping TTL, respecting max chain depth.

### 8.4. Security Properties

- **Blast radius containment:** If a session key is compromised, only that session's actions are affected. Revoke the session delegation; the root identity is unharmed.
- **Root key minimization:** The root key signs once per session (or per renewal). It can be kept in secure storage (HSM, keychain) between uses.
- **Key zeroization:** Implementations SHOULD zeroize ephemeral private keys when sessions end. This is a best-effort defense — language runtimes with garbage collection may have copied the key.

---

## 9. Revocation

A delegator MAY revoke a delegation they previously issued.

### 9.1. Revocation Object

```json
{
  "type": "revocation",
  "delegation_id": "d-a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6",
  "revoked_by": "sha256:...",
  "revoked_at": "2026-02-15T11:00:00Z",
  "reason": "Agent compromised",
  "signature": "base64url_encoded_signature"
}
```

| Field           | Type   | Required | Description                                                              |
| --------------- | ------ | -------- | ------------------------------------------------------------------------ |
| `type`          | string | REQUIRED | MUST be `"revocation"`.                                                  |
| `delegation_id` | string | REQUIRED | The `id` of the delegation being revoked.                                |
| `revoked_by`    | string | REQUIRED | The identity ID of the revoker. MUST be the `from.id` of the delegation. |
| `revoked_at`    | string | REQUIRED | RFC 3339 timestamp.                                                      |
| `reason`        | string | OPTIONAL | Human-readable revocation reason.                                        |
| `signature`     | string | REQUIRED | Base64url-encoded Ed25519 signature.                                     |

### 9.2. Revocation Signing

1. Set `signature` to `""`.
2. Serialize to canonical JSON (§4.6).
3. Sign with the revoker's private key (the entity who issued the original delegation).
4. Set `signature` to the base64url encoding of the signature.

### 9.3. Revocation Verification

1. Decode the revoker's public key (from the original delegation's `from.public_key`).
2. Verify `revoked_by` matches `"sha256:" + hex(SHA-256(public_key))`.
3. Set `signature` to `""`, serialize to canonical JSON, verify the Ed25519 signature.

### 9.4. Revocation Checking

Pact does not mandate a specific revocation distribution mechanism. Options include:

- **In-memory store:** Suitable for single-process providers.
- **Shared database or cache:** For distributed systems (Redis, PostgreSQL, etc.).
- **CRL-style endpoint:** Providers publish revocation lists.
- **Webhook push:** Delegators notify providers of revocations.

During verification (§7.1 Step 3.9), the provider checks each delegation ID against its revocation store. If any delegation in the chain has been revoked, the entire chain is rejected.

---

## 10. Key Rotation

An entity MAY rotate its keypair while maintaining identity continuity.

### 10.1. Rotation Object

```json
{
  "previous_id": "sha256:old_key_hash...",
  "previous_public_key": "base64url_old_public_key",
  "new_id": "sha256:new_key_hash...",
  "new_public_key": "base64url_new_public_key",
  "rotated_at": "2026-02-15T12:00:00Z",
  "signature": "base64url_encoded_signature"
}
```

### 10.2. Rotation Rules

1. The rotation is signed by the **old** private key.
2. Signing procedure: set `signature` to `""`, serialize to canonical JSON, sign with old key.
3. Both `previous_id` and `new_id` MUST match their respective public keys.
4. After rotation, the entity uses the new keypair for all future operations.
5. Existing delegations signed by the old key remain valid until their expiry.

---

## 11. Wire Format Reference

### 11.1. HTTP Headers Summary

| Header            | Direction | Format                                                                     |
| ----------------- | --------- | -------------------------------------------------------------------------- |
| `X-Pact-Identity` | Request   | `sha256:<64_hex_chars>`                                                    |
| `X-Pact-Chain`    | Request   | Base64url-encoded JSON array of delegation objects                         |
| `Signature-Input` | Request   | `pact=("<comp1>" "<comp2>" ...);keyid="<id>";created=<unix>;alg="ed25519"` |
| `Signature`       | Request   | `pact=:<base64url_64_byte_signature>:`                                     |
| `Content-Digest`  | Request   | `sha-256=:<base64url_32_byte_hash>:`                                       |
| `Date`            | Request   | RFC 7231 HTTP date format                                                  |

### 11.2. Covered Components (in order)

```
@method
@path
@authority
date
x-pact-identity
x-pact-chain
```

### 11.3. Encoding Summary

| Data                         | Encoding                                   |
| ---------------------------- | ------------------------------------------ |
| Public keys                  | Base64url, no padding (RFC 4648 §5)        |
| Signatures                   | Base64url, no padding                      |
| Delegation chain (in header) | JSON → Base64url, no padding               |
| Identity IDs                 | `"sha256:"` + lowercase hex                |
| Timestamps in objects        | RFC 3339 (`2026-02-15T10:30:00Z`)          |
| Timestamps in HTTP Date      | RFC 7231 (`Sat, 15 Feb 2026 10:30:00 GMT`) |
| Delegation IDs               | `"d-"` + 32 lowercase hex characters       |
| JSON for signing             | RFC 8785 JCS (canonical)                   |

---

## 12. Security Considerations

### 12.1. Key Management

- Private keys MUST be stored securely. File permissions of 0600 (owner-only read/write) are the minimum for file-based storage.
- For production agents, implementations SHOULD integrate with platform key stores (macOS Keychain, Linux Secret Service, cloud KMS, HSMs).
- Ephemeral session keys SHOULD be zeroized (overwritten with zeros) when no longer needed.

### 12.2. Replay Protection

- The `Date` header and clock skew check (§7.1 Step 5) provide replay protection.
- Providers SHOULD reject requests with timestamps more than 5 minutes from server time.
- For increased security, providers MAY maintain a nonce cache of recently seen signatures.

### 12.3. Delegation Chain Length

- Implementations SHOULD enforce a practical maximum chain depth (e.g., 10) even when the root delegation allows more.
- Longer chains increase verification time linearly.
- Each link in the chain is an Ed25519 signature verification (fast, but not free).

### 12.4. Capability Scope

- Providers SHOULD define the narrowest capabilities necessary for each endpoint.
- Wildcard capabilities (`*`) SHOULD be avoided in production delegations.
- Providers SHOULD log and audit capability usage.

### 12.5. Clock Skew

- Implementations MUST tolerate reasonable clock skew between agents and providers.
- The default maximum skew of 5 minutes balances security and practicality.
- Agents and providers SHOULD use NTP-synchronized clocks.

### 12.6. Confused Deputy Prevention

- All Pact headers are included in the signature base. An attacker cannot strip or modify Pact headers without invalidating the signature.
- The delegation chain is bound to specific public keys. An attacker with a different keypair cannot use a stolen chain.
- The `@authority` component in the signature base binds the request to a specific host, preventing header-forwarding attacks.

### 12.7. Forward Secrecy

- Pact does not provide forward secrecy at the protocol level. If an agent's private key is compromised, an attacker can forge requests until the key is rotated or the delegation expires.
- Sessions partially mitigate this: ephemeral session keys limit exposure windows.
- TLS provides forward secrecy at the transport layer. Pact is designed to be used with TLS.

### 12.8. Privacy

- Delegation chains reveal the root authority's public key. If the root authority is a human, this may be a privacy concern.
- Chains also reveal the organizational structure of delegation.
- Providers SHOULD treat delegation chains as sensitive data in logs and storage.

---

## 13. Implementation Guidance

### 13.1. Minimum Viable Implementation

An implementation MUST support:

1. Ed25519 key generation, signing, and verification.
2. SHA-256 hashing for identity derivation.
3. Base64url encoding/decoding without padding.
4. RFC 8785 JSON canonicalization.
5. Delegation creation, signing, and verification.
6. Delegation chain verification (all rules in §7.1 Step 3).
7. HTTP request signing (§6.2) and verification (§7.1).

### 13.2. Optional Features

An implementation MAY additionally support:

- Capability URI parsing and matching (§5).
- Session identity management (§8).
- Revocation (§9).
- Key rotation (§10).
- HTTP middleware / framework integration.
- Key storage backends.
- OAuth/credential bridging.

### 13.3. Cross-Language Test Vectors

Reference test vectors are provided in `testdata/vectors.json`. They are generated using deterministic Ed25519 key derivation:

```
seed = SHA-256("pact-test-vector:" + label)
keypair = Ed25519_from_seed(seed[0:32])
```

Where `label` is a string like `"alice"`, `"agent-1"`, etc.

Any implementation can reproduce these seed values and verify that:

- Identity IDs match.
- Canonical JSON output is byte-identical.
- Delegation signatures match.
- Capability narrowing decisions match.
- Content digest values match.

### 13.4. Error Handling

Implementations SHOULD provide detailed error messages on verification failure, including:

- Which step failed (signature, expiry, chain continuity, etc.).
- Which chain link failed (index in the chain).
- The specific expectation vs. actual value.

This aids debugging. In production, providers MAY sanitize errors to avoid leaking internal chain structure to untrusted callers.

---

## 14. Referenced Standards

| Standard                                                                           | Usage in Pact                             |
| ---------------------------------------------------------------------------------- | ----------------------------------------- |
| [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119)                          | Requirement keywords (MUST, SHOULD, etc.) |
| [RFC 3339](https://datatracker.ietf.org/doc/html/rfc3339)                          | Timestamp format in delegation objects    |
| [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)             | Base64url encoding without padding        |
| [RFC 7231 §7.1.1.2](https://datatracker.ietf.org/doc/html/rfc7231#section-7.1.1.2) | HTTP Date header format                   |
| [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032)                          | Ed25519 signatures                        |
| [RFC 8259](https://datatracker.ietf.org/doc/html/rfc8259)                          | JSON string escaping                      |
| [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785)                          | JSON Canonicalization Scheme (JCS)        |
| [RFC 9421](https://datatracker.ietf.org/doc/html/rfc9421)                          | HTTP Message Signatures (subset used)     |

---

## Appendix A: Full Request Example

### Agent Side

```
POST /api/deploy?env=staging HTTP/1.1
Host: api.example.com
Date: Sat, 15 Feb 2026 10:30:00 GMT
Content-Type: application/json
X-Pact-Identity: sha256:a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
X-Pact-Chain: eyJ0eXBlIjoiZGVsZWdhdGlvbiIsInZlcnNpb24iOiIxLjAiLC...
Signature-Input: pact=("@method" "@path" "@authority" "date" "x-pact-identity" "x-pact-chain");keyid="sha256:a7f3b2c1...";created=1739612000;alg="ed25519"
Signature: pact=:dGhpcyBpcyBhIGJhc2U2NHVybCBlbmNvZGVkIHNpZ25hdHVyZQ:
Content-Digest: sha-256=:RK9kN2VyLWJvZHktaGFzaC1leGFtcGxl:

{"service": "frontend", "version": "2.1.0"}
```

### Provider Side (Verification Result)

```json
{
  "valid": true,
  "agent_id": "sha256:a7f3b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
  "root_authority": "sha256:b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1a7f3b2c1d4e5f6a7",
  "capabilities": ["deploy:create,env=staging"],
  "chain_depth": 2,
  "expires_at": "2026-02-15T11:30:00Z"
}
```

---

## Appendix B: Capability Conventions

See [CAPABILITIES.md](CAPABILITIES.md) for proposed shared vocabulary across domains.

The following domain prefixes are RECOMMENDED but not mandatory:

| Domain        | Prefix            | Example                           |
| ------------- | ----------------- | --------------------------------- |
| Code hosting  | `repo:`           | `repo:pr:create,repo=myorg/*`     |
| Deployment    | `deploy:`         | `deploy:create,env=staging`       |
| Storage       | `storage:`        | `storage:read,bucket=user-data`   |
| Communication | `email:`, `chat:` | `email:send,to=*@company.com`     |
| AI/ML         | `model:`          | `model:inference,cost<100USD`     |
| Compute       | `compute:`        | `compute:create,region=us-east-1` |
| Filesystem    | `fs:`             | `fs:write,path=/src/*`            |
| Generic API   | `api:`            | `api:read,path=/v1/users/*`       |

---

## Appendix C: Design Rationale

### Why Ed25519?

- Fixed-size keys (32 bytes public, 64 bytes private) and signatures (64 bytes).
- Fast: ~70,000 signatures/sec on commodity hardware.
- Deterministic: same message + key always produces the same signature.
- Widely implemented in every major language's standard library.
- No parameter negotiation needed — single algorithm simplifies cross-implementation compatibility.

### Why not JWTs?

- JWTs are bearer tokens — possessing the token is sufficient to use it. Pact signs every request.
- JWT verification often requires calling a JWKS endpoint. Pact verification is local.
- JWTs don't natively represent multi-hop delegation chains.
- JWTs conflate identity assertion with capability — Pact separates them.

### Why not OIDC-A?

- OIDC-A extends centralized identity infrastructure. The IdP asserts the agent's identity. Pact agents assert their own.
- OIDC-A requires an Authorization Server for token issuance. Pact requires nothing.
- OIDC-A tokens expire and need refresh. Pact chains are signed once and verified forever (until expiry or revocation).
- OIDC-A sub-delegation requires the AS to issue new tokens. Pact sub-delegation is a local signature operation.

### Why narrowing-only?

Monotonic narrowing (capabilities can only reduce at each delegation step) prevents privilege escalation attacks in multi-hop chains. An agent that delegates to a sub-agent can never grant the sub-agent more power than it has. This is a compile-time guarantee, not a runtime policy check.
