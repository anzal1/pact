#!/usr/bin/env python3
"""Pact Demo — Python Agent Client.

This script demonstrates a Python AI agent authenticating against
a Go provider using the Pact protocol:

1. Creates a local agent identity (Ed25519 keypair)
2. Requests a delegation from the Go provider's /setup/delegate endpoint
3. Uses the delegation chain to sign and make authenticated API calls
4. Demonstrates both allowed and denied requests

Usage:
    python demo/client/agent.py [--server http://localhost:8090]

Requires:
    pip install pact-auth requests
"""

import pact
import argparse
import json
import sys
import os
from datetime import timedelta

# Add the SDK to path for development
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.abspath(__file__)), "..", "..", "sdk", "python"))

# Use requests if available, fall back to urllib
try:
    import requests as _requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False
    import urllib.request
    import urllib.error


def http_post(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    """POST JSON and return (status_code, response_json)."""
    data = json.dumps(body).encode()
    if HAS_REQUESTS:
        resp = _requests.post(url, json=body, headers=headers or {})
        return resp.status_code, resp.json()
    else:
        req = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


def http_get(url: str, headers: dict) -> tuple[int, dict]:
    """GET with headers and return (status_code, response_json)."""
    if HAS_REQUESTS:
        resp = _requests.get(url, headers=headers)
        return resp.status_code, resp.json()
    else:
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


def http_request(method: str, url: str, headers: dict, body: bytes | None = None) -> tuple[int, dict]:
    """Generic HTTP request returning (status_code, response_json)."""
    if HAS_REQUESTS:
        resp = _requests.request(method, url, headers=headers, data=body)
        return resp.status_code, resp.json()
    else:
        req = urllib.request.Request(
            url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())


def banner(msg: str) -> None:
    print(f"\n{'='*60}")
    print(f"  {msg}")
    print(f"{'='*60}")


def step(n: int, msg: str) -> None:
    print(f"\n--- Step {n}: {msg} ---")


def main():
    parser = argparse.ArgumentParser(description="Pact Python Agent Demo")
    parser.add_argument(
        "--server", default="http://localhost:8090", help="Go server URL")
    args = parser.parse_args()
    server = args.server.rstrip("/")

    banner("Pact Cross-Language Demo: Python Agent -> Go Provider")
    print(f"Server: {server}")
    print(f"Python SDK version: {pact.__version__}")

    # ── Step 1: Create agent identity ───────────────────────────────────
    step(1, "Create agent identity (Ed25519 keypair)")
    agent = pact.new_identity("agent", "demo-python-agent")
    print(f"  Agent ID:     {agent.id}")
    print(f"  Agent Name:   {agent.name}")
    print(f"  Public Key:   {agent.public_key[:32]}...")

    # ── Step 2: Request delegation from the Go server ───────────────────
    step(2, "Request delegation from Go server")
    status, resp = http_post(f"{server}/setup/delegate", {
        "agent_public_key": agent.public_key,
        "agent_name": agent.name,
        "capabilities": ["api:read", "api:write"],
    })

    if status != 200:
        print(f"  FAILED: {status} — {resp}")
        sys.exit(1)

    # Parse delegation chain from response
    chain_data = resp["delegation_chain"]
    if isinstance(chain_data, str):
        chain_data = json.loads(chain_data)

    chain = [pact.Delegation.from_dict(d) for d in chain_data]
    human_id = resp["human_id"]

    print(f"  Human (root): {human_id}")
    print(f"  Chain length: {len(chain)}")
    print(f"  Capabilities: {chain[0].capabilities}")
    print(f"  Expires:      {chain[0].constraints.expires}")

    # ── Step 3: Make authenticated GET request ──────────────────────────
    step(3, "GET /api/data (requires api:read)")

    req = pact.HttpRequest("GET", f"{server}/api/data")
    pact.sign_request(req, agent, chain)

    print(f"  Signed headers:")
    for k, v in sorted(req.headers.items()):
        val = v if len(v) < 60 else v[:60] + "..."
        print(f"    {k}: {val}")

    status, resp = http_get(f"{server}/api/data", req.headers)
    print(f"  Response [{status}]: {json.dumps(resp, indent=4)}")

    if status == 200 and resp.get("verified"):
        print("  ✓ Successfully authenticated!")
    else:
        print("  ✗ Authentication failed")
        sys.exit(1)

    # ── Step 4: Make authenticated POST request ─────────────────────────
    step(4, "POST /api/data (requires api:write)")

    body = json.dumps({"action": "create", "name": "New Project"}).encode()
    req = pact.HttpRequest("POST", f"{server}/api/data", body=body)
    pact.sign_request(req, agent, chain)

    status, resp = http_request(
        "POST", f"{server}/api/data", req.headers, body)
    print(f"  Response [{status}]: {json.dumps(resp, indent=4)}")

    if status == 200:
        print("  ✓ Write request accepted!")
    else:
        print("  ✗ Write request rejected")

    # ── Step 5: Demonstrate denied request ──────────────────────────────
    step(5, "POST /api/deploy (requires deploy:create — NOT delegated)")

    req = pact.HttpRequest("POST", f"{server}/api/deploy")
    pact.sign_request(req, agent, chain)

    status, resp = http_request("POST", f"{server}/api/deploy", req.headers)
    print(f"  Response [{status}]: {json.dumps(resp, indent=4)}")

    if status == 401:
        print("  ✓ Correctly denied — agent lacks deploy:create capability")
    else:
        print(f"  ? Unexpected status: {status}")

    # ── Step 6: Demonstrate session-based identity ──────────────────────
    step(6, "Session-based ephemeral identity")

    session = pact.new_session(agent, chain)
    print(f"  Session ID:    {session.identity.id}")
    print(f"  Chain depth:   {len(session.chain)}")
    print(f"  Root:          {pact.chain_root_authority(session.chain)}")

    req = pact.HttpRequest("GET", f"{server}/api/data")
    session.sign_request(req)

    status, resp = http_get(f"{server}/api/data", req.headers)
    print(f"  Response [{status}]: {json.dumps(resp, indent=4)}")

    if status == 200 and resp.get("verified"):
        print("  ✓ Session identity authenticated!")
    else:
        print(f"  ✗ Session auth failed: {resp}")

    session.close()
    print(f"  Session closed (key zeroized)")

    # ── Step 7: Demonstrate sub-delegation ──────────────────────────────
    step(7, "Sub-delegation: agent delegates to sub-agent")

    sub_agent = pact.new_identity("agent", "sub-agent")
    sub_delegation, sub_chain = pact.sub_delegate(
        chain=chain,
        agent=agent,
        to=sub_agent,
        capabilities=["api:read"],
        ttl=timedelta(minutes=30),
    )

    print(f"  Sub-agent ID:  {sub_agent.id}")
    print(f"  Chain depth:   {len(sub_chain)}")
    print(f"  Narrowed caps: {sub_delegation.capabilities}")

    req = pact.HttpRequest("GET", f"{server}/api/data")
    pact.sign_request(req, sub_agent, sub_chain)

    status, resp = http_get(f"{server}/api/data", req.headers)
    print(f"  Response [{status}]: {json.dumps(resp, indent=4)}")

    if status == 200:
        print("  ✓ Sub-delegated agent authenticated!")
    else:
        print(f"  ✗ Sub-delegation failed: {resp}")

    # ── Summary ─────────────────────────────────────────────────────────
    banner("Demo Complete")
    print("""
  What just happened:

  1. A Python agent created an Ed25519 identity
  2. It obtained a delegation chain from a Go server (human -> agent)
  3. It signed HTTP requests using the Python SDK
  4. The Go server verified signatures using the Go SDK
  5. Capability-based access control was enforced:
     - api:read  ✓  (delegated)
     - api:write ✓  (delegated)
     - deploy:create ✗  (not delegated)
  6. Ephemeral session identity worked across languages
  7. Sub-delegation (agent -> sub-agent) worked across languages

  This proves full cross-language compatibility between
  the Go and Python implementations of the Pact protocol.
""")


if __name__ == "__main__":
    main()
