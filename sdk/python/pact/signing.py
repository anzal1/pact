"""HTTP request signing for the Pact protocol.

Signs HTTP requests with the agent's private key and attaches the delegation
chain. Uses a subset of RFC 9421 HTTP Message Signatures.
"""

from __future__ import annotations

import hashlib
import json
import time as time_mod
from email.utils import formatdate
from typing import Any

from .delegation import Delegation, DelegationChain
from .encoding import decode_base64url, encode_base64url
from .identity import Identity


# HTTP headers used by Pact
HEADER_AGENT_IDENTITY = "X-Pact-Identity"
HEADER_DELEGATION_CHAIN = "X-Pact-Chain"
HEADER_SIGNATURE_INPUT = "Signature-Input"
HEADER_SIGNATURE = "Signature"
HEADER_CONTENT_DIGEST = "Content-Digest"

# Covered components in the signature base (RFC 9421)
COVERED_COMPONENTS = [
    "@method",
    "@path",
    "@authority",
    "date",
    HEADER_AGENT_IDENTITY,
    HEADER_DELEGATION_CHAIN,
]


class HttpRequest:
    """A simple HTTP request representation for signing/verification.

    This abstracts away the HTTP library (requests, httpx, aiohttp, etc.)
    so the signing code doesn't depend on any specific library.
    """

    def __init__(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ):
        self.method = method.upper()
        self.headers = {k: v for k, v in (headers or {}).items()}
        self.body = body

        # Parse URL
        from urllib.parse import urlparse
        parsed = urlparse(url)
        self.host = parsed.hostname or ""
        if parsed.port and parsed.port not in (80, 443):
            self.host = f"{parsed.hostname}:{parsed.port}"
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += f"?{parsed.query}"

    def get_header(self, name: str) -> str:
        """Get a header value (case-insensitive)."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return ""

    def set_header(self, name: str, value: str) -> None:
        """Set a header value."""
        self.headers[name] = value


def sign_request(
    req: HttpRequest,
    agent: Identity,
    chain: DelegationChain,
) -> None:
    """Sign an HTTP request with the agent's private key and attach the delegation chain.

    After signing, the request will have:
    - X-Pact-Identity: the agent's identity ID
    - X-Pact-Chain: base64url-encoded delegation chain JSON
    - Signature-Input: describes what components are covered
    - Signature: the Ed25519 signature
    - Date: current UTC time (if not already set)

    Args:
        req: The HTTP request to sign.
        agent: The agent identity (must have private key).
        chain: The delegation chain.

    Raises:
        ValueError: If the agent has no private key.
    """
    if agent.private_key is None:
        raise ValueError("Cannot sign request — agent has no private key")

    # Set Date header if not already set
    if not req.get_header("Date"):
        req.set_header("Date", formatdate(
            timeval=None, localtime=False, usegmt=True))

    # Set agent identity header
    req.set_header(HEADER_AGENT_IDENTITY, agent.id)

    # Serialize and set delegation chain
    chain_dicts = [d.to_dict() for d in chain]
    chain_json = json.dumps(chain_dicts, separators=(",", ":")).encode("utf-8")
    req.set_header(HEADER_DELEGATION_CHAIN, encode_base64url(chain_json))

    # Build signature base
    sig_base = _build_signature_base(req, COVERED_COMPONENTS)

    # Build Signature-Input header value
    sig_input = _build_signature_input(COVERED_COMPONENTS, agent.id)
    req.set_header(HEADER_SIGNATURE_INPUT, sig_input)

    # Include Signature-Input in what we sign
    sig_base += f'"signature-input": {sig_input}\n'

    # Sign the signature base
    sig = agent.sign(sig_base.encode("utf-8"))
    req.set_header(HEADER_SIGNATURE, f"pact=:{encode_base64url(sig)}:")


def compute_content_digest(body: bytes) -> str:
    """Compute the SHA-256 digest of a request body.

    Returns the Content-Digest header value per RFC 9530.
    """
    h = hashlib.sha256(body).digest()
    return f"sha-256=:{encode_base64url(h)}:"


def _build_signature_base(req: HttpRequest, components: list[str]) -> str:
    """Build the signature base string per RFC 9421 §2.5."""
    parts = []
    for comp in components:
        value = _resolve_component(req, comp)
        parts.append(f'"{comp.lower()}": {value}\n')
    return "".join(parts)


def _resolve_component(req: HttpRequest, component: str) -> str:
    """Extract the value of a covered component from the request."""
    if component == "@method":
        return req.method
    elif component == "@path":
        return req.path if req.path else "/"
    elif component == "@authority":
        return req.host
    else:
        # Regular header
        return req.get_header(component)


def _build_signature_input(components: list[str], key_id: str) -> str:
    """Build the Signature-Input header value per RFC 9421."""
    parts = [f'"{comp.lower()}"' for comp in components]
    created = int(time_mod.time())
    return f'pact=({" ".join(parts)});keyid="{key_id}";created={created};alg="ed25519"'


def extract_signature_data(req: HttpRequest) -> dict[str, Any]:
    """Parse the Pact signature data from an HTTP request.

    This is the first step of provider-side verification.

    Returns:
        Dict with keys: signature_base, signature, agent_id, chain, timestamp.

    Raises:
        ValueError: If required headers are missing or malformed.
    """
    # Extract agent identity
    agent_id = req.get_header(HEADER_AGENT_IDENTITY)
    if not agent_id:
        raise ValueError(f"Missing {HEADER_AGENT_IDENTITY} header")

    # Extract and decode delegation chain
    chain_encoded = req.get_header(HEADER_DELEGATION_CHAIN)
    if not chain_encoded:
        raise ValueError(f"Missing {HEADER_DELEGATION_CHAIN} header")
    chain_json = decode_base64url(chain_encoded)
    chain_dicts = json.loads(chain_json)
    chain = [Delegation.from_dict(d) for d in chain_dicts]

    # Extract signature
    sig_header = req.get_header(HEADER_SIGNATURE)
    if not sig_header:
        raise ValueError(f"Missing {HEADER_SIGNATURE} header")
    sig_bytes = _parse_signature_header(sig_header)

    # Extract Signature-Input
    sig_input = req.get_header(HEADER_SIGNATURE_INPUT)
    if not sig_input:
        raise ValueError(f"Missing {HEADER_SIGNATURE_INPUT} header")

    # Rebuild signature base for verification
    sig_base = _build_signature_base(req, COVERED_COMPONENTS)
    sig_base += f'"signature-input": {sig_input}\n'

    # Parse timestamp from Date header
    date_str = req.get_header("Date")
    timestamp = None
    if date_str:
        from email.utils import parsedate_to_datetime
        try:
            timestamp = parsedate_to_datetime(date_str)
        except Exception:
            pass

    return {
        "signature_base": sig_base,
        "signature": sig_bytes,
        "agent_id": agent_id,
        "chain": chain,
        "signature_input": sig_input,
        "timestamp": timestamp,
    }


def _parse_signature_header(header: str) -> bytes:
    """Extract the raw signature bytes from the Signature header.

    Format: pact=:base64url_signature:
    """
    prefix = "pact=:"
    if not header.startswith(prefix):
        raise ValueError(f"Invalid Signature header format: {header!r}")
    rest = header[len(prefix):]
    if not rest.endswith(":"):
        raise ValueError(f"Invalid Signature header format: {header!r}")
    encoded = rest[:-1]
    return decode_base64url(encoded)
