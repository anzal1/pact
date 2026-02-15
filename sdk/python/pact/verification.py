"""Request and delegation chain verification for the Pact protocol.

All verification is LOCAL — zero network calls. A provider can verify
a Pact-signed request using only data present in the request headers.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .capabilities import CapabilitySet, parse_capability, parse_capability_set
from .delegation import Delegation, DelegationChain, chain_root_authority, chain_terminal_entity
from .encoding import decode_base64url
from .identity import derive_id
from .signing import HttpRequest, extract_signature_data


@dataclass
class VerificationResult:
    """The outcome of verifying a Pact-signed request."""

    valid: bool = False
    """True if the request passed all verification checks."""

    agent_id: str = ""
    """The verified agent identity ID."""

    root_authority: str = ""
    """The root authority (human) who initiated the delegation chain."""

    capabilities: list[str] = field(default_factory=list)
    """The capabilities the agent is authorized to use."""

    chain_depth: int = 0
    """Number of delegation links in the chain."""

    error: str = ""
    """Describes why verification failed (if valid is False)."""

    expires_at: Optional[datetime] = None
    """When the delegation chain expires (earliest expiry)."""


@dataclass
class VerifyOptions:
    """Configuration for verification behavior."""

    max_clock_skew: timedelta = field(
        default_factory=lambda: timedelta(minutes=5))
    """Maximum allowed difference between request timestamp and server time."""

    required_capability: str = ""
    """Capability the request must have. If empty, only chain validity is checked."""

    trusted_roots: set[str] = field(default_factory=set)
    """Known root authority IDs. If empty, any valid chain is accepted."""

    revocation_checker: Optional[Callable[[str], bool]] = None
    """Function that checks if a delegation ID has been revoked."""

    now: Optional[Callable[[], datetime]] = None
    """Override current time (for testing)."""


def default_verify_options() -> VerifyOptions:
    """Return sensible default verification options."""
    return VerifyOptions()


def verify_request(req: HttpRequest, opts: VerifyOptions | None = None) -> VerificationResult:
    """Perform full Pact verification on an HTTP request.

    This is the provider-side function — the main integration point.

    Verification steps:
    1. Extract signature data from headers
    2. Walk the delegation chain, verifying each link's signature
    3. Check chain continuity
    4. Verify capabilities cover the required capability (if specified)
    5. Check all constraints (expiry, chain depth, time bounds)
    6. Verify the request signature against the terminal agent's public key
    7. Check timestamp freshness (replay protection)

    All verification is LOCAL — zero network calls.
    """
    if opts is None:
        opts = default_verify_options()

    now = datetime.now(timezone.utc)
    if opts.now is not None:
        now = opts.now()

    if opts.max_clock_skew == timedelta(0):
        opts.max_clock_skew = timedelta(minutes=5)

    # Step 1: Extract signature data
    try:
        sig_data = extract_signature_data(req)
    except ValueError as e:
        return VerificationResult(valid=False, error=f"extraction failed: {e}")

    # Step 2-6: Verify chain + request
    return _verify_signature_data(sig_data, opts, now)


def verify_chain(chain: DelegationChain, opts: VerifyOptions | None = None) -> VerificationResult:
    """Verify a delegation chain without an HTTP request.

    Useful for offline chain inspection and validation.
    """
    if opts is None:
        opts = default_verify_options()

    now = datetime.now(timezone.utc)
    if opts.now is not None:
        now = opts.now()

    return _verify_chain_only(chain, opts, now)


def _verify_signature_data(
    sig_data: dict, opts: VerifyOptions, now: datetime
) -> VerificationResult:
    """Perform the full verification pipeline."""
    chain: DelegationChain = sig_data["chain"]

    # Verify the delegation chain
    chain_result = _verify_chain_only(chain, opts, now)
    if not chain_result.valid:
        return chain_result

    # Step 6: Verify request signature
    if sig_data["agent_id"] != chain_terminal_entity(chain):
        return VerificationResult(
            valid=False,
            error=f"agent identity {sig_data['agent_id']} does not match chain terminal {chain_terminal_entity(chain)}",
        )

    # Get the terminal agent's public key
    last = chain[-1]
    try:
        agent_pub_bytes = decode_base64url(last.to_entity.public_key)
        agent_pub_key = Ed25519PublicKey.from_public_bytes(agent_pub_bytes)
    except Exception as e:
        return VerificationResult(valid=False, error=f"invalid agent public key: {e}")

    # Verify the request signature
    try:
        agent_pub_key.verify(
            sig_data["signature"],
            sig_data["signature_base"].encode("utf-8"),
        )
    except Exception:
        return VerificationResult(
            valid=False, error="request signature verification failed"
        )

    # Step 7: Check timestamp freshness
    timestamp = sig_data.get("timestamp")
    if timestamp is not None:
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        skew = abs((now - timestamp).total_seconds())
        if skew > opts.max_clock_skew.total_seconds():
            return VerificationResult(
                valid=False,
                error=f"request timestamp too far from server time (skew: {skew:.0f}s, max: {opts.max_clock_skew.total_seconds():.0f}s)",
            )

    return chain_result


def _verify_chain_only(
    chain: DelegationChain, opts: VerifyOptions, now: datetime
) -> VerificationResult:
    """Verify the delegation chain structure and signatures."""
    if not chain:
        return VerificationResult(valid=False, error="empty delegation chain")

    earliest_expiry: Optional[datetime] = None
    terminal_caps: list[str] = []

    for i, d in enumerate(chain):
        # Verify delegation type
        if d.type != "delegation":
            return VerificationResult(
                valid=False, error=f"chain link {i}: invalid type {d.type!r}"
            )

        # Verify chain continuity
        if i > 0:
            prev = chain[i - 1]
            if prev.to_entity.id != d.from_entity.id or prev.to_entity.public_key != d.from_entity.public_key:
                return VerificationResult(
                    valid=False,
                    error=f"chain link {i}: discontinuity — previous 'to' ({prev.to_entity.id}) != current 'from' ({d.from_entity.id})",
                )

        # Verify the delegator's signature
        try:
            from_pub_bytes = decode_base64url(d.from_entity.public_key)
            from_pub_key = Ed25519PublicKey.from_public_bytes(from_pub_bytes)
        except Exception as e:
            return VerificationResult(
                valid=False, error=f"chain link {i}: invalid 'from' public key: {e}"
            )

        # Verify identity matches public key
        expected_id = derive_id(from_pub_bytes)
        if expected_id != d.from_entity.id:
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: 'from' ID does not match public key",
            )

        # Reconstruct signing payload and verify signature
        payload = d.signing_payload()
        try:
            sig_bytes = decode_base64url(d.signature)
        except Exception as e:
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: invalid signature encoding: {e}",
            )

        try:
            from_pub_key.verify(sig_bytes, payload)
        except Exception:
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: signature verification failed",
            )

        # Check expiry
        try:
            expires = datetime.fromisoformat(d.constraints.expires)
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except Exception as e:
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: invalid expiry format: {e}",
            )
        if now > expires:
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: delegation expired at {d.constraints.expires}",
            )
        if earliest_expiry is None or expires < earliest_expiry:
            earliest_expiry = expires

        # Check NotBefore
        if d.constraints.not_before:
            try:
                not_before = datetime.fromisoformat(d.constraints.not_before)
                if not_before.tzinfo is None:
                    not_before = not_before.replace(tzinfo=timezone.utc)
                if now < not_before:
                    return VerificationResult(
                        valid=False,
                        error=f"chain link {i}: delegation not yet valid (not before {d.constraints.not_before})",
                    )
            except Exception:
                pass

        # Check chain depth
        if i > 0 and len(chain) > chain[0].constraints.max_chain_depth:
            return VerificationResult(
                valid=False,
                error=f"chain exceeds max depth {chain[0].constraints.max_chain_depth}",
            )

        # Verify narrowing
        if i > 0:
            try:
                parent_caps = parse_capability_set(chain[i - 1].capabilities)
                child_caps = parse_capability_set(d.capabilities)
                if not parent_caps.covers(child_caps):
                    return VerificationResult(
                        valid=False,
                        error=f"chain link {i}: capabilities exceed parent scope (narrowing violation)",
                    )
            except ValueError as e:
                return VerificationResult(
                    valid=False,
                    error=f"chain link {i}: invalid capabilities: {e}",
                )

        # Check revocation
        if opts.revocation_checker is not None and opts.revocation_checker(d.id):
            return VerificationResult(
                valid=False,
                error=f"chain link {i}: delegation {d.id} has been revoked",
            )

        terminal_caps = d.capabilities

    # Check trusted roots
    root_id = chain_root_authority(chain)
    if opts.trusted_roots and root_id not in opts.trusted_roots:
        return VerificationResult(
            valid=False, error=f"root authority {root_id} is not trusted"
        )

    # Check required capability
    if opts.required_capability:
        try:
            term_caps = parse_capability_set(terminal_caps)
            req_cap = parse_capability(opts.required_capability)
            from .capabilities import CapabilitySet
            if not term_caps.covers(CapabilitySet([req_cap])):
                return VerificationResult(
                    valid=False,
                    error=f"agent lacks required capability: {opts.required_capability}",
                )
        except ValueError as e:
            return VerificationResult(
                valid=False, error=f"invalid capability: {e}"
            )

    return VerificationResult(
        valid=True,
        agent_id=chain_terminal_entity(chain),
        root_authority=root_id,
        capabilities=terminal_caps,
        chain_depth=len(chain),
        expires_at=earliest_expiry,
    )
