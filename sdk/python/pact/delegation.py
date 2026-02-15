"""Signed delegation chains for the Pact protocol.

A delegation is a signed statement from one entity (delegator) granting
specific capabilities to another entity (delegate). Chains of delegations
form a trust path from a root authority (human) to the acting agent.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from .canonical import canonical_json
from .capabilities import CapabilitySet, parse_capability_set
from .encoding import decode_base64url, encode_base64url
from .identity import Identity


@dataclass
class DelegationConstraints:
    """Bounds on a delegation."""

    expires: str
    """RFC 3339 timestamp after which the delegation is invalid."""

    max_chain_depth: int
    """Maximum total chain length. 1 = no sub-delegation."""

    not_before: str = ""
    """RFC 3339 timestamp before which the delegation is invalid (optional)."""

    def to_dict(self) -> dict:
        d: dict = {
            "expires": self.expires,
            "max_chain_depth": self.max_chain_depth,
        }
        if self.not_before:
            d["not_before"] = self.not_before
        return d


@dataclass
class DelegationEntity:
    """Public identity info embedded in a delegation."""

    type: str
    id: str
    public_key: str
    name: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "type": self.type,
            "id": self.id,
            "public_key": self.public_key,
        }
        if self.name:
            d["name"] = self.name
        return d

    @classmethod
    def from_dict(cls, d: dict) -> DelegationEntity:
        return cls(
            type=d["type"],
            id=d["id"],
            public_key=d["public_key"],
            name=d.get("name", ""),
        )


@dataclass
class Delegation:
    """A signed authorization from one entity to another.

    The core primitive of Pact — the cryptographic pact between delegator and delegate.
    """

    type: str = "delegation"
    version: str = "1.0"
    id: str = ""
    from_entity: DelegationEntity = field(
        default_factory=lambda: DelegationEntity("", "", ""))
    to_entity: DelegationEntity = field(
        default_factory=lambda: DelegationEntity("", "", ""))
    capabilities: list[str] = field(default_factory=list)
    constraints: DelegationConstraints = field(
        default_factory=lambda: DelegationConstraints("", 1)
    )
    issued_at: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        """Serialize to dict for JSON/canonical JSON."""
        d: dict = {
            "type": self.type,
            "version": self.version,
            "id": self.id,
            "from": self.from_entity.to_dict(),
            "to": self.to_entity.to_dict(),
            "capabilities": self.capabilities,
            "constraints": self.constraints.to_dict(),
            "issued_at": self.issued_at,
            "signature": self.signature,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Delegation:
        """Deserialize from dict."""
        constraints_d = d.get("constraints", {})
        return cls(
            type=d.get("type", "delegation"),
            version=d.get("version", "1.0"),
            id=d.get("id", ""),
            from_entity=DelegationEntity.from_dict(d["from"]),
            to_entity=DelegationEntity.from_dict(d["to"]),
            capabilities=d.get("capabilities", []),
            constraints=DelegationConstraints(
                expires=constraints_d.get("expires", ""),
                max_chain_depth=constraints_d.get("max_chain_depth", 1),
                not_before=constraints_d.get("not_before", ""),
            ),
            issued_at=d.get("issued_at", ""),
            signature=d.get("signature", ""),
        )

    def signing_payload(self) -> bytes:
        """Return the canonical JSON bytes that are signed.

        Sets signature to "" before canonicalization (matching Go implementation).
        """
        d = self.to_dict()
        d["signature"] = ""
        return canonical_json(d)

    def _sign(self, signer: Identity) -> None:
        """Compute and set the Ed25519 signature."""
        self.signature = ""
        payload = self.signing_payload()
        sig = signer.sign(payload)
        self.signature = encode_base64url(sig)


# Type alias for clarity
DelegationChain = list[Delegation]


def new_delegation(
    from_identity: Identity,
    to_identity: Identity,
    capabilities: list[str],
    ttl: timedelta,
    max_chain_depth: int = 1,
    not_before: Optional[datetime] = None,
    delegation_id: Optional[str] = None,
) -> Delegation:
    """Create and sign a new delegation.

    The delegator (from_identity) signs the delegation with their private key,
    cryptographically binding themselves to the authorization.

    Args:
        from_identity: The delegator (must have a private key).
        to_identity: The delegate (only public key needed).
        capabilities: Permission strings being granted.
        ttl: How long the delegation is valid.
        max_chain_depth: Maximum sub-delegation depth. Default 1 (no sub-delegation).
        not_before: Earliest validity time. Default: now.
        delegation_id: Optional explicit delegation ID (for test vectors).

    Returns:
        A signed Delegation.

    Raises:
        ValueError: If required fields are missing or invalid.
    """
    if from_identity is None:
        raise ValueError("Delegation requires a 'from' identity")
    if to_identity is None:
        raise ValueError("Delegation requires a 'to' identity")
    if from_identity.private_key is None:
        raise ValueError("Delegator must have a private key to sign")
    if not capabilities:
        raise ValueError("Delegation requires at least one capability")
    if ttl.total_seconds() <= 0:
        raise ValueError("Delegation requires a positive TTL")

    if max_chain_depth <= 0:
        max_chain_depth = 1

    now = datetime.now(timezone.utc)
    if not_before is None:
        not_before = now

    if delegation_id is None:
        delegation_id = generate_delegation_id()

    d = Delegation(
        type="delegation",
        version="1.0",
        id=delegation_id,
        from_entity=DelegationEntity(
            type=from_identity.type,
            id=from_identity.id,
            public_key=from_identity.public_key,
            name=from_identity.name,
        ),
        to_entity=DelegationEntity(
            type=to_identity.type,
            id=to_identity.id,
            public_key=to_identity.public_key,
            name=to_identity.name,
        ),
        capabilities=capabilities,
        constraints=DelegationConstraints(
            expires=(now + ttl).strftime("%Y-%m-%dT%H:%M:%SZ"),
            max_chain_depth=max_chain_depth,
            not_before=not_before.strftime("%Y-%m-%dT%H:%M:%SZ"),
        ),
        issued_at=now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        signature="",
    )

    d._sign(from_identity)
    return d


def sub_delegate(
    chain: DelegationChain,
    agent: Identity,
    to: Identity,
    capabilities: list[str],
    ttl: timedelta,
) -> tuple[Delegation, DelegationChain]:
    """Create a sub-delegation from the chain's terminal agent to a new agent.

    The new delegation's capabilities must be a subset of the parent's.
    The chain depth must not exceed the root's max_chain_depth.

    Args:
        chain: The existing delegation chain.
        agent: The terminal agent in the chain (must have private key).
        to: The new delegate.
        capabilities: Capabilities to grant (must be subset of parent's).
        ttl: TTL for the sub-delegation.

    Returns:
        Tuple of (new delegation, extended chain).

    Raises:
        ValueError: If constraints are violated.
    """
    if not chain:
        raise ValueError("Cannot sub-delegate from empty chain")

    last = chain[-1]

    # Verify the agent is the terminal entity
    if agent.id != last.to_entity.id:
        raise ValueError(
            f"Agent identity {agent.id} does not match chain terminal {last.to_entity.id}"
        )

    # Check chain depth
    root = chain[0]
    if len(chain) >= root.constraints.max_chain_depth:
        raise ValueError(
            f"Sub-delegation would exceed max chain depth {root.constraints.max_chain_depth}"
        )

    # Verify narrowing
    parent_caps = parse_capability_set(last.capabilities)
    child_caps = parse_capability_set(capabilities)
    if not parent_caps.covers(child_caps):
        raise ValueError(
            "Sub-delegation capabilities exceed parent scope (narrowing-only violation)"
        )

    # TTL cannot exceed parent's remaining TTL
    parent_expires = datetime.fromisoformat(last.constraints.expires)
    if parent_expires.tzinfo is None:
        parent_expires = parent_expires.replace(tzinfo=timezone.utc)
    remaining = parent_expires - datetime.now(timezone.utc)
    if ttl > remaining:
        ttl = remaining

    # Clamp max chain depth
    new_max_depth = root.constraints.max_chain_depth - len(chain)
    if new_max_depth < 1:
        new_max_depth = 1

    d = new_delegation(
        from_identity=agent,
        to_identity=to,
        capabilities=capabilities,
        ttl=ttl,
        max_chain_depth=new_max_depth,
    )

    new_chain = chain + [d]
    return d, new_chain


def chain_terminal_entity(chain: DelegationChain) -> str:
    """Return the identity ID of the last delegate in the chain."""
    if not chain:
        return ""
    return chain[-1].to_entity.id


def chain_root_authority(chain: DelegationChain) -> str:
    """Return the identity ID of the root delegator."""
    if not chain:
        return ""
    return chain[0].from_entity.id


def generate_delegation_id() -> str:
    """Generate a random delegation ID: 'd-' + 32 hex chars."""
    return "d-" + secrets.token_hex(16)
