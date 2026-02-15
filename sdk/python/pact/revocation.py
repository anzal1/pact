"""Revocation support for the Pact protocol.

A delegator can revoke a delegation they previously issued by creating
a signed Revocation object.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .canonical import canonical_json
from .encoding import decode_base64url, encode_base64url
from .identity import Identity, derive_id


@dataclass
class Revocation:
    """A signed statement revoking a previously issued delegation."""

    type: str = "revocation"
    delegation_id: str = ""
    revoked_by: str = ""
    revoked_at: str = ""
    reason: str = ""
    signature: str = ""

    def to_dict(self) -> dict:
        d: dict = {
            "type": self.type,
            "delegation_id": self.delegation_id,
            "revoked_by": self.revoked_by,
            "revoked_at": self.revoked_at,
        }
        if self.reason:
            d["reason"] = self.reason
        d["signature"] = self.signature
        return d

    @classmethod
    def from_dict(cls, d: dict) -> Revocation:
        return cls(
            type=d.get("type", "revocation"),
            delegation_id=d.get("delegation_id", ""),
            revoked_by=d.get("revoked_by", ""),
            revoked_at=d.get("revoked_at", ""),
            reason=d.get("reason", ""),
            signature=d.get("signature", ""),
        )

    def signing_payload(self) -> bytes:
        """Return the canonical JSON bytes that are signed."""
        d = self.to_dict()
        d["signature"] = ""
        return canonical_json(d)


def new_revocation(
    delegation_id: str,
    revoker: Identity,
    reason: str = "",
) -> Revocation:
    """Create a signed revocation for a delegation.

    Args:
        delegation_id: The ID of the delegation to revoke.
        revoker: The entity who issued the original delegation (must have private key).
        reason: Optional human-readable reason.

    Returns:
        A signed Revocation.

    Raises:
        ValueError: If the revoker has no private key.
    """
    if revoker.private_key is None:
        raise ValueError("Revoker must have a private key to sign")

    rev = Revocation(
        type="revocation",
        delegation_id=delegation_id,
        revoked_by=revoker.id,
        revoked_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        reason=reason,
        signature="",
    )

    # Sign the revocation
    payload = rev.signing_payload()
    sig = revoker.sign(payload)
    rev.signature = encode_base64url(sig)

    return rev


def verify_revocation(revocation: Revocation, revoker_public_key: str) -> bool:
    """Verify that a revocation was properly signed by the revoker.

    Args:
        revocation: The revocation to verify.
        revoker_public_key: Base64url-encoded public key of the revoker.

    Returns:
        True if the revocation is valid, False otherwise.
    """
    try:
        pub_bytes = decode_base64url(revoker_public_key)
        pub_key = Ed25519PublicKey.from_public_bytes(pub_bytes)

        # Verify the ID matches the key
        expected_id = derive_id(pub_bytes)
        if expected_id != revocation.revoked_by:
            return False

        # Decode signature
        sig_bytes = decode_base64url(revocation.signature)

        # Reconstruct payload
        payload = revocation.signing_payload()

        # Verify
        pub_key.verify(sig_bytes, payload)
        return True
    except Exception:
        return False


class MemoryRevocationStore:
    """In-memory revocation store for checking if delegations are revoked.

    Suitable for single-process providers. For distributed systems,
    implement your own store backed by Redis, PostgreSQL, etc.
    """

    def __init__(self) -> None:
        self._revoked: dict[str, Revocation] = {}

    def revoke(self, revocation: Revocation) -> None:
        """Add a revocation to the store."""
        self._revoked[revocation.delegation_id] = revocation

    def is_revoked(self, delegation_id: str) -> bool:
        """Check if a delegation has been revoked."""
        return delegation_id in self._revoked

    def get(self, delegation_id: str) -> Optional[Revocation]:
        """Get the revocation for a delegation, if any."""
        return self._revoked.get(delegation_id)

    def __len__(self) -> int:
        return len(self._revoked)
