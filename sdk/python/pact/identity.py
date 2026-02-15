"""Self-sovereign Ed25519 identity for the Pact protocol.

Identity = Ed25519 keypair. ID = sha256:hex(SHA-256(public_key)).
No registry, no central authority — the public key IS the identity.
"""

from __future__ import annotations

import hashlib
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from .encoding import decode_base64url, encode_base64url


class EntityType:
    """Entity types in the Pact protocol."""
    HUMAN = "human"
    AGENT = "agent"


@dataclass
class Identity:
    """A Pact identity — a self-sovereign Ed25519 keypair.

    The identity ID is derived from the public key:
        ID = "sha256:" + hex(SHA-256(public_key_bytes))

    This is globally unique without any registry.
    """

    type: str
    """Entity type: 'human' or 'agent'."""

    id: str
    """SHA-256 hash of public key, hex-encoded with 'sha256:' prefix."""

    public_key: str
    """Base64url-encoded Ed25519 public key (no padding)."""

    private_key: Optional[Ed25519PrivateKey] = field(default=None, repr=False)
    """Ed25519 private key. Never serialized. Only present for locally generated identities."""

    name: str = ""
    """Optional human-readable label (not used in crypto operations)."""

    created_at: str = ""
    """RFC 3339 timestamp of when this identity was generated."""

    def sign(self, message: bytes) -> bytes:
        """Sign a message with this identity's private key.

        Returns the 64-byte Ed25519 signature.
        Raises ValueError if this identity has no private key.
        """
        if self.private_key is None:
            raise ValueError(
                f"Cannot sign — no private key for identity {self.id}")
        return self.private_key.sign(message)

    def verify(self, message: bytes, signature: bytes) -> bool:
        """Verify that a signature was made by this identity's public key.

        Returns True if valid, False otherwise.
        """
        try:
            pub_key = self.ed25519_public_key()
            pub_key.verify(signature, message)
            return True
        except Exception:
            return False

    def ed25519_public_key(self) -> Ed25519PublicKey:
        """Decode and return the raw Ed25519 public key object."""
        pub_bytes = decode_base64url(self.public_key)
        return Ed25519PublicKey.from_public_bytes(pub_bytes)

    def public_identity(self) -> Identity:
        """Return a copy with the private key stripped. Safe to share."""
        return Identity(
            type=self.type,
            id=self.id,
            public_key=self.public_key,
            name=self.name,
            created_at=self.created_at,
        )

    def to_dict(self) -> dict:
        """Serialize to a dict (for JSON). Private key is never included."""
        d: dict = {
            "type": self.type,
            "id": self.id,
            "public_key": self.public_key,
        }
        if self.name:
            d["name"] = self.name
        if self.created_at:
            d["created_at"] = self.created_at
        return d

    def to_entity_dict(self) -> dict:
        """Serialize to a DelegationEntity dict (for embedding in delegations)."""
        d: dict = {
            "type": self.type,
            "id": self.id,
            "public_key": self.public_key,
        }
        if self.name:
            d["name"] = self.name
        return d

    def raw_public_key_bytes(self) -> bytes:
        """Return the raw 32-byte public key."""
        return decode_base64url(self.public_key)


def new_identity(entity_type: str, name: str = "") -> Identity:
    """Generate a new Ed25519 identity.

    The identity is self-sovereign — no registration, no central authority.

    Args:
        entity_type: 'human' or 'agent'.
        name: Optional human-readable label.

    Returns:
        A new Identity with both public and private keys.
    """
    private_key = Ed25519PrivateKey.generate()
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    identity_id = derive_id(pub_bytes)
    pub_encoded = encode_base64url(pub_bytes)

    return Identity(
        type=entity_type,
        id=identity_id,
        public_key=pub_encoded,
        private_key=private_key,
        name=name,
        created_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


def identity_from_seed(seed: bytes, entity_type: str, name: str = "") -> Identity:
    """Create an identity from a 32-byte seed (deterministic).

    Used for test vectors — same seed always produces the same keypair.

    Args:
        seed: 32-byte seed for Ed25519 key generation.
        entity_type: 'human' or 'agent'.
        name: Optional human-readable label.

    Returns:
        A deterministic Identity.
    """
    private_key = Ed25519PrivateKey.from_private_bytes(seed[:32])
    pub_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )

    identity_id = derive_id(pub_bytes)
    pub_encoded = encode_base64url(pub_bytes)

    return Identity(
        type=entity_type,
        id=identity_id,
        public_key=pub_encoded,
        private_key=private_key,
        name=name,
        created_at="",
    )


def identity_from_public_key(entity_type: str, pub_key_bytes: bytes) -> Identity:
    """Create an Identity from an existing public key (no private key).

    Used when you have a peer's public key but not their private key.
    """
    return Identity(
        type=entity_type,
        id=derive_id(pub_key_bytes),
        public_key=encode_base64url(pub_key_bytes),
    )


def derive_id(pub_key_bytes: bytes) -> str:
    """Compute the identity ID from a raw public key.

    ID = "sha256:" + hex(SHA-256(public_key_bytes))
    """
    h = hashlib.sha256(pub_key_bytes).hexdigest()
    return f"sha256:{h}"


def test_vector_seed(label: str) -> bytes:
    """Derive a deterministic seed for test vectors.

    seed = SHA-256("pact-test-vector:" + label)
    """
    return hashlib.sha256(f"pact-test-vector:{label}".encode("utf-8")).digest()
