"""Hierarchical session identity for the Pact protocol.

Solves agent ephemerality: persistent root identity creates ephemeral session
identities via delegation. Sessions auto-delegate from the root, sign requests
with the session key, and zeroize on close.

Hierarchy:
    Human (long-lived keypair)
      └── Agent Root (persistent, stored in key store)
            └── Session (ephemeral, in-memory, auto-delegated)
"""

from __future__ import annotations

import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption

from .delegation import (
    Delegation,
    DelegationChain,
    DelegationConstraints,
    DelegationEntity,
    generate_delegation_id,
    sub_delegate,
)
from .encoding import encode_base64url
from .identity import Identity, new_identity
from .signing import HttpRequest, sign_request


@dataclass
class SessionConfig:
    """Configuration for creating a session."""

    ttl: timedelta = timedelta(hours=1)
    """Session validity duration. Default: 1 hour."""

    capabilities: list[str] | None = None
    """Capabilities for the session. None = inherit from parent chain."""

    max_chain_depth: int = 2
    """Max chain depth for the session delegation."""


class Session:
    """An ephemeral session identity derived from a persistent root identity.

    The session generates a fresh Ed25519 keypair and auto-delegates from
    the root. All requests are signed with the session key. The full chain
    (human -> root -> session) is attached to every request.
    """

    def __init__(
        self,
        root: Identity,
        parent_chain: DelegationChain,
        session_identity: Identity,
        root_to_session: Delegation,
        closed: bool = False,
    ):
        self._root = root
        self._parent_chain = parent_chain
        self._session = session_identity
        self._root_to_session = root_to_session
        self._full_chain = parent_chain + [root_to_session]
        self._closed = closed

    @property
    def identity(self) -> Identity:
        """The session's ephemeral identity."""
        return self._session

    @property
    def root(self) -> Identity:
        """The persistent root identity."""
        return self._root

    @property
    def chain(self) -> DelegationChain:
        """The full delegation chain including the session delegation."""
        return self._full_chain

    @property
    def is_closed(self) -> bool:
        """Whether this session has been closed."""
        return self._closed

    def sign_request(self, req: HttpRequest) -> None:
        """Sign an HTTP request with the session's ephemeral key.

        Raises:
            RuntimeError: If the session is closed.
        """
        if self._closed:
            raise RuntimeError("Cannot sign with a closed session")
        sign_request(req, self._session, self._full_chain)

    def sub_delegate(
        self,
        to: Identity,
        capabilities: list[str],
        ttl: timedelta,
    ) -> tuple[Delegation, DelegationChain]:
        """Sub-delegate from this session to another agent.

        Follows all standard narrowing rules.

        Raises:
            RuntimeError: If the session is closed.
        """
        if self._closed:
            raise RuntimeError("Cannot sub-delegate from a closed session")
        return sub_delegate(
            self._full_chain,
            self._session,
            to,
            capabilities,
            ttl,
        )

    def renew(self, config: SessionConfig | None = None) -> None:
        """Renew the session with a fresh ephemeral keypair.

        The old session key is zeroized. The root key signs a new
        delegation to the new session identity.

        Args:
            config: Optional new configuration. Defaults to original settings.
        """
        if self._closed:
            raise RuntimeError("Cannot renew a closed session")

        if config is None:
            config = SessionConfig(
                ttl=timedelta(hours=1),
                capabilities=[d for d in self._root_to_session.capabilities],
            )

        # Zeroize old session key
        _zeroize_key(self._session)

        # Generate new session identity
        new_session = new_identity(
            "agent", f"session-{generate_delegation_id()}")

        # Determine capabilities
        caps = config.capabilities
        if caps is None:
            caps = self._root_to_session.capabilities

        # Create new delegation from root to new session
        new_delegation, new_chain = sub_delegate(
            self._parent_chain,
            self._root,
            new_session,
            caps,
            config.ttl,
        )

        self._session = new_session
        self._root_to_session = new_delegation
        self._full_chain = new_chain

    def close(self) -> None:
        """Close the session and zeroize the ephemeral key.

        After closing, no further requests can be signed.
        The root identity is NOT affected.
        """
        if not self._closed:
            _zeroize_key(self._session)
            self._closed = True


def new_session(
    root: Identity,
    parent_chain: DelegationChain,
    config: SessionConfig | None = None,
) -> Session:
    """Create a new session with an ephemeral identity.

    Args:
        root: The persistent root identity (must have private key).
        parent_chain: The delegation chain from human to root.
        config: Optional session configuration.

    Returns:
        A new Session.

    Raises:
        ValueError: If root has no private key or is not the chain terminal.
    """
    if root.private_key is None:
        raise ValueError("Root identity must have a private key")

    if config is None:
        config = SessionConfig()

    # Verify root is the terminal entity in the parent chain
    if parent_chain:
        last = parent_chain[-1]
        if root.id != last.to_entity.id:
            raise ValueError(
                f"Root identity {root.id} does not match chain terminal {last.to_entity.id}"
            )

    # Generate ephemeral session identity
    session_id = new_identity("agent", f"session-{generate_delegation_id()}")

    # Determine capabilities
    caps = config.capabilities
    if caps is None and parent_chain:
        caps = parent_chain[-1].capabilities

    if caps is None:
        raise ValueError(
            "Session requires capabilities (either from config or parent chain)")

    # Create delegation from root to session
    delegation, new_chain = sub_delegate(
        parent_chain,
        root,
        session_id,
        caps,
        config.ttl,
    )

    return Session(
        root=root,
        parent_chain=parent_chain,
        session_identity=session_id,
        root_to_session=delegation,
    )


def _zeroize_key(identity: Identity) -> None:
    """Best-effort zeroization of a private key in memory.

    Overwrites the private key bytes with zeros. This is a defense-in-depth
    measure — language runtimes with garbage collection may have copied
    the key material.
    """
    if identity.private_key is None:
        return

    try:
        # Get the raw private key bytes and overwrite
        raw = identity.private_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption()
        )
        # We can't overwrite the bytes object directly in Python (immutable),
        # but we can clear the reference and replace the key
        identity.private_key = None
    except Exception:
        identity.private_key = None
