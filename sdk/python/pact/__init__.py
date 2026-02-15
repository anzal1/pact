"""Pact — Sovereign Agent Authentication Protocol.

Python SDK for the Pact protocol. Enables AI agents to prove their
identity, authorization, and capabilities through cryptographic
delegation chains.

Usage:
    import pact

    # Create identities
    human = pact.new_identity("human", "alice")
    agent = pact.new_identity("agent", "my-agent")

    # Delegate capabilities
    delegation = pact.new_delegation(
        from_identity=human,
        to_identity=agent,
        capabilities=["storage:read", "storage:write"],
        ttl=timedelta(hours=24),
    )

    # Sign a request
    req = pact.HttpRequest("GET", "https://api.example.com/data")
    pact.sign_request(req, agent, [delegation])

    # Verify a request (provider side)
    result = pact.verify_request(req)
    assert result.valid
"""

from datetime import timedelta

from .canonical import canonical_json
from .capabilities import (
    Capability,
    CapabilitySet,
    parse_capability,
    parse_capability_set,
)
from .delegation import (
    Delegation,
    DelegationChain,
    DelegationConstraints,
    DelegationEntity,
    chain_root_authority,
    chain_terminal_entity,
    generate_delegation_id,
    new_delegation,
    sub_delegate,
)
from .encoding import decode_base64url, encode_base64url
from .identity import (
    EntityType,
    Identity,
    derive_id,
    identity_from_public_key,
    identity_from_seed,
    new_identity,
    test_vector_seed,
)
from .revocation import (
    MemoryRevocationStore,
    Revocation,
    new_revocation,
    verify_revocation,
)
from .session import Session, SessionConfig, new_session
from .signing import (
    HEADER_AGENT_IDENTITY,
    HEADER_CONTENT_DIGEST,
    HEADER_DELEGATION_CHAIN,
    HEADER_SIGNATURE,
    HEADER_SIGNATURE_INPUT,
    HttpRequest,
    compute_content_digest,
    extract_signature_data,
    sign_request,
)
from .verification import (
    VerificationResult,
    VerifyOptions,
    default_verify_options,
    verify_chain,
    verify_request,
)

__version__ = "0.1.0"
__all__ = [
    # Identity
    "Identity",
    "EntityType",
    "new_identity",
    "identity_from_seed",
    "identity_from_public_key",
    "derive_id",
    "test_vector_seed",
    # Capabilities
    "Capability",
    "CapabilitySet",
    "parse_capability",
    "parse_capability_set",
    # Delegation
    "Delegation",
    "DelegationChain",
    "DelegationConstraints",
    "DelegationEntity",
    "new_delegation",
    "sub_delegate",
    "chain_terminal_entity",
    "chain_root_authority",
    "generate_delegation_id",
    # Signing
    "HttpRequest",
    "sign_request",
    "compute_content_digest",
    "extract_signature_data",
    "HEADER_AGENT_IDENTITY",
    "HEADER_DELEGATION_CHAIN",
    "HEADER_SIGNATURE_INPUT",
    "HEADER_SIGNATURE",
    "HEADER_CONTENT_DIGEST",
    # Verification
    "VerificationResult",
    "VerifyOptions",
    "default_verify_options",
    "verify_request",
    "verify_chain",
    # Revocation
    "Revocation",
    "MemoryRevocationStore",
    "new_revocation",
    "verify_revocation",
    # Session
    "Session",
    "SessionConfig",
    "new_session",
    # Encoding
    "encode_base64url",
    "decode_base64url",
    # Canonical JSON
    "canonical_json",
]
