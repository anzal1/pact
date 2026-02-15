"""Unit tests for delegation module."""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import pact


class TestNewDelegation:
    def test_creates_signed_delegation(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        assert d.type == "delegation"
        assert d.version == "1.0"
        assert d.id.startswith("d-")
        assert d.from_entity.id == human.id
        assert d.to_entity.id == agent.id
        assert d.capabilities == ["storage:read"]
        assert d.signature != ""

    def test_signature_verifies(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        # Verify the signature
        payload = d.signing_payload()
        sig_bytes = pact.decode_base64url(d.signature)
        assert human.verify(payload, sig_bytes)

    def test_requires_private_key(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")
        pub = human.public_identity()

        with pytest.raises(ValueError, match="private key"):
            pact.new_delegation(
                from_identity=pub,
                to_identity=agent,
                capabilities=["storage:read"],
                ttl=timedelta(hours=1),
            )

    def test_requires_capabilities(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        with pytest.raises(ValueError, match="capability"):
            pact.new_delegation(
                from_identity=human,
                to_identity=agent,
                capabilities=[],
                ttl=timedelta(hours=1),
            )

    def test_max_chain_depth_default(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        assert d.constraints.max_chain_depth == 1


class TestSubDelegate:
    def test_sub_delegation(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "agent-1")
        sub = pact.new_identity("agent", "sub-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        new_d, new_chain = pact.sub_delegate(
            chain=[d],
            agent=agent,
            to=sub,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        assert len(new_chain) == 2
        assert new_chain[0].id == d.id
        assert new_chain[1].from_entity.id == agent.id
        assert new_chain[1].to_entity.id == sub.id
        assert new_chain[1].capabilities == ["storage:read"]

    def test_rejects_capability_escalation(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "agent-1")
        sub = pact.new_identity("agent", "sub-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        with pytest.raises(ValueError, match="narrowing"):
            pact.sub_delegate(
                chain=[d],
                agent=agent,
                to=sub,
                capabilities=["storage:write"],
                ttl=timedelta(hours=1),
            )

    def test_rejects_chain_depth_exceeded(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "agent-1")
        sub = pact.new_identity("agent", "sub-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=24),
            max_chain_depth=1,  # No sub-delegation
        )

        with pytest.raises(ValueError, match="max chain depth"):
            pact.sub_delegate(
                chain=[d],
                agent=agent,
                to=sub,
                capabilities=["storage:read"],
                ttl=timedelta(hours=1),
            )

    def test_clamps_ttl(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "agent-1")
        sub = pact.new_identity("agent", "sub-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
            max_chain_depth=3,
        )

        # Request longer TTL than remaining — should be clamped
        new_d, _ = pact.sub_delegate(
            chain=[d],
            agent=agent,
            to=sub,
            capabilities=["storage:read"],
            ttl=timedelta(hours=24),
        )

        # The sub-delegation's expiry should not exceed the parent's
        parent_expires = datetime.fromisoformat(d.constraints.expires)
        child_expires = datetime.fromisoformat(new_d.constraints.expires)
        assert child_expires <= parent_expires


class TestDelegationSerialization:
    def test_to_dict_from_dict_roundtrip(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read", "storage:write"],
            ttl=timedelta(hours=1),
        )

        d_dict = d.to_dict()
        restored = pact.Delegation.from_dict(d_dict)

        assert restored.type == d.type
        assert restored.version == d.version
        assert restored.id == d.id
        assert restored.from_entity.id == d.from_entity.id
        assert restored.to_entity.id == d.to_entity.id
        assert restored.capabilities == d.capabilities
        assert restored.signature == d.signature


class TestChainHelpers:
    def test_terminal_entity(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        assert pact.chain_terminal_entity([d]) == agent.id

    def test_root_authority(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["storage:read"],
            ttl=timedelta(hours=1),
        )

        assert pact.chain_root_authority([d]) == human.id

    def test_empty_chain(self):
        assert pact.chain_terminal_entity([]) == ""
        assert pact.chain_root_authority([]) == ""
