"""Unit tests for revocation and session modules."""

import pact
import sys
from datetime import timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestRevocation:
    def test_create_and_verify(self):
        human = pact.new_identity("human", "alice")
        agent = pact.new_identity("agent", "my-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=agent,
            capabilities=["api:read"],
            ttl=timedelta(hours=1),
        )

        rev = pact.new_revocation(d.id, human, reason="compromised")
        assert rev.delegation_id == d.id
        assert rev.revoked_by == human.id
        assert rev.reason == "compromised"
        assert rev.signature != ""

        # Verify
        assert pact.verify_revocation(rev, human.public_key)

    def test_wrong_key_fails(self):
        human = pact.new_identity("human", "alice")
        other = pact.new_identity("human", "bob")

        rev = pact.new_revocation("d-12345", human, reason="test")
        assert not pact.verify_revocation(rev, other.public_key)


class TestMemoryRevocationStore:
    def test_store_and_check(self):
        store = pact.MemoryRevocationStore()
        human = pact.new_identity("human", "alice")

        rev = pact.new_revocation("d-test-123", human, reason="test")
        store.revoke(rev)

        assert store.is_revoked("d-test-123")
        assert not store.is_revoked("d-other")
        assert len(store) == 1


class TestSession:
    def test_create_session(self):
        human = pact.new_identity("human", "alice")
        root = pact.new_identity("agent", "root-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=root,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        session = pact.new_session(root, [d])

        assert session.identity.type == "agent"
        assert session.identity.id != root.id
        assert len(session.chain) == 2
        assert not session.is_closed

    def test_session_sign_request(self):
        human = pact.new_identity("human", "alice")
        root = pact.new_identity("agent", "root-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=root,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        session = pact.new_session(root, [d])

        req = pact.HttpRequest("GET", "https://api.example.com/data")
        session.sign_request(req)

        # Verify the signed request
        result = pact.verify_request(req)
        assert result.valid, f"Expected valid, got error: {result.error}"
        assert result.agent_id == session.identity.id
        assert result.root_authority == human.id
        assert result.chain_depth == 2

    def test_session_close(self):
        human = pact.new_identity("human", "alice")
        root = pact.new_identity("agent", "root-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=root,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        session = pact.new_session(root, [d])
        session.close()

        assert session.is_closed
        with pytest.raises(RuntimeError, match="closed"):
            req = pact.HttpRequest("GET", "https://example.com/")
            session.sign_request(req)

    def test_session_renew(self):
        human = pact.new_identity("human", "alice")
        root = pact.new_identity("agent", "root-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=root,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=3,
        )

        session = pact.new_session(root, [d])
        old_id = session.identity.id

        session.renew()

        assert session.identity.id != old_id
        assert not session.is_closed

        # Should still be able to sign and verify
        req = pact.HttpRequest("GET", "https://api.example.com/data")
        session.sign_request(req)

        result = pact.verify_request(req)
        assert result.valid, f"Expected valid, got error: {result.error}"

    def test_session_sub_delegate(self):
        human = pact.new_identity("human", "alice")
        root = pact.new_identity("agent", "root-agent")

        d = pact.new_delegation(
            from_identity=human,
            to_identity=root,
            capabilities=["api:*"],
            ttl=timedelta(hours=24),
            max_chain_depth=4,
        )

        session = pact.new_session(root, [d])
        sub = pact.new_identity("agent", "sub-agent")

        _, sub_chain = session.sub_delegate(
            sub, ["api:read"], timedelta(minutes=30))
        assert len(sub_chain) == 3  # human->root->session->sub

        # Verify the sub-delegation chain
        req = pact.HttpRequest("GET", "https://api.example.com/data")
        pact.sign_request(req, sub, sub_chain)

        result = pact.verify_request(req)
        assert result.valid, f"Expected valid, got error: {result.error}"
        assert result.chain_depth == 3
